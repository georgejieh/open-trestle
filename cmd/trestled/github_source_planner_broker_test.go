//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/webhook"
)

const (
	plannerBrokerBoundaryDefaultAdapter = "517c2c0f3623e7323425b17ad5bacd82d4d99a1588591b082ecccfdbe2d393d9"
	plannerBrokerBoundaryDefaultHandler = "6c2950a00915cb9ac80e6b166f794a62eb9be7994bfc3e0ba1303fd36092c98a"
	plannerBrokerBoundaryBrokerAdapter  = "d33d4bbc9e485da3269c826599e10977658ebddb697dfd3d32a06c9f8b2b48e4"
	plannerBrokerBoundaryBrokerHandler  = "010d652a13783b74ac7b372c3f6a5d234a0a7ab142c1374f5ff199e4fe54cd0e"
)

type plannerBrokerBoundaryEnvironment struct {
	mu     sync.Mutex
	values map[string]string
	reads  map[string]int
}

func (e *plannerBrokerBoundaryEnvironment) getenv(name string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reads[name]++
	return e.values[name]
}

func (e *plannerBrokerBoundaryEnvironment) snapshot() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make(map[string]int, len(e.reads))
	for name, count := range e.reads {
		result[name] = count
	}
	return result
}

func plannerBrokerBoundaryRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	requireProtectedFixtureRoot(t, root)
	return root
}

func plannerBrokerBoundaryArgs(root string) []string {
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", filepath.Join(root, "state"), "--tenant", "tenant-a", "--repository", "repo-a", "--github-webhook-repository", "repo-a", "--github-webhook-key-id", "key-2026-01", "--github-open-runs", "--github-local-deterministic-workers", "--github-repository-full-name", "owner/repo", "--github-review-policy-identity", strings.Repeat("a", 64)}
	for index, kind := range []string{"assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
		args = append(args, "--github-handler", kind+"="+strings.Repeat(string("5678"[index]), 64))
	}
	return args
}

func plannerBrokerBoundaryBuild(t *testing.T, args []string, environment *plannerBrokerBoundaryEnvironment) *daemon {
	t.Helper()
	d, err := buildDaemon(context.Background(), args, environment.getenv, io.Discard)
	if d != nil {
		t.Cleanup(func() {
			if err := d.Close(); err != nil {
				t.Errorf("daemon close: %v", err)
			}
		})
	}
	if err != nil || d == nil {
		t.Fatalf("build daemon: %v", err)
	}
	if _, ok := d.artifactStore.(*artifact.FileStore); !ok {
		t.Fatal("prepared inputs must use the native protected file store")
	}
	return d
}

func plannerBrokerBoundaryPrepare(t *testing.T, d *daemon) controlplane.ReviewRunPlan {
	t.Helper()
	payload := []byte(fmt.Sprintf(`{"action":"opened","number":42,"repository":{"full_name":"owner/repo"},"pull_request":{"base":{"sha":"%s","repo":{"full_name":"owner/repo"}},"head":{"sha":"%s","repo":{"full_name":"owner/repo"}}}}`, strings.Repeat("a", 40), strings.Repeat("b", 40)))
	digest := hmac.New(sha256.New, []byte(daemonFixtureWebhook))
	_, _ = digest.Write(payload)
	request := httptest.NewRequest(http.MethodPost, "https://trestle.test/webhooks/github", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Delivery", "planner-broker-boundary-42")
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(digest.Sum(nil)))
	response := httptest.NewRecorder()
	d.server.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("mounted ingress response: %d", response.Code)
	}
	scope, err := webhook.NewRepositoryScope("tenant-a", "repo-a")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := d.inboxStore.List(context.Background(), scope, webhook.SourceGitHub, "", 10)
	if err != nil || len(stored) != 1 || stored[0].Validate() != nil {
		t.Fatal("mounted ingress did not persist exactly one verified delivery")
	}
	plans, err := d.journal.ListPlans(context.Background(), "tenant-a", "repo-a", "", 10)
	if err != nil || len(plans) != 0 {
		t.Fatal("plan existed before registered processor ran")
	}
	var selected daemonSupervisor
	count := 0
	if len(d.supervisors) != len(d.supervisorNames) {
		t.Fatal("supervisor registry mismatch")
	}
	for index, name := range d.supervisorNames {
		if name == "webhook_processing" {
			selected = d.supervisors[index]
			count++
		}
	}
	if count != 1 || selected == nil {
		t.Fatal("missing unique registered webhook processor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	joined := false
	stop := func() {
		cancel()
		if joined {
			return
		}
		select {
		case err := <-done:
			joined = true
			if err != nil {
				t.Errorf("registered webhook supervisor: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("registered webhook supervisor did not join after cancellation")
		}
	}
	defer stop()
	go func() { done <- selected.Run(ctx) }()
	select {
	case <-selected.Ready():
		if ctx.Err() != nil {
			t.Fatal("readiness occurred after startup deadline")
		}
	case err := <-done:
		joined = true
		t.Fatalf("registered webhook supervisor exited before readiness: %v", err)
	case <-ctx.Done():
		t.Fatal("registered webhook processor did not reconcile before deadline")
	}
	stop()
	if !joined {
		t.Fatal("cannot inspect the journal until webhook processing joins")
	}
	plans, err = d.journal.ListPlans(context.Background(), "tenant-a", "repo-a", "", 10)
	if err != nil || len(plans) != 1 || plans[0].Validate() != nil {
		t.Fatal("registered prepared processor did not open exactly one plan")
	}
	plan := plans[0]
	if plan.RequestIdentity() != stored[0].Delivery().Identity() || plan.Scope().ReviewRunID() != webhook.ReviewRunIDForDelivery(stored[0].Delivery()) || plan.Mode() != controlplane.ReviewRunAdvisory {
		t.Fatal("journal plan lost mounted delivery lineage")
	}
	for _, key := range []string{"source-base", "source-head"} {
		task, found := plan.Task(key)
		if !found {
			t.Fatal("prepared source task missing")
		}
		value, err := d.artifactStore.Get(context.Background(), plan.Scope(), task.InputIdentity(), time.Now().UTC())
		if err != nil || value.Validate() != nil || value.Kind() != artifact.KindTaskInput || value.Origin() != artifact.OriginHost || value.Classification() != artifact.ClassificationRestricted || value.Protection() != artifact.ProtectionProcessPrivate || value.Scope().Identity() != plan.Scope().Identity() || !value.CreatedAt().Equal(stored[0].Receipt().AcceptedAt()) || !value.ExpiresAt().Equal(value.CreatedAt().Add(24*time.Hour)) || !reflect.DeepEqual(value.Provenance(), []string{stored[0].Delivery().Identity()}) {
			t.Fatal("prepared source input lost protected delivery binding")
		}
	}
	return plan
}

func plannerBrokerBoundaryClaim(t *testing.T, d *daemon, plan controlplane.ReviewRunPlan, key string) (*controlplane.Coordinator, controlplane.TaskExecutionRequest) {
	t.Helper()
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	resumed, _, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil || resumed.Identity() != plan.Identity() {
		t.Fatal("processor did not leave a resumable actual run")
	}
	task, found := plan.Task(key)
	if !found {
		t.Fatal("source task missing")
	}
	lease, claimed, err := coordinator.ClaimTask(context.Background(), plan, key, task.HandlerIdentity(), "planner-broker-boundary", time.Now().UTC())
	if err != nil || !claimed {
		t.Fatalf("claim actual prepared source task: %v", err)
	}
	request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	if err != nil || request.Validate() != nil {
		t.Fatal("invalid actual prepared source request")
	}
	return coordinator, request
}

func plannerBrokerBoundaryCheckPlan(t *testing.T, d *daemon, plan controlplane.ReviewRunPlan, broker bool) []sourcehandler.Input {
	t.Helper()
	adapterIdentity, handlerIdentity := plannerBrokerBoundaryDefaultAdapter, plannerBrokerBoundaryDefaultHandler
	payloadHashes := []string{"7cd4f0ac1d914bf42bcf44cee60a0b5650d0c1bb625d5748615d27d447142914", "ce8059ddc4007a6be0bf660db7d9b322687ff088613616e451eed563cbd46780"}
	if broker {
		adapterIdentity, handlerIdentity = plannerBrokerBoundaryBrokerAdapter, plannerBrokerBoundaryBrokerHandler
		payloadHashes = []string{"cf5cbe471c019ffb164eaa4bbf268288f9a745ec975483039015406aaa27d98f", "3eee6b4204e2c69e36c45eb1ff5688c5c8c267e919b40fc0d125b8ba76b6025b"}
	}
	keys := []string{}
	dependencies := map[string][]string{"analysis": {"change"}, "candidates": {"context"}, "change": {"source-base", "source-head"}, "context": {"analysis", "memory"}, "memory": {"change"}, "readiness": {"analysis", "change", "verification"}, "source-base": nil, "source-head": nil, "verification": {"candidates"}}
	for _, task := range plan.Tasks() {
		keys = append(keys, task.Key())
		attempts := uint8(3)
		if task.Key() == "context" || task.Key() == "candidates" || task.Key() == "verification" {
			attempts = 1
		}
		if task.MaxAttempts() != attempts || task.RetryDelayMilliseconds() != 1000 || task.LeaseDurationMilliseconds() != 30000 || !task.Required() || !reflect.DeepEqual(task.Dependencies(), dependencies[task.Key()]) {
			t.Fatal("prepared planner changed the frozen task recipe")
		}
	}
	if !reflect.DeepEqual(keys, []string{"analysis", "candidates", "change", "context", "memory", "readiness", "source-base", "source-head", "verification"}) {
		t.Fatal("prepared planner changed the frozen advisory task inventory")
	}
	inputs := []sourcehandler.Input{}
	for index, key := range []string{"source-base", "source-head"} {
		task, _ := plan.Task(key)
		if task.Kind() != controlplane.TaskAcquireSource || task.HandlerIdentity() != handlerIdentity {
			t.Fatal("prepared source task does not bind the selected handler")
		}
		value, err := d.artifactStore.Get(context.Background(), plan.Scope(), task.InputIdentity(), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		input, err := sourcehandler.ParseInput(value.Payload())
		digest := sha256.Sum256(value.Payload())
		if err != nil || input.SourceAdapterIdentity() != adapterIdentity || hex.EncodeToString(digest[:]) != payloadHashes[index] {
			t.Fatal("prepared source input changed its frozen canonical descriptor or payload")
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func plannerBrokerBoundaryCheckOutput(t *testing.T, d *daemon, request controlplane.TaskExecutionRequest, completion controlplane.TaskCompletion, input sourcehandler.Input) {
	t.Helper()
	if completion.Validate() != nil || completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("actual prepared source completion: %s", completion.Failure())
	}
	now := time.Now().UTC()
	value, err := d.artifactStore.Get(context.Background(), request.Plan().Scope(), completion.OutputIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := sourcehandler.ParseSnapshotArtifact(value)
	file, fileErr := evidence.NewRepositoryFile("main.go", []byte(daemonFixtureContent))
	manifest, manifestErr := evidence.NewRepositoryManifest([]evidence.RepositoryFile{file})
	if err != nil || fileErr != nil || manifestErr != nil || snapshot.FileCount() != 1 || snapshot.ManifestIdentity() != manifest.Identity() || snapshot.RevisionIdentity() != input.Revision().Identity() || snapshot.RepositoryIdentity() != input.Repository().Identity() || snapshot.SourceAdapterIdentity() != input.SourceAdapterIdentity() || snapshot.AcquisitionExecutionIdentity() == "" || snapshot.Protection() != artifact.ProtectionProcessPrivate {
		t.Fatal("actual prepared input did not produce a bound native source snapshot")
	}
	reference := snapshot.Files()[0]
	content, err := d.artifactStore.Get(context.Background(), request.Plan().Scope(), reference.ArtifactIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := sourcehandler.ParseFileArtifact(content, snapshot, reference)
	if err != nil || persisted.Path() != file.Path() || persisted.Digest() != file.Digest() || !bytes.Equal(persisted.Content(), []byte(daemonFixtureContent)) {
		t.Fatal("prepared source task did not persist exact native archive content")
	}
}

func TestPlannerBrokerBoundaryMountedPreparedSource(t *testing.T) {
	var defaultRequest controlplane.TaskExecutionRequest
	var defaultInput sourcehandler.Input
	for _, mode := range []string{"anonymous", "static"} {
		t.Run(mode, func(t *testing.T) {
			root := plannerBrokerBoundaryRoot(t)
			environment := &plannerBrokerBoundaryEnvironment{values: map[string]string{"OPEN_TRESTLE_API_TOKEN": daemonFixtureOperator, "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": daemonFixtureWebhook}, reads: map[string]int{}}
			if mode == "static" {
				environment.values["OPEN_TRESTLE_GITHUB_API_TOKEN"] = daemonFixtureStatic
			}
			d := plannerBrokerBoundaryBuild(t, plannerBrokerBoundaryArgs(root), environment)
			plan := plannerBrokerBoundaryPrepare(t, d)
			inputs := plannerBrokerBoundaryCheckPlan(t, d, plan, false)
			owners := 0
			for _, closer := range d.closers {
				if owner, ok := closer.(*githubSourceRuntime); ok {
					owners++
					if owner.credentials != nil || owner.adapter.Identity().Identity() != plannerBrokerBoundaryDefaultAdapter || owner.handler.HandlerIdentity() != plannerBrokerBoundaryDefaultHandler {
						t.Fatal("default source owner descriptor changed")
					}
				}
			}
			if owners != 1 || environment.snapshot()["OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"] != 0 {
				t.Fatal("default planner activated installation credentials")
			}
			_, defaultRequest = plannerBrokerBoundaryClaim(t, d, plan, "source-base")
			defaultInput = inputs[0]
		})
	}
	if defaultRequest.Validate() != nil || defaultInput.Validate() != nil {
		t.Fatal("default positive controls did not produce real planner authority")
	}
	f := newDaemonBrokerFixture(t)
	t.Run("broker", func(t *testing.T) {
		root := plannerBrokerBoundaryRoot(t)
		path, authority := writeProtectedBrokerDescriptor(t, root, f)
		environment := &plannerBrokerBoundaryEnvironment{values: map[string]string{"OPEN_TRESTLE_API_TOKEN": daemonFixtureOperator, "OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": daemonFixtureWebhook, "OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG": path, "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY": string(f.pem), "OPEN_TRESTLE_GITHUB_SETUP_TOKEN": daemonFixtureSetup, "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN": daemonFixturePublication}, reads: map[string]int{}}
		args := append(plannerBrokerBoundaryArgs(root), "--approve-github-source-broker-authority-identity", authority)
		wrongArgs := append([]string(nil), args...)
		for index := range wrongArgs {
			if wrongArgs[index] == "owner/repo" {
				wrongArgs[index] = "owner/other"
			}
		}
		wrongDaemon, wrongErr := buildDaemon(context.Background(), wrongArgs, environment.getenv, io.Discard)
		if wrongDaemon != nil {
			_ = wrongDaemon.Close()
		}
		if wrongDaemon != nil || !errors.Is(wrongErr, ErrInvalidDaemonConfiguration) {
			t.Fatal("broker accepted the wrong daemon repository")
		}
		entries, err := os.ReadDir(filepath.Join(root, "attempts"))
		if err != nil || len(entries) != 0 {
			t.Fatal("wrong repository created issuance state")
		}
		d := plannerBrokerBoundaryBuild(t, args, environment)
		owner := findDaemonSourceRuntime(t, d)
		if owner.handler.HandlerIdentity() != plannerBrokerBoundaryBrokerHandler {
			t.Fatal("broker owner did not select frozen handler identity")
		}
		plan := plannerBrokerBoundaryPrepare(t, d)
		inputs := plannerBrokerBoundaryCheckPlan(t, d, plan, true)
		completion := owner.handler.Execute(context.Background(), defaultRequest)
		if completion.Validate() != nil || completion.Status() == controlplane.TaskCompletionSucceeded || completion.Failure() != controlplane.RunFailureInvalidInput {
			t.Fatal("broker handler accepted an actual old-descriptor planner task")
		}
		for _, input := range []sourcehandler.Input{defaultInput, inputs[0]} {
			repository := input.Repository()
			if input.SourceAdapterIdentity() == plannerBrokerBoundaryBrokerAdapter {
				repository, err = evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "other")
				if err != nil {
					t.Fatal(err)
				}
			}
			request, err := evidence.NewRepositoryAcquisitionRequest(repository, input.Revision(), input.Adapter(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			result := owner.adapter.Acquire(ctx, request)
			cancel()
			if result.Outcome != evidence.AcquisitionOutcomeBlocked || result.Reason != evidence.AcquisitionReasonPolicyBlocked || len(result.Contents) != 0 {
				t.Fatal("broker adapter accepted crossed descriptor or repository")
			}
		}
		baseline := environment.snapshot()
		f.mu.Lock()
		beforeHTTP := len(f.apiPaths) + len(f.archivePaths)
		f.mu.Unlock()
		if baseline["OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"] != 0 || beforeHTTP != 0 {
			t.Fatal("planner or rejected authority consumed a key or issuer/source request")
		}
		for index, key := range []string{"source-base", "source-head"} {
			coordinator, request := plannerBrokerBoundaryClaim(t, d, plan, key)
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			completion := owner.handler.Execute(ctx, request)
			cancel()
			plannerBrokerBoundaryCheckOutput(t, d, request, completion, inputs[index])
			if _, err := coordinator.CompleteTask(context.Background(), plan, request.Lease(), completion, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
		}
		after := environment.snapshot()
		if after["OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"] != 1 {
			t.Fatal("actual prepared source tasks did not share the lazy App signer")
		}
		delete(after, "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY")
		delete(baseline, "OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY")
		if !reflect.DeepEqual(after, baseline) {
			t.Fatal("source requests read an unrelated environment credential")
		}
		publicationBrokerBoundaryCheckConfiguredProvider(t, environment, owner, inputs[1].Repository(), inputs[1].Revision())
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.failures) != 0 {
			t.Fatalf("HTTP fixture refusals: %v", f.failures)
		}
		expected := []string{"GET /api/v3/app/installations/42", "POST /api/v3/app/installations/42/access_tokens"}
		expectedArchives := []string{}
		for _, commit := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
			expected = append(expected, "GET /api/v3/repos/owner/repo/git/commits/"+commit, "GET /api/v3/repos/owner/repo/git/trees/"+f.tree+"?recursive=1", "GET /api/v3/repos/owner/repo/tarball/"+commit)
			expectedArchives = append(expectedArchives, "GET /owner/repo/archive/"+commit)
		}
		if f.installationGETs != 1 || f.installationPOSTs != 1 || !reflect.DeepEqual(f.apiPaths, expected) || !reflect.DeepEqual(f.archivePaths, expectedArchives) || len(f.sourceHeaders) != 6 || len(f.archiveHeaders) != 2 {
			t.Fatal("actual prepared tasks did not consume one native issued grant in order")
		}
		for _, header := range f.sourceHeaders {
			if len(header.Values("Authorization")) != 1 || header.Get("Authorization") != "Bearer "+daemonFixtureToken {
				t.Fatal("source GET did not use the issued installation token")
			}
		}
		for _, header := range f.archiveHeaders {
			if len(header.Values("Authorization")) != 0 {
				t.Fatal("archive received Authorization")
			}
		}
	})
}
