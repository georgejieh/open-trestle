//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/worker"
)

type daemonBudgetedHandlerClock struct {
	mu sync.Mutex
	at time.Time
}

func newDaemonBudgetedHandlerClock() *daemonBudgetedHandlerClock {
	zone := time.FixedZone("budgeted-raw-fixture", -7*60*60)
	at := time.Now().In(zone)
	if at.Nanosecond()%int(time.Millisecond) == 0 {
		at = at.Add(123456 * time.Nanosecond)
	}
	return &daemonBudgetedHandlerClock{at: at}
}

func (c *daemonBudgetedHandlerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *daemonBudgetedHandlerClock) UTCMS() time.Time {
	return c.Now().UTC().Truncate(time.Millisecond)
}

type daemonBudgetedHandlerHarness struct {
	sql              *daemonBudgetedSQLService
	s3               *daemonBudgetedS3Fixture
	kms              *daemonBudgetedKMSFixture
	clock            *daemonBudgetedHandlerClock
	github           *daemonBudgetedGitHubFixture
	env              func(string) string
	reads            map[string]int
	readMu           sync.Mutex
	policyPath       string
	caPath           string
	sqlAuthority     string
	githubAuthority  string
	githubConfigPath string
}

func newDaemonBudgetedHandlerHarness(t *testing.T) *daemonBudgetedHandlerHarness {
	t.Helper()
	clock := newDaemonBudgetedHandlerClock()
	sqlService := newDaemonBudgetedSQLService(t)
	s3 := newDaemonBudgetedS3FixtureWithProfile(t, daemonBudgetedBucket, daemonBudgetedRegion, daemonBudgetedS3Access, daemonBudgetedS3Secret, daemonBudgetedS3Session, daemonBudgetedS3Profile{MaxRawRequests: 128, MaxBodyBytes: daemonBudgetedS3MaxBodyBytes, MaxAggregateBytes: 8 << 20})
	kms := newDaemonBudgetedKMSFixtureWithProfile(t, daemonBudgetedRegion, daemonBudgetedKMSKeyARN, daemonBudgetedKMSAccess, daemonBudgetedKMSSecret, daemonBudgetedKMSSession, daemonBudgetedKMSProfile{MaxRawRequests: 64, MaxBodyBytes: daemonBudgetedKMSMaxBodyBytes, MaxAggregateBytes: 8 << 20})
	sqlAuthority := daemonBudgetedAuthorityIdentity(sqlService.catalog)
	backendIdentity, err := s3store.ConfigurationIdentity(s3.Endpoint(), daemonBudgetedRegion, daemonBudgetedBucket)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := daemonBudgetedProtectedFile(t, "policy.json", daemonBudgetedPolicyWire(t, backendIdentity, sqlAuthority, clock.UTCMS()))
	caPath := daemonBudgetedProtectedFile(t, "ca.pem", string(s3.CAPEM()))
	root := t.TempDir()
	github := newDaemonBudgetedGitHubFixture(t, clock.Now())
	githubConfigPath, githubAuthority := writeDaemonBudgetedGitHubBrokerDescriptor(t, root, github)
	values := map[string]string{
		"OPEN_TRESTLE_API_TOKEN":                   strings.Repeat("t", 32),
		"OPEN_TRESTLE_POSTGRES_URL":                "postgres://budgeted-runtime.fixture/open_trestle",
		"OPEN_TRESTLE_S3_ACCESS_KEY_ID":            daemonBudgetedS3Access,
		"OPEN_TRESTLE_S3_SECRET_ACCESS_KEY":        daemonBudgetedS3Secret,
		"OPEN_TRESTLE_S3_SESSION_TOKEN":            daemonBudgetedS3Session,
		"OPEN_TRESTLE_AWS_ACCESS_KEY_ID":           daemonBudgetedKMSAccess,
		"OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY":       daemonBudgetedKMSSecret,
		"OPEN_TRESTLE_AWS_SESSION_TOKEN":           daemonBudgetedKMSSession,
		"OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET":       daemonBudgetedGitHubWebhook,
		"OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG": githubConfigPath,
		"OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY":      string(github.pem),
		"OPEN_TRESTLE_GITHUB_SETUP_TOKEN":          daemonBudgetedGitHubSetupToken,
		"OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN":    daemonBudgetedGitHubPubToken,
	}
	h := &daemonBudgetedHandlerHarness{sql: sqlService, s3: s3, kms: kms, clock: clock, github: github, reads: map[string]int{}, policyPath: policyPath, caPath: caPath, sqlAuthority: sqlAuthority, githubAuthority: githubAuthority, githubConfigPath: githubConfigPath}
	h.env = func(key string) string {
		h.readMu.Lock()
		defer h.readMu.Unlock()
		h.reads[key]++
		return values[key]
	}
	return h
}

func (h *daemonBudgetedHandlerHarness) args(t *testing.T) []string {
	t.Helper()
	args := []string{
		"--listen", "127.0.0.1:0",
		"--state-dir", filepath.Join(t.TempDir(), "state"),
		"--tenant", daemonBudgetedTenant,
		"--repository", daemonBudgetedRepository,
		"--metadata-store", "postgres",
		"--postgres-database-authority-identity", h.sqlAuthority,
		"--artifact-store", "s3",
		"--artifact-erasure-mode", "budgeted",
		"--erasure-policy", h.policyPath,
		"--s3-erasure-trusted-ca", h.caPath,
		"--s3-endpoint", h.s3.Endpoint(),
		"--s3-region", daemonBudgetedRegion,
		"--s3-bucket", daemonBudgetedBucket,
		"--s3-prefix", daemonBudgetedPrefix,
		"--kms-region", daemonBudgetedRegion,
		"--kms-key-arn", daemonBudgetedKMSKeyARN,
		"--kms-endpoint", h.kms.Endpoint(),
		"--github-webhook-repository", daemonBudgetedRepository,
		"--github-webhook-key-id", "key-2026-09",
		"--github-open-runs",
		"--github-local-deterministic-workers",
		"--github-repository-full-name", "owner/repo",
		"--github-review-policy-identity", strings.Repeat("a", 64),
		"--approve-github-source-broker-authority-identity", h.githubAuthority,
	}
	for index, kind := range []string{"assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
		args = append(args, "--github-handler", kind+"="+strings.Repeat(string("5678"[index]), 64))
	}
	return args
}

func (h *daemonBudgetedHandlerHarness) build(t *testing.T, ctx context.Context) *daemon {
	t.Helper()
	d, err := buildDaemonWithDependencies(ctx, h.args(t), h.env, io.Discard, daemonDependencies{openPostgres: h.sql.OpenPostgres, clock: h.clock})
	if err != nil {
		t.Fatalf("budgeted daemon build failed: %v", err)
	}
	return d
}

func (h *daemonBudgetedHandlerHarness) readCount(key string) int {
	h.readMu.Lock()
	defer h.readMu.Unlock()
	return h.reads[key]
}

func TestDaemonBudgetedLocalSupervisorRunsSourceBrokerChangeAndAnalysisWithUTCMillisecondArtifacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fixture := newDaemonBudgetedHandlerHarness(t)
	d := fixture.build(t, ctx)
	defer d.Close()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted artifact providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	handlers := daemonBudgetedHandlerIdentities(t, d)
	for _, kind := range []string{"acquire_source", "build_change", "inspect_deterministic"} {
		if handlers[kind] == "" {
			t.Fatalf("runtime status omitted local handler %s: %#v", kind, handlers)
		}
	}
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("runtime status contacted artifact providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	supervisor := daemonBudgetedLocalSupervisor(t, d)
	scope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-budgeted-handler-clock")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil {
		t.Fatal(err)
	}
	created := fixture.clock.UTCMS().Add(-time.Second)
	expires := fixture.clock.UTCMS().Add(time.Hour)
	baseInput := daemonBudgetedSourceInputArtifact(t, scope, repository, adapter, daemonBudgetedGitHubBaseCommit, created, expires)
	headInput := daemonBudgetedSourceInputArtifact(t, scope, repository, adapter, daemonBudgetedGitHubHeadCommit, created, expires)
	for _, value := range []artifact.Artifact{baseInput, headInput} {
		if ok, err := d.artifactStore.Put(ctx, value, fixture.clock.UTCMS()); err != nil || !ok {
			t.Fatalf("persist source input %s: created=%v err=%v", value.Identity(), ok, err)
		}
	}
	plan := daemonBudgetedHandlerPlan(t, scope, handlers, baseInput.Identity(), headInput.Identity())
	if err := d.journal.SavePlan(ctx, plan); err != nil {
		t.Fatalf("SavePlan rejected real handler plan: %v", err)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, time.Now().UTC().Truncate(time.Millisecond)); err != nil {
		t.Fatalf("open saved handler plan: %v", err)
	}
	worked, err := supervisor.RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("local supervisor RunOnce = (%v, %v)", worked, err)
	}
	finalizer, err := controlplane.NewRunFinalizer(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	state, finalized, err := finalizer.ReconcileRun(ctx, scope, time.Now().UTC().Truncate(time.Millisecond))
	if err != nil || !finalized || state.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("finalize handler run = (%v, %v, %v)", state.Status(), finalized, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis"} {
		task, ok := receipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("task %s did not succeed from actual journal: %#v", key, task)
		}
	}
	readAt := fixture.clock.UTCMS()
	baseSnapshotArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "source-base", readAt)
	headSnapshotArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "source-head", readAt)
	changeArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "change", readAt)
	analysisArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "analysis", readAt)
	for label, value := range map[string]artifact.Artifact{"source-base": baseSnapshotArtifact, "source-head": headSnapshotArtifact, "change": changeArtifact, "analysis": analysisArtifact} {
		daemonBudgetedAssertUTCMS(t, label+" created_at", value.CreatedAt(), fixture.clock.UTCMS())
		if value.Protection() != artifact.ProtectionEnvelopeEncrypted || value.Classification() != artifact.ClassificationRestricted {
			t.Fatalf("%s artifact was not budgeted protected restricted output", label)
		}
	}
	baseSnapshot, err := sourcehandler.ParseSnapshotArtifact(baseSnapshotArtifact)
	if err != nil || baseSnapshot.RevisionIdentity() == "" || baseSnapshot.FileCount() != 1 {
		t.Fatalf("base snapshot = %#v err=%v", baseSnapshot, err)
	}
	headSnapshot, err := sourcehandler.ParseSnapshotArtifact(headSnapshotArtifact)
	if err != nil || headSnapshot.RevisionIdentity() == baseSnapshot.RevisionIdentity() || headSnapshot.FileCount() != 1 {
		t.Fatalf("head snapshot = %#v err=%v", headSnapshot, err)
	}
	daemonBudgetedAssertSnapshotContent(t, ctx, d, scope, baseSnapshotArtifact, baseSnapshot, fixture.github.revisions[daemonBudgetedGitHubBaseCommit].content, readAt)
	daemonBudgetedAssertSnapshotContent(t, ctx, d, scope, headSnapshotArtifact, headSnapshot, fixture.github.revisions[daemonBudgetedGitHubHeadCommit].content, readAt)
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || change.HeadRevision().Identity() != headSnapshot.RevisionIdentity() || len(change.Entries()) != 1 || change.Entries()[0].Path() != "main.go" || len(change.Entries()[0].Ranges()) == 0 {
		t.Fatalf("change result = %#v err=%v", change, err)
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || analysis.ChangeIdentity() != change.Identity() || analysis.HeadSnapshotIdentity() != headSnapshot.Identity() || len(analysis.Checks()) != 1 || len(analysis.Items())+len(analysis.Gaps()) == 0 {
		t.Fatalf("analysis result = %#v err=%v", analysis, err)
	}
	apiPaths, archivePaths, sourceHeaders, archiveHeaders, githubFailures := fixture.github.snapshot()
	if len(githubFailures) != 0 {
		t.Fatalf("GitHub fixture rejected requests: %v", githubFailures)
	}
	if fixture.github.installationGETs != 1 || fixture.github.installationPOSTs != 1 || sourceHeaders != 6 || archiveHeaders != 2 {
		t.Fatalf("unexpected GitHub broker traffic counts: api=%#v archive=%#v source_headers=%d archive_headers=%d", apiPaths, archivePaths, sourceHeaders, archiveHeaders)
	}
	if fixture.readCount("OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY") != 1 || fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("GitHub credential reads were not lazy source-only: key=%d publication=%d", fixture.readCount("OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY"), fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	s3Requests, kmsRequests := fixture.s3.Requests(), fixture.kms.Requests()
	if !daemonBudgetedS3SawArtifactWrite(s3Requests) || !daemonBudgetedS3SawMethod(s3Requests, http.MethodGet) {
		t.Fatalf("missing S3 protected write/read path: %#v", s3Requests)
	}
	if daemonBudgetedKMSTargetCount(kmsRequests, "TrentService.GenerateDataKey") == 0 || daemonBudgetedKMSTargetCount(kmsRequests, "TrentService.Decrypt") == 0 {
		t.Fatalf("missing KMS generate/decrypt path: %#v", kmsRequests)
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected requests: %v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected requests: %v", failures)
	}
	if got := len(fixture.s3.Requests()); got == 0 || got > 128 {
		t.Fatalf("S3 profile bound not honored: %d", got)
	}
	if got := len(fixture.kms.Requests()); got == 0 || got > 64 {
		t.Fatalf("KMS profile bound not honored: %d", got)
	}
	t.Logf("external requests: S3=%d KMS=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	sqlSnapshot := fixture.sql.Snapshot()
	for _, id := range []string{"run_plan_insert", "run_event_insert", "run_plans_list", "run_events_read", "run_event_head"} {
		if !daemonBudgetedTraceContains(sqlSnapshot.Events, id) {
			t.Fatalf("run journal SQL did not execute %s", id)
		}
	}
	for _, id := range []string{"metadata_insert", "admission_insert", "confirmation_cas", "metadata_read", "admission_read"} {
		if !daemonBudgetedTraceContains(sqlSnapshot.Events, id) {
			t.Fatalf("artifact SQL did not execute %s", id)
		}
	}
	if len(sqlSnapshot.Failures) != 0 {
		t.Fatalf("SQL fixture rejected real run: %v", sqlSnapshot.Failures)
	}
}

func daemonBudgetedHandlerIdentities(t *testing.T, d *daemon) map[string]string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/api/v1/tenants/"+daemonBudgetedTenant+"/repositories/"+daemonBudgetedRepository+"/runtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	recorder := httptest.NewRecorder()
	d.server.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("runtime status failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Status struct {
			Configuration struct {
				Handlers []struct {
					Kind     string `json:"kind"`
					Identity string `json:"identity"`
				} `json:"handlers"`
			} `json:"configuration"`
		} `json:"status"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, handler := range response.Status.Configuration.Handlers {
		out[handler.Kind] = handler.Identity
	}
	return out
}

func daemonBudgetedLocalSupervisor(t *testing.T, d *daemon) *worker.RepositorySupervisor {
	t.Helper()
	for index, name := range d.supervisorNames {
		if name != "local_workers" {
			continue
		}
		supervisor, ok := d.supervisors[index].(*worker.RepositorySupervisor)
		if !ok || supervisor == nil {
			t.Fatalf("local_workers supervisor has unexpected type %#v", d.supervisors[index])
		}
		return supervisor
	}
	t.Fatalf("local_workers supervisor was not registered: %#v", d.supervisorNames)
	return nil
}

func daemonBudgetedSourceInputArtifact(t *testing.T, scope audit.ReviewScope, repository evidence.RepositoryIdentity, adapter evidence.SourceAdapterIdentity, commit string, created, expires time.Time) artifact.Artifact {
	t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		t.Fatal(err)
	}
	input, err := sourcehandler.NewInput(repository, revision, adapter)
	if err != nil {
		t.Fatal(err)
	}
	value, err := sourcehandler.NewInputArtifact(scope, input, artifact.ClassificationRestricted, artifact.ProtectionEnvelopeEncrypted, []string{strings.Repeat("e", 64)}, created, expires)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func daemonBudgetedHandlerPlan(t *testing.T, scope audit.ReviewScope, handlers map[string]string, baseInput, headInput string) controlplane.ReviewRunPlan {
	t.Helper()
	mk := func(key string, kind controlplane.TaskKind, input, handler string, dependencies []string) controlplane.TaskDefinition {
		attempt, err := controlplane.DefaultTaskAttemptPolicy(kind)
		if err != nil {
			t.Fatal(err)
		}
		task, err := controlplane.NewTaskDefinition(key, kind, input, handler, dependencies, attempt.MaximumAttempts(), attempt.RetryDelayMilliseconds(), attempt.LeaseDurationMilliseconds(), true)
		if err != nil {
			t.Fatalf("task %s: %v", key, err)
		}
		return task
	}
	tasks := []controlplane.TaskDefinition{
		mk("source-base", controlplane.TaskAcquireSource, baseInput, handlers["acquire_source"], nil),
		mk("source-head", controlplane.TaskAcquireSource, headInput, handlers["acquire_source"], nil),
		mk("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), handlers["build_change"], []string{"source-base", "source-head"}),
		mk("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("d", 64), handlers["inspect_deterministic"], []string{"change"}),
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("a", 64), controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func daemonBudgetedTaskOutput(t *testing.T, ctx context.Context, d *daemon, scope audit.ReviewScope, receipt controlplane.ReviewRunReceipt, key string, at time.Time) artifact.Artifact {
	t.Helper()
	task, ok := receipt.Task(key)
	if !ok {
		t.Fatalf("missing task %s", key)
	}
	value, err := d.artifactStore.Get(ctx, scope, task.OutputIdentity(), at)
	if err != nil {
		t.Fatalf("get %s output: %v", key, err)
	}
	return value
}

func daemonBudgetedAssertSnapshotContent(t *testing.T, ctx context.Context, d *daemon, scope audit.ReviewScope, snapshotArtifact artifact.Artifact, snapshot sourcehandler.Snapshot, expected []byte, at time.Time) {
	t.Helper()
	if snapshot.ManifestIdentity() == "" || snapshot.FileCount() != 1 {
		t.Fatalf("snapshot has no exact manifest: %#v", snapshot)
	}
	ref := snapshot.Files()[0]
	value, err := d.artifactStore.Get(ctx, scope, ref.ArtifactIdentity(), at)
	if err != nil {
		t.Fatal(err)
	}
	file, err := sourcehandler.ParseFileArtifact(value, snapshot, ref)
	if err != nil {
		t.Fatal(err)
	}
	if file.Path() != "main.go" || !bytes.Equal(file.Content(), expected) || !strings.Contains(string(snapshotArtifact.Payload()), ref.ArtifactIdentity()) {
		t.Fatalf("snapshot content mismatch: path=%s digest=%s", file.Path(), file.Digest())
	}
}

func daemonBudgetedAssertUTCMS(t *testing.T, label string, got, want time.Time) {
	t.Helper()
	if got.Location() != time.UTC || got.Nanosecond()%int(time.Millisecond) != 0 || !got.Equal(want) {
		t.Fatalf("%s = %s (%s, ns=%d), want %s UTC millisecond", label, got.Format(time.RFC3339Nano), got.Location(), got.Nanosecond(), want.Format(time.RFC3339Nano))
	}
}
