package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonFullLocalReviewPersistsLinkedContextAbstention(t *testing.T) {
	cases := []struct {
		name, path, reason string
		content            []byte
	}{
		{"all-oversized-go", "large.go", "source_size_limit", []byte("package main\n//" + strings.Repeat("oversized-marker", 22000) + "\nfunc Large() {}\n")},
		{"packet-budget-zero-selection", "large.go", "packet_budget", []byte("package main\n//" + strings.Repeat("budget-marker", 12000) + "\nfunc Large() {}\n")},
		{"excluded-lockfile-only", "package-lock.json", "excluded_path", []byte("{\"lockfileVersion\": \"unsupported-marker\"}\n")},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			args, getenv, repository, base, _, policy, inventory := localFullDaemonFixture(t)
			objects := ""
			for index := range args {
				if args[index] == "--local-git-objects-root" {
					objects = args[index+1]
					break
				}
			}
			head := abstentionHeadRevision(t, objects, test.path, test.content)
			d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(d.server.Handler)
			api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-"+test.name)
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			supervisor, ok := d.supervisors[1].(*worker.RepositorySupervisor)
			if !ok {
				t.Fatalf("unexpected supervisor %T", d.supervisors[1])
			}
			if worked, err := supervisor.RunOnce(context.Background()); err != nil || !worked {
				t.Fatalf("pre-model work=%t err=%v", worked, err)
			}
			receipt, err := api.GetRun(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			output := ""
			for _, task := range receipt.Tasks() {
				switch task.Key() {
				case "context":
					if task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() == "" {
						t.Fatalf("context status=%s failure=%s output=%q", task.Status(), task.Failure(), task.OutputIdentity())
					}
					output = task.OutputIdentity()
				case "candidates", "verification", "readiness":
					if task.Status() == controlplane.TaskRuntimeAvailable || task.Status() == controlplane.TaskRuntimeSucceeded {
						t.Fatalf("model task %s incorrectly ready: %s", task.Key(), task.Status())
					}
				}
			}
			events, err := d.journal.Read(context.Background(), scope, 1, 100)
			if err != nil {
				t.Fatal(err)
			}
			preparedIndex, failedIndex := -1, -1
			for index, event := range events {
				if event.TaskKey() != "context" {
					continue
				}
				if event.Kind().String() == "context_abstention_prepared" && event.OutputIdentity() == output {
					preparedIndex = index
				}
				if event.Kind().String() == "task_failed" && event.OutputIdentity() == output {
					failedIndex = index
				}
			}
			if preparedIndex < 0 || failedIndex <= preparedIndex {
				t.Fatalf("abstention not durably prepared before failure: prepare=%d fail=%d", preparedIndex, failedIndex)
			}
			value, err := d.artifactStore.Get(context.Background(), scope, output, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if value.Kind() != artifact.KindDeterministicEvidence {
				t.Fatalf("abstention kind=%s", value.Kind())
			}
			encodedPrepare, err := controlplane.EncodeRunEvent(events[preparedIndex])
			if err != nil {
				t.Fatal(err)
			}
			var prepare struct {
				PreparedArtifact []byte `json:"prepared_artifact"`
			}
			if err := json.Unmarshal(encodedPrepare, &prepare); err != nil {
				t.Fatal(err)
			}
			preparedArtifact, err := artifact.Parse(prepare.PreparedArtifact)
			if err != nil || preparedArtifact.Identity() != output || !bytes.Equal(preparedArtifact.Payload(), value.Payload()) {
				t.Fatalf("journaled prepare does not bind exact content-free artifact: %v", err)
			}
			if bytes.Contains(prepare.PreparedArtifact, []byte("oversized-marker")) || bytes.Contains(prepare.PreparedArtifact, []byte("budget-marker")) || bytes.Contains(prepare.PreparedArtifact, []byte("unsupported-marker")) {
				t.Fatal("source bytes leaked into durable prepare")
			}
			foreign, _ := audit.NewReviewScope("tenant-a", "repo-a", "foreign-run")
			if _, err := d.artifactStore.Get(context.Background(), foreign, output, time.Now().UTC()); err == nil {
				t.Fatal("cross-scope abstention artifact retrieved")
			}
			plan, err := api.GetRunPlan(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			contextTask, exists := plan.Task("context")
			if !exists {
				t.Fatal("context task absent")
			}
			var payload struct {
				Contract  string `json:"contract"`
				Scope     string `json:"review_scope_identity"`
				Task      string `json:"task_identity"`
				Plan      string `json:"plan_identity"`
				Omissions []struct {
					Path   string `json:"path"`
					Reason string `json:"reason"`
					Count  int    `json:"count"`
				} `json:"source_omissions"`
			}
			if err := json.Unmarshal(value.Payload(), &payload); err != nil || payload.Contract != "open-trestle/context-abstention" || payload.Scope != scope.Identity() || payload.Plan != plan.Identity() || payload.Task != contextTask.Identity() {
				t.Fatalf("abstention=%+v err=%v", payload, err)
			}
			found := false
			for _, o := range payload.Omissions {
				if o.Path == test.path && o.Reason == test.reason && o.Count > 0 {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s omission missing: %+v", test.reason, payload.Omissions)
			}
			if bytes.Contains(value.Payload(), []byte("oversized-marker")) || bytes.Contains(value.Payload(), []byte("budget-marker")) || bytes.Contains(value.Payload(), []byte("unsupported-marker")) {
				t.Fatal("source content leaked into abstention")
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			d, err = buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			server = httptest.NewServer(d.server.Handler)
			defer server.Close()
			api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			replay, err := api.GetRun(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			for _, task := range replay.Tasks() {
				if task.Key() == "context" && (task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() != output) {
					t.Fatalf("restarted context=%s output=%q want=%q", task.Status(), task.OutputIdentity(), output)
				}
			}
			if _, err := d.artifactStore.Get(context.Background(), scope, output, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func abstentionHeadRevision(t *testing.T, objects, changedPath string, changedContent []byte) evidence.RevisionIdentity {
	t.Helper()
	unchanged := []byte("package main\nfunc main() {}\n")
	source := append([]byte(fmt.Sprintf("blob %d\x00", len(unchanged))), unchanged...)
	existing := fmt.Sprintf("%x", sha1.Sum(source))
	changed := daemonWriteLooseObject(t, objects, "blob", changedContent)
	files := map[string]string{"main.go": existing, changedPath: changed}
	names := []string{"main.go", changedPath}
	sort.Strings(names)
	tree := []byte{}
	for _, name := range names {
		digest, err := hex.DecodeString(files[name])
		if err != nil {
			t.Fatal(err)
		}
		tree = append(tree, []byte("100644 "+name+"\x00")...)
		tree = append(tree, digest...)
	}
	root := daemonWriteLooseObject(t, objects, "tree", tree)
	commit := daemonWriteLooseObject(t, objects, "commit", []byte("tree "+root+"\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nmessage\n"))
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commit)
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestDaemonFullLocalReviewAbstainsEmptySourceDiff(t *testing.T) {
	args, getenv, repository, base, _, policy, inventory := localFullDaemonFixture(t)
	objects := ""
	for i := range args {
		if args[i] == "--local-git-objects-root" {
			objects = args[i+1]
			break
		}
	}
	unchanged := []byte("package main\nfunc main() {}\n")
	framed := append([]byte(fmt.Sprintf("blob %d\x00", len(unchanged))), unchanged...)
	blob := sha1.Sum(framed)
	tree := append([]byte("100644 main.go\x00"), blob[:]...)
	treeFramed := append([]byte(fmt.Sprintf("tree %d\x00", len(tree))), tree...)
	treeHash := sha1.Sum(treeFramed)
	headHash := daemonWriteLooseObject(t, objects, "commit", []byte(fmt.Sprintf("tree %x\nparent %s\nauthor A <a@example.com> 1 +0000\ncommitter A <a@example.com> 1 +0000\n\nunchanged content\n", treeHash, base.Digest())))
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, headHash)
	if err != nil {
		t.Fatal(err)
	}
	d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-empty-diff")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	supervisor := d.supervisors[1].(*worker.RepositorySupervisor)
	if worked, err := supervisor.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("pre-model work=%t err=%v", worked, err)
	}
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range receipt.Tasks() {
		t.Logf("task=%s status=%s failure=%s", task.Key(), task.Status(), task.Failure())
	}
	for _, task := range receipt.Tasks() {
		if task.Key() == "context" {
			if task.Status() != controlplane.TaskRuntimeFailed || task.OutputIdentity() == "" {
				t.Fatalf("empty-diff context=%s output=%q", task.Status(), task.OutputIdentity())
			}
			value, err := d.artifactStore.Get(context.Background(), scope, task.OutputIdentity(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			var payload struct {
				Reason          string            `json:"reason"`
				SourceOmissions []json.RawMessage `json:"source_omissions"`
			}
			if err := json.Unmarshal(value.Payload(), &payload); err != nil || payload.Reason != "no_source_changes" || len(payload.SourceOmissions) != 0 {
				t.Fatalf("empty-diff abstention=%+v err=%v", payload, err)
			}
		} else if task.Key() == "candidates" && task.Status() == controlplane.TaskRuntimeAvailable {
			t.Fatal("empty diff made generation ready")
		}
	}
}
