//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonLocalModelWorkersLargerRepositoryRepeatedProgress(t *testing.T) {
	args, getenv, fake, repository, _, _, policy, inventory := localModelWorkerFixture(t)
	objects := daemonTestFlagValue(t, args, "--local-git-objects-root")
	shared := daemonWriteLooseObject(t, objects, "blob", []byte("owned synthetic repository evidence\n"))
	sharedBytes, _ := hex.DecodeString(shared)
	makeRevision := func(source string) evidence.RevisionIdentity {
		t.Helper()
		blob := daemonWriteLooseObject(t, objects, "blob", []byte(source))
		blobBytes, _ := hex.DecodeString(blob)
		var tree bytes.Buffer
		for i := 0; i < 1000; i++ {
			fmt.Fprintf(&tree, "100644 file-%04d.txt%c", i, byte(0))
			tree.Write(sharedBytes)
		}
		tree.WriteString("100644 main.go\x00")
		tree.Write(blobBytes)
		treeDigest := daemonWriteLooseObject(t, objects, "tree", tree.Bytes())
		commit := []byte("tree " + treeDigest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nlarge synthetic fixture\n")
		commitDigest := daemonWriteLooseObject(t, objects, "commit", commit)
		revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, commitDigest)
		if err != nil {
			t.Fatal(err)
		}
		return revision
	}
	base := makeRevision("package main\nfunc main() { /* base synthetic fixture */ }\n")
	head := makeRevision("package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"large synthetic fixture\") }\n")
	args = append(args, "--local-model-workers")
	build := func() *daemon {
		t.Helper()
		d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	started := time.Now()
	d := build()
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("close daemon: %v", err)
		}
	})
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(func() { server.Close() })
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-large-progress")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2, 1} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	final, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || final.SchemaVersion() != 7 || final.Outcome() != diagnostics.FinalOutcomeCompleted || final.AnalysisResultIdentity() == "" || final.VerifiedSetIdentity() == "" || len(final.DeterministicChecks()) != 1 {
		t.Fatalf("larger repository final=%s err=%v", final.Outcome(), err)
	}
	pipelineDuration := time.Since(started)
	before, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if before.Status() != controlplane.ReviewRunSucceeded || before.TaskCount() != 9 {
		t.Fatalf("larger repository receipt status=%s tasks=%d", before.Status(), before.TaskCount())
	}
	for _, task := range before.Tasks() {
		if task.Status() != controlplane.TaskRuntimeSucceeded {
			t.Fatalf("larger repository task not succeeded: %s", task.Status())
		}
	}
	for key, revision := range map[string]evidence.RevisionIdentity{"source-base": base, "source-head": head} {
		task, found := before.Task(key)
		if !found {
			t.Fatalf("missing source task %s", key)
		}
		value, err := d.artifactStore.Get(context.Background(), scope, task.OutputIdentity(), time.Now().UTC())
		if err != nil {
			t.Fatalf("read %s snapshot: %v", key, err)
		}
		snapshot, err := sourcehandler.ParseSnapshotArtifact(value)
		if err != nil || snapshot.FileCount() != 1001 || snapshot.RevisionIdentity() != revision.Identity() {
			t.Fatalf("%s snapshot files=%d revision=%s err=%v", key, snapshot.FileCount(), snapshot.RevisionIdentity(), err)
		}
	}
	readStarted := time.Now()
	for i := 0; i < 20; i++ {
		progress, err := api.GetRunProgress(context.Background(), scope)
		if err != nil {
			t.Fatalf("progress read: %v", err)
		}
		coverage := progress.Progress
		if progress.Run.Identity() != before.Identity() || coverage.Change.State != "available" || coverage.Deterministic.State != "available" || coverage.Context.State != "available" || coverage.Verification.State != "available" {
			t.Fatalf("progress changed: %+v", coverage)
		}
		if coverage.Context.Analyzed == nil || coverage.Context.Selected == nil || coverage.Context.Omitted == nil || *coverage.Context.Analyzed != int(final.SourceAnalyzedCount()) || *coverage.Context.Selected != int(final.SourceSelectedCount()) || *coverage.Context.Omitted != int(final.SourceOmittedCount()) || coverage.Verification.Candidates == nil || coverage.Verification.Verified == nil || coverage.Verification.Rejected == nil || coverage.Verification.Inconclusive == nil || *coverage.Verification.Candidates != int(final.CandidateCount()) || *coverage.Verification.Verified != int(final.VerifiedCount()) || *coverage.Verification.Rejected != int(final.RejectedCount()) || *coverage.Verification.Inconclusive != int(final.InconclusiveCount()) {
			t.Fatalf("progress differs from canonical final evidence: %+v", coverage)
		}
	}
	readDuration := time.Since(readStarted)
	if calls, _, _, failures := fake.generation.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("generation calls=%d failures=%v", calls, failures)
	}
	if calls, _, _, failures := fake.verification.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("verification calls=%d failures=%v", calls, failures)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopenStarted := time.Now()
	d = build()
	reopenDuration := time.Since(reopenStarted)
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	after, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || after.Identity() != final.Identity() || after.AnalysisResultIdentity() != final.AnalysisResultIdentity() || after.VerifiedSetIdentity() != final.VerifiedSetIdentity() || after.SnapshotIdentity() != final.SnapshotIdentity() || after.ReviewSnapshotIdentity() != final.ReviewSnapshotIdentity() {
		t.Fatalf("larger repository reopen changed result: %v", err)
	}
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := api.GetRun(context.Background(), scope)
	if err != nil || reopened.Identity() != before.Identity() {
		t.Fatalf("larger repository reopen changed receipt: %v", err)
	}
	if calls, _, _, failures := fake.generation.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("reopened generation calls=%d failures=%v", calls, failures)
	}
	if calls, _, _, failures := fake.verification.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("reopened verification calls=%d failures=%v", calls, failures)
	}
	// Observations have no timing threshold and include synthetic loopback work.
	t.Logf("files=1001 repeated_reads=20 pipeline=%s progress_total=%s progress_per_read=%s reopen=%s", pipelineDuration, readDuration, readDuration/20, reopenDuration)
}
