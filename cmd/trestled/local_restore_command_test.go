package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func stoppedRestoreFixture(t *testing.T) (string, evidence.RepositoryIdentity) {
	t.Helper()
	state, setupPath, plan := snapshotFixture(t)
	writeSnapshotSetup(t, setupPath, plan)
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	artifacts, err := artifact.NewFileStore(filepath.Join(state, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if err := artifacts.Close(); err != nil {
		t.Fatal(err)
	}
	diagnosticStore, err := diagnostics.NewFileStore(filepath.Join(state, "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	if err := diagnosticStore.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := audit.NewFileLedger(filepath.Join(state, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	gitPath := filepath.Join(t.TempDir(), "objects")
	if err := os.Mkdir(gitPath, 0o700); err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	stateRoot, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer stateRoot.Close()
	artifactRoot, err := stateRoot.OpenRoot("artifacts")
	if err != nil {
		t.Fatal(err)
	}
	defer artifactRoot.Close()
	gitRoot, digest, err := openDaemonLocalGitRoot(gitPath, repository)
	if err != nil {
		t.Fatal(err)
	}
	defer gitRoot.Close()
	stateID, err := observeLocalSourceDirectory(state, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	artifactID, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, state)
	if err != nil {
		t.Fatal(err)
	}
	gitID, err := observeLocalSourceDirectory(gitPath, gitRoot)
	if err != nil {
		t.Fatal(err)
	}
	store, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	record := localSourceOwnerRecord{StatePath: state, ArtifactPath: filepath.Join(state, "artifacts"), GitObjectsPath: gitPath, TenantID: plan.TenantID(), RepositoryID: plan.RepositoryID(), RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity(), Profile: string(store.Profile()), SourcePathDigest: digest, State: stateID, Artifact: artifactID, Git: gitID}
	raw, err := encodeLocalSourceOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, localSourceOwnerLeaf), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return state, repository
}
func TestRecoveryCommandMatchesClosedBytesAndRefusesMutation(t *testing.T) {
	state, _ := stoppedRestoreFixture(t)
	flags := []string{"--state-dir", state, "--repository-authority", "local.test", "--repository-namespace", "team", "--repository-name", "repo"}
	flags = append(flags, recoveryAssetFlags(t)...)
	var record, stderr bytes.Buffer
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		if err := runDaemon(context.Background(), append([]string{"recovery-point"}, flags...), func(string) string { t.Fatal("offline command read credential environment"); return "" }, &record, &stderr); err != nil {
			t.Fatal(err)
		}
	})
	path := filepath.Join(t.TempDir(), "recovery-point.json")
	if err := os.WriteFile(path, record.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	verifyArgs := append(append([]string{"verify-restore"}, flags...), "--record", path)
	var output bytes.Buffer
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		if err := runDaemon(context.Background(), verifyArgs, func(string) string { t.Fatal("offline command read credential environment"); return "" }, &output, &stderr); err != nil {
			t.Fatal(err)
		}
	})
	if output.String() != "{\"status\":\"matched\",\"restart_authorized\":false}\n" {
		t.Fatalf("unexpected authority: %s", output.String())
	}
	if err := os.WriteFile(filepath.Join(state, "diagnostics", "foreign"), []byte("operator bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := runDaemon(context.Background(), verifyArgs, func(string) string { t.Fatal("offline command read credential environment"); return "" }, &output, &stderr); err == nil {
		t.Fatalf("inventory mutation accepted: %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("mismatch emitted success")
	}
}
func TestRecoveryObservationRefusesLiveWriter(t *testing.T) {
	state, repository := stoppedRestoreFixture(t)
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		_, _, err := observeLocalRecoveryPoint(context.Background(), state, repository)
		if !errors.Is(err, controlplane.ErrRunJournalLocked) {
			t.Fatalf("live writer accepted: %v", err)
		}
	})
}

func TestRecoveryCommandMatchesReceiptArtifactsDiagnosticsAndAudit(t *testing.T) {
	state, repository := stoppedRestoreFixture(t)
	scope, err := audit.NewReviewScope("tenant-one", "repository-one", "restored-run")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("b", 64), strings.Repeat("c", 64), nil, 1, 0, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("d", 64), strings.Repeat("e", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	point, pending, err := observeLocalRecoveryPoint(context.Background(), state, repository)
	if err != nil || !pending || len(point.Runs) != 1 {
		t.Fatalf("active history lost or promoted: %v pending=%v", err, pending)
	}
	value, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationPublic, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{plan.Identity()}, []byte("closed source"), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewFileStore(filepath.Join(state, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), value, time.UnixMilli(150)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err = controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	lease, ok, err := coordinator.ClaimTask(context.Background(), plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(200))
	if err != nil || !ok {
		t.Fatalf("claim: %v", err)
	}
	success, err := controlplane.NewTaskSuccess(value.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(context.Background(), plan, lease, success, time.UnixMilli(201)); err != nil {
		t.Fatal(err)
	}
	// Fixture setup explicitly records the terminal event; observation must never do this.
	if _, err := coordinator.SucceedRun(context.Background(), plan, value.Identity(), time.UnixMilli(202)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSet(scope, strings.Repeat("b", 64), strings.Repeat("1", 40), strings.Repeat("c", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticStore, err := diagnostics.NewFileStore(filepath.Join(state, "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := diagnosticStore.PutDiagnosticSet(context.Background(), set); err != nil {
		t.Fatal(err)
	}
	if err := diagnosticStore.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := audit.NewFileLedger(filepath.Join(state, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	event, err := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, value.Identity(), nil, time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), "", event); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		point, pending, err = observeLocalRecoveryPoint(context.Background(), state, repository)
		if err != nil || pending || len(point.Runs) != 1 || point.Runs[0].Diagnostic != set.Identity() || point.Runs[0].AuditHead != event.Identity() {
			t.Fatalf("closed replay parity failed: %v pending=%v", err, pending)
		}
	})
	// Expiry is not applied during observation, but corrupted stored output is refused.
	artifactPath := filepath.Join(state, "artifacts", scope.Identity()+"-"+value.Identity()+".artifact.json")
	if err := os.WriteFile(artifactPath, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeLocalRecoveryPoint(context.Background(), state, repository); !errors.Is(err, artifact.ErrCorruptArtifact) {
		t.Fatalf("corrupt output accepted: %v", err)
	}
}
