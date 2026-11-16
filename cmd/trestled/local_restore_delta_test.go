package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryCommandDetectsGitBytesAndInPlaceRestore(t *testing.T) {
	state, repository := stoppedRestoreFixture(t)
	stateRoot, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := readLocalSourceOwnerRecord(stateRoot, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := stateRoot.Close(); err != nil {
		t.Fatal(err)
	}
	gitLeaf := filepath.Join(owner.GitObjectsPath, "closed-object")
	original := []byte("closed object bytes")
	if err := os.WriteFile(gitLeaf, original, 0o444); err != nil {
		t.Fatal(err)
	}
	point, _, err := observeLocalRecoveryPoint(context.Background(), state, repository)
	if err != nil {
		t.Fatal(err)
	}
	if len(point.GitEntries) != 1 {
		t.Fatal("Git object bytes absent from record")
	}
	if err := os.Chmod(gitLeaf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gitLeaf, []byte("changed object bytes"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gitLeaf, 0o444); err != nil {
		t.Fatal(err)
	}
	changed, _, err := observeLocalRecoveryPoint(context.Background(), state, repository)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(compareLocalRecoveryPoint(point, changed), errRestoreObservationMismatch) {
		t.Fatal("Git object mismatch accepted")
	}
	// Restore only leaf bytes in the same retained directory, not a new owner.
	if err := os.Chmod(gitLeaf, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gitLeaf, original, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(gitLeaf, 0o444); err != nil {
		t.Fatal(err)
	}
	restored, _, err := observeLocalRecoveryPoint(context.Background(), state, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := compareLocalRecoveryPoint(point, restored); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "webhook-inbox"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "webhook-inbox", "pending"), []byte("uncertain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeLocalRecoveryPoint(context.Background(), state, repository); err == nil {
		t.Fatal("webhook uncertainty accepted")
	}
}
func TestRecoveryDiffNamesChangedInventory(t *testing.T) {
	expected := localRecoveryPoint{Entries: []localRecoveryEntry{{Path: "diagnostics/closed", Mode: 0o600, SHA256: "a"}}}
	observed := expected
	observed.Entries = []localRecoveryEntry{{Path: "diagnostics/closed", Mode: 0o600, SHA256: "b"}}
	err := compareLocalRecoveryPoint(expected, observed)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("diagnostics/closed")) {
		t.Fatalf("no changed path: %v", err)
	}
}

func TestRecoveryObservationRefusesUnfinishedDeletion(t *testing.T) {
	state, repository := stoppedRestoreFixture(t)
	scope, err := audit.NewReviewScope("tenant-one", "repository-one", "deleted-run")
	if err != nil {
		t.Fatal(err)
	}
	plan := startupContextPlan(t, scope, strings.Repeat("c", 64))
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
	if _, err := coordinator.CancelRun(context.Background(), plan, time.UnixMilli(110)); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindSourceSnapshot, "application/json", artifact.ClassificationPublic, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{plan.Identity()}, []byte("deleted bytes"), time.UnixMilli(100), time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifact.Encode(value)
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
	authorization, err := artifact.NewDeletionAuthorization(scope, value.Identity(), strings.Repeat("a", 64), "operator.local", strings.Repeat("b", 64), artifact.DeletionExpired, time.UnixMilli(200), time.UnixMilli(400))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(context.Background(), authorization, time.UnixMilli(250)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeLocalRecoveryPoint(context.Background(), state, repository); err != nil {
		t.Fatalf("completed deletion refused: %v", err)
	}
	deletionPath := filepath.Join(state, "artifacts", scope.Identity()+"-"+value.Identity()+".artifact-deleted.json")
	completed, err := os.ReadFile(deletionPath)
	if err != nil {
		t.Fatal(err)
	}
	pending := bytes.Replace(completed, []byte(`"completed":true`), []byte(`"completed":false`), 1)
	if bytes.Equal(completed, pending) {
		t.Fatal("invalid pending fixture")
	}
	if err := os.WriteFile(deletionPath, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		if _, _, err := observeLocalRecoveryPoint(context.Background(), state, repository); err == nil {
			t.Fatal("pending deletion accepted")
		}
	})
	if err := os.WriteFile(deletionPath, completed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "artifacts", scope.Identity()+"-"+value.Identity()+".artifact.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := observeLocalRecoveryPoint(context.Background(), state, repository); err == nil {
		t.Fatal("completed record with remaining artifact accepted")
	}
}
