package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
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
