package artifact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// observerDeletionFixture builds a private store root, a scope, one artifact and the
// canonical deletion receipt for it, without opening a writer.
func observerDeletionFixture(t *testing.T) (string, audit.ReviewScope, Artifact, DeletionReceipt) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(scope, KindSourceSnapshot, "application/json", ClassificationPublic, OriginHost, ProtectionProcessPrivate,
		[]string{strings.Repeat("a", 64)}, []byte("observed payload"), time.UnixMilli(1000), time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := NewDeletionAuthorization(scope, value.Identity(), strings.Repeat("1", 64), "operator.local",
		strings.Repeat("2", 64), DeletionExpired, time.UnixMilli(1000), time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(1500))
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory, scope, value, receipt
}

func TestObserveFileDeletionReportsPendingRecordWithoutMutation(t *testing.T) {
	directory, scope, value, receipt := observerDeletionFixture(t)
	encoded, err := encodeDeletionRecord(receipt, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, artifactDeletionFileName(scope, value.Identity())), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before := observerArtifactDirectoryState(t, directory)
	observed, completed, err := ObserveFileDeletion(context.Background(), root, scope, value.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if completed {
		t.Fatal("pending deletion record reported as completed")
	}
	if observed.Identity() != receipt.Identity() || observed.ArtifactIdentity() != value.Identity() ||
		observed.PayloadDigest() != receipt.PayloadDigest() || observed.Scope().Identity() != scope.Identity() {
		t.Fatalf("deletion receipt mismatch: %v", observed.Identity())
	}
	if after := observerArtifactDirectoryState(t, directory); !reflect.DeepEqual(before, after) {
		t.Fatal("observation changed the store")
	}
	if _, err := os.Lstat(filepath.Join(directory, artifactLockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("observation created a writer lock: %v", err)
	}
}

func TestObserveFileDeletionReportsCompletedRecord(t *testing.T) {
	directory, scope, value, receipt := observerDeletionFixture(t)
	encoded, err := encodeDeletionRecord(receipt, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, artifactDeletionFileName(scope, value.Identity())), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	observed, completed, err := ObserveFileDeletion(context.Background(), root, scope, value.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if !completed {
		t.Fatal("completed deletion record reported as pending")
	}
	if observed.Identity() != receipt.Identity() || observed.ArtifactIdentity() != value.Identity() {
		t.Fatalf("deletion receipt mismatch: %v", observed.Identity())
	}
}

func TestObserveFileDeletionReportsMissingLeaf(t *testing.T) {
	directory, scope, value, _ := observerDeletionFixture(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, _, err := ObserveFileDeletion(context.Background(), root, scope, value.Identity()); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("missing deletion record accepted: %v", err)
	}
}

func TestObserveFileDeletionRefusesCorruptRecord(t *testing.T) {
	directory, scope, value, _ := observerDeletionFixture(t)
	if err := os.WriteFile(filepath.Join(directory, artifactDeletionFileName(scope, value.Identity())), []byte("not a deletion record"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, _, err := ObserveFileDeletion(context.Background(), root, scope, value.Identity()); !errors.Is(err, ErrCorruptArtifact) {
		t.Fatalf("corrupt deletion record accepted: %v", err)
	}
}
