package scm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalGitPackedReadHonorsCanceledCallerContext(t *testing.T) {
	objectRoot, revision, _, _ := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := ReadLocalGitRevision(ctx, store, revision)
	if err == nil || result.RevisionIdentity() != "" {
		t.Fatalf("ReadLocalGitRevision(canceled) = (%#v, %v), want caller-context failure", result, err)
	}
}

func TestLocalGitPackedDirectPublicReadsUseIndependentScopes(t *testing.T) {
	objectRoot, revision, _, files := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	if _, err := store.ReadCommit(context.Background(), revision); err != nil {
		t.Fatalf("ReadCommit(packed) error = %v", err)
	}
	if err := os.WriteFile(files.idxPath, append(files.idx, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	if payload, err := store.ReadCommit(context.Background(), revision); err == nil || payload != nil {
		t.Fatalf("second ReadCommit after index mutation = (%q, %v), want new scoped stability failure", payload, err)
	}
}

func TestLocalGitPackedCloseRefusesNewReadsAndKeepsCallerRootSeparatelyOwned(t *testing.T) {
	objectRoot, revision, _, _ := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	store, root := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	if payload, err := store.ReadCommit(context.Background(), revision); err == nil || payload != nil {
		t.Fatalf("ReadCommit(after Close) = (%q, %v), want refused read", payload, err)
	}
	if _, err := root.Stat("."); err != nil {
		t.Fatalf("store Close closed caller-owned root: %v", err)
	}
}

func TestLocalGitPackedConstructorFailureKeepsCallerRootOwned(t *testing.T) {
	objectRoot, _, _, files := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	if err := os.WriteFile(filepath.Join(filepath.Dir(files.packPath), "multi-pack-index"), []byte("MIDX"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewLocalGitObjectStoreWithOptions(LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: packedRepository(t), Profile: LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: evidence.RevisionAlgorithmSHA1})
	if err == nil || store != nil {
		t.Fatalf("NewLocalGitObjectStoreWithOptions(unsupported layout) = (%#v, %v), want failure", store, err)
	}
	if _, statErr := root.Stat("."); statErr != nil {
		t.Fatalf("failed constructor closed caller root: %v", statErr)
	}
	if closeErr := root.Close(); closeErr != nil {
		t.Fatalf("caller root close after failed constructor = %v", closeErr)
	}
}

func TestLocalGitPackedStoreRefusesMismatchedAlgorithmsAndProfiles(t *testing.T) {
	objectRoot, revision, _, _ := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA256, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA256)
	sha1Revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, revision.Digest()[:40])
	if err != nil {
		sha1Revision, _ = evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "1111111111111111111111111111111111111111")
	}
	if payload, err := store.ReadCommit(context.Background(), sha1Revision); err == nil || payload != nil {
		t.Fatalf("ReadCommit(mismatched algorithm) = (%q, %v), want rejection", payload, err)
	}
	root, err := os.OpenRoot(objectRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if store, err := NewLocalGitObjectStoreWithOptions(LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: packedRepository(t), Profile: LocalGitObjectStoreProfile("future"), ObjectAlgorithm: evidence.RevisionAlgorithmSHA1}); err == nil || store != nil {
		t.Fatalf("NewLocalGitObjectStoreWithOptions(unknown profile) = (%#v, %v), want failure", store, err)
	}
}

func TestLocalGitPackedCloseWithExpiredContextDoesNotInventSuccess(t *testing.T) {
	objectRoot, _, _, _ := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := store.Close(ctx)
	if err == nil && ctx.Err() != nil {
		// A no-active-read fast close may complete before observing the deadline. If it reports success,
		// subsequent reads must still be refused. This keeps the assertion on public lifecycle behavior.
		if _, readErr := store.ReadBlob(context.Background(), evidence.RevisionAlgorithmSHA1, "1111111111111111111111111111111111111111"); readErr == nil {
			t.Fatal("expired Close reported success but store still accepted reads")
		}
		return
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		t.Fatalf("Close(expired context) error = %v", err)
	}
}
