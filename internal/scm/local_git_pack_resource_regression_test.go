package scm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func packedRegressionContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 30*time.Second)
}

func TestLocalGitPackedMissingTreeObjectClassifiesObjectUnavailableAndIncomplete(t *testing.T) {
	objectRoot, revision := packedMissingBlobRevisionFixture(t, evidence.RevisionAlgorithmSHA1)
	err := packedReadRevisionRegressionError(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)
	if !errors.Is(err, LocalGitRevisionObjectUnavailable) {
		t.Fatalf("ReadLocalGitRevision(missing packed tree object) error = %v, want %v", err, LocalGitRevisionObjectUnavailable)
	}

	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	adapter, err := NewLocalGitPackedSourceAdapter(store)
	if err != nil {
		t.Fatalf("NewLocalGitPackedSourceAdapter() error = %v", err)
	}
	request, err := evidence.NewRepositoryAcquisitionRequest(packedRepository(t), revision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	if request.RepositoryIdentity() != store.RepositoryIdentity() {
		t.Fatalf("request repository identity %q does not match store %q", request.RepositoryIdentity(), store.RepositoryIdentity())
	}
	ctx, cancel := packedRegressionContext(t)
	result := adapter.Acquire(ctx, request)
	cancel()
	if result.Outcome != evidence.AcquisitionOutcomeFailed || result.Reason != evidence.AcquisitionReasonArtifactIncomplete {
		t.Fatalf("Acquire(missing packed tree object) = (%q, %q), want (%q, %q)", result.Outcome, result.Reason, evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonArtifactIncomplete)
	}
}

func TestLocalGitPackedDepthResourceLimitSurvivesTraversalAndAdapter(t *testing.T) {
	objectRoot, revision := packedDepthOverflowRevisionFixture(t, evidence.RevisionAlgorithmSHA1)
	err := packedReadRevisionRegressionError(t, objectRoot, evidence.RevisionAlgorithmSHA1, revision)
	if !errors.Is(err, LocalGitRevisionResourceLimit) {
		t.Fatalf("ReadLocalGitRevision(depth overflow) error = %v, want %v", err, LocalGitRevisionResourceLimit)
	}

	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	adapter, err := NewLocalGitPackedSourceAdapter(store)
	if err != nil {
		t.Fatalf("NewLocalGitPackedSourceAdapter() error = %v", err)
	}
	request, err := evidence.NewRepositoryAcquisitionRequest(packedRepository(t), revision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	ctx, cancel := packedRegressionContext(t)
	result := adapter.Acquire(ctx, request)
	cancel()
	if result.Outcome != evidence.AcquisitionOutcomeFailed || result.Reason != evidence.AcquisitionReasonResourceLimit {
		t.Fatalf("Acquire(depth overflow) = (%q, %q), want (%q, %q)", result.Outcome, result.Reason, evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonResourceLimit)
	}
}

func TestLocalGitPackedCanceledContextIsPreserved(t *testing.T) {
	objectRoot, revision, _, _ := packedSimpleRevisionFixture(t, evidence.RevisionAlgorithmSHA1, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := ReadLocalGitRevision(ctx, store, revision)
	if !errors.Is(err, context.Canceled) || result.RevisionIdentity() != "" {
		t.Fatalf("ReadLocalGitRevision(canceled) = (%#v, %v), want context.Canceled and no result", result, err)
	}
}

func TestLocalGitPackedRepeatedSameBaseDeltaCopiesRespectWorkBudget(t *testing.T) {
	objectRoot, revision, _ := packedSameBaseTinyDeltaRevisionFixture(t, evidence.RevisionAlgorithmSHA1, 31<<20, 18)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	ctx, cancel := packedRegressionContext(t)
	result, err := ReadLocalGitRevision(ctx, store, revision)
	cancel()
	if !errors.Is(err, LocalGitRevisionResourceLimit) || result.RevisionIdentity() != "" {
		t.Fatalf("ReadLocalGitRevision(repeated same-base delta copies) = (%#v, %v), want %v", result, err, LocalGitRevisionResourceLimit)
	}
}

func TestLocalGitPackedSameBaseDeltaCacheHitUnderBudgetPreservesOutputs(t *testing.T) {
	objectRoot, revision, want := packedSameBaseTinyDeltaRevisionFixture(t, evidence.RevisionAlgorithmSHA1, 1<<20, 4)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)
	ctx, cancel := packedRegressionContext(t)
	result, err := ReadLocalGitRevision(ctx, store, revision)
	cancel()
	if err != nil {
		t.Fatalf("ReadLocalGitRevision(under-budget same-base deltas) error = %v", err)
	}
	contents := result.Contents()
	if len(contents) != len(want) || result.FileCount() != len(want) {
		t.Fatalf("under-budget contents count = (%d, %d), want %d", len(contents), result.FileCount(), len(want))
	}
	for path, wantContent := range want {
		if got := contents[path]; !bytes.Equal(got, wantContent) {
			t.Fatalf("content %q = %q, want %q", path, got, wantContent)
		}
	}
}

func TestLocalGitPackedCatalogHeaderAndOIDLookupReadsAreAccounted(t *testing.T) {
	builder := newPackedTestBuilder(t, evidence.RevisionAlgorithmSHA1)
	base := builder.addWhole(t, "blob", []byte("catalog accounting base"))
	builder.addREFDelta(t, base, "blob", []byte("catalog accounting child"))
	objectRoot := t.TempDir()
	files := packedWritePackAndIndex(t, objectRoot, builder, nil)
	store, _ := packedOpenStore(t, objectRoot, evidence.RevisionAlgorithmSHA1)

	var gotPhysical int64
	ctx, cancel := packedRegressionContext(t)
	err := store.withPackScope(ctx, func(scope *localGitPackScope) error {
		gotPhysical = scope.physicalReadBytes
		return nil
	})
	cancel()
	if err != nil {
		t.Fatalf("withPackScope(catalog accounting) error = %v", err)
	}
	countedBuildFloor := packedCatalogBuildAccountedFloor(t, evidence.RevisionAlgorithmSHA1, files)
	headerAndLookupFloor := packedCatalogHeaderAndOIDLookupFloor(t, evidence.RevisionAlgorithmSHA1, files)
	if gotPhysical < countedBuildFloor+headerAndLookupFloor {
		t.Fatalf("catalog physical bytes = %d, want at least counted build floor %d plus header/OID lookup floor %d", gotPhysical, countedBuildFloor, headerAndLookupFloor)
	}
}

func packedReadRevisionRegressionError(t *testing.T, objectRoot string, algorithm evidence.RevisionAlgorithm, revision evidence.RevisionIdentity) error {
	t.Helper()
	store, _ := packedOpenStore(t, objectRoot, algorithm)
	ctx, cancel := packedRegressionContext(t)
	result, err := ReadLocalGitRevision(ctx, store, revision)
	cancel()
	if err == nil || result.RevisionIdentity() != "" {
		t.Fatalf("ReadLocalGitRevision() = (%#v, %v), want failure and no result", result, err)
	}
	return err
}

func packedMissingBlobRevisionFixture(t *testing.T, algorithm evidence.RevisionAlgorithm) (string, evidence.RevisionIdentity) {
	t.Helper()
	builder := newPackedTestBuilder(t, algorithm)
	missingDigest := packedObjectDigest(t, algorithm, "blob", []byte("missing packed blob\n"))
	treePayload := packedTreeEntry(t, algorithm, "100644", "missing.txt", missingDigest)
	tree := builder.addWhole(t, "tree", treePayload)
	commitPayload := []byte("tree " + builder.entries[tree].digest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nmissing packed blob fixture\n")
	commit := builder.addWhole(t, "commit", commitPayload)
	objectRoot := t.TempDir()
	packedWritePackAndIndex(t, objectRoot, builder, nil)
	return objectRoot, packedRevision(t, algorithm, builder.entries[commit].digest)
}

func packedDepthOverflowRevisionFixture(t *testing.T, algorithm evidence.RevisionAlgorithm) (string, evidence.RevisionIdentity) {
	t.Helper()
	builder := newPackedTestBuilder(t, algorithm)
	last := builder.addWhole(t, "blob", []byte("depth-00"))
	for i := 1; i <= maxLocalGitPackDeltaDepth+1; i++ {
		last = builder.addREFDelta(t, last, "blob", []byte(fmt.Sprintf("depth-%02d", i)))
	}
	return packedCommitSelectingBlob(t, builder, last, "deep.txt")
}

func packedSameBaseTinyDeltaRevisionFixture(t *testing.T, algorithm evidence.RevisionAlgorithm, baseSize int, children int) (string, evidence.RevisionIdentity, map[string][]byte) {
	t.Helper()
	if baseSize <= 0 || baseSize > maxLocalGitPackBaseCacheBytes {
		t.Fatalf("base size %d is outside the admitted cache-sized bound", baseSize)
	}
	if children <= 0 {
		t.Fatalf("children = %d, want positive", children)
	}
	builder := newPackedTestBuilder(t, algorithm)
	basePayload := bytes.Repeat([]byte{'B'}, baseSize)
	base := builder.addWhole(t, "blob", basePayload)
	want := make(map[string][]byte, children)
	var treePayload []byte
	for i := 0; i < children; i++ {
		path := fmt.Sprintf("child-%03d.txt", i)
		content := []byte(fmt.Sprintf("tiny child %03d\n", i))
		child := builder.addREFDelta(t, base, "blob", content)
		want[path] = append([]byte(nil), content...)
		treePayload = append(treePayload, packedTreeEntry(t, algorithm, "100644", path, builder.entries[child].digest)...)
	}
	tree := builder.addWhole(t, "tree", treePayload)
	commitPayload := []byte("tree " + builder.entries[tree].digest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nsame base tiny deltas\n")
	commit := builder.addWhole(t, "commit", commitPayload)
	objectRoot := t.TempDir()
	packedWritePackAndIndex(t, objectRoot, builder, nil)
	return objectRoot, packedRevision(t, algorithm, builder.entries[commit].digest), want
}

func packedCatalogBuildAccountedFloor(t *testing.T, algorithm evidence.RevisionAlgorithm, files packedTestFiles) int64 {
	t.Helper()
	hashLen := int64(packedHashSize(t, algorithm))
	objectCount := int64(len(files.entries))
	indexVerification := int64(8+256*4) + int64(len(files.idx)) + hashLen + objectCount*(hashLen+8)
	packVerification := int64(12) + int64(len(files.pack))
	return indexVerification + packVerification
}

func packedCatalogHeaderAndOIDLookupFloor(t *testing.T, algorithm evidence.RevisionAlgorithm, files packedTestFiles) int64 {
	t.Helper()
	hashLen := int64(packedHashSize(t, algorithm))
	var total int64
	for _, entry := range files.entries {
		declaredSize := len(entry.payload)
		if entry.packType == packedTypeOFSDelta || entry.packType == packedTypeREFDelta {
			declaredSize = len(entry.delta)
		}
		total += int64(len(packedEncodeObjectHeader(entry.packType, declaredSize)))
		if entry.packType == packedTypeREFDelta {
			total += hashLen // REF_DELTA base object id in the pack stream.
			total += hashLen // At least one same-pack OID table read while checking that base.
		}
	}
	return total
}
