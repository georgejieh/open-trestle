package scm

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteRepositoryAcquisitionSnapshotRetainsValidatedCopies(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	result := fixture.acquiredResult()
	adapter := &fakeSourceAdapter{identity: fixture.adapter, result: result}
	snapshot, err := ExecuteRepositoryAcquisitionSnapshot(context.Background(), fixture.request, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Validate() != nil || snapshot.Identity() == "" || snapshot.Execution().Outcome() != evidence.AcquisitionOutcomeAcquired || snapshot.Manifest().Identity() != fixture.manifest.Identity() {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	contents := snapshot.Contents()
	if !bytes.Equal(contents["file"], []byte("content")) {
		t.Fatalf("contents = %#v", contents)
	}
	contents["file"][0] = 'x'
	delete(contents, "file")
	if !bytes.Equal(snapshot.Contents()["file"], []byte("content")) {
		t.Fatal("snapshot contents were mutable")
	}
	result.Contents["file"][0] = 'z'
	if !bytes.Equal(snapshot.Contents()["file"], []byte("content")) {
		t.Fatal("adapter result content was retained by reference")
	}
}

func TestExecuteRepositoryAcquisitionSnapshotPreservesTypedTerminalResult(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	adapter := &fakeSourceAdapter{identity: fixture.adapter, result: SourceAdapterResult{
		Outcome: evidence.AcquisitionOutcomeBlocked,
		Reason:  evidence.AcquisitionReasonAuthorizationRequired,
	}}
	snapshot, err := ExecuteRepositoryAcquisitionSnapshot(context.Background(), fixture.request, adapter)
	if err != nil || snapshot.Validate() != nil || snapshot.Execution().Outcome() != evidence.AcquisitionOutcomeBlocked || snapshot.Manifest().Identity() != "" || snapshot.Contents() != nil {
		t.Fatalf("snapshot = (%#v, %v)", snapshot, err)
	}
}

func TestExecuteRepositoryAcquisitionSnapshotRejectsManifestOnlyAndInvalidResults(t *testing.T) {
	manifestFixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifest)
	adapter := &fakeSourceAdapter{identity: manifestFixture.adapter, result: manifestFixture.acquiredResult()}
	if snapshot, err := ExecuteRepositoryAcquisitionSnapshot(context.Background(), manifestFixture.request, adapter); err == nil || snapshot.Identity() != "" || adapter.calls != 0 {
		t.Fatalf("manifest-only snapshot = (%#v, %v), calls=%d", snapshot, err, adapter.calls)
	}

	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	adapter = &fakeSourceAdapter{identity: fixture.adapter, result: SourceAdapterResult{
		Outcome:  evidence.AcquisitionOutcomeAcquired,
		Reason:   evidence.AcquisitionReasonNone,
		Manifest: fixture.manifest,
		Contents: map[string][]byte{"file": []byte("changed")},
	}}
	if snapshot, err := ExecuteRepositoryAcquisitionSnapshot(context.Background(), fixture.request, adapter); err == nil || snapshot.Identity() != "" {
		t.Fatalf("invalid snapshot = (%#v, %v)", snapshot, err)
	}
}

func TestExecuteRepositoryAcquisitionSnapshotHonorsCancellation(t *testing.T) {
	fixture := mustExecutionFixture(t, evidence.AcquisitionArtifactManifestAndContent)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	adapter := &fakeSourceAdapter{identity: fixture.adapter, result: fixture.acquiredResult()}
	snapshot, err := ExecuteRepositoryAcquisitionSnapshot(ctx, fixture.request, adapter)
	if !errors.Is(err, context.Canceled) || snapshot.Identity() != "" || adapter.calls != 0 {
		t.Fatalf("snapshot = (%#v, %v), calls=%d", snapshot, err, adapter.calls)
	}
}
