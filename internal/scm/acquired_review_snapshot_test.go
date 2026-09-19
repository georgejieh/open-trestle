package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestBindAcquiredReviewSnapshotBindsExactPairAndChangedRanges(t *testing.T) {
	adapter, baseRequest, headRequest, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	pair, err := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	sourceRange, _ := evidence.NewSourceRange("changed.go", 1, 1)
	snapshot, err := BindAcquiredReviewSnapshot("workspace", pair, baseRequest, headRequest, []evidence.SourceRange{sourceRange})
	if err != nil || snapshot.Identity() == "" || snapshot.RepositoryIdentity() != headRequest.RepositoryIdentity() || snapshot.BaseRevision() != baseRequest.Revision() || snapshot.HeadRevision() != headRequest.Revision() || snapshot.BaseBindingIdentity() != pair.BaseEnvelope().EvidenceBinding().Identity() || snapshot.HeadBindingIdentity() != pair.HeadEnvelope().EvidenceBinding().Identity() || snapshot.ManifestDelta().Identity() != pair.ManifestDelta().Identity() || snapshot.Validate() != nil {
		t.Fatalf("snapshot=(%#v,%v)", snapshot, err)
	}
	ledger := audit.NewMemoryLedger()
	scope, _ := audit.NewReviewScope("tenant", snapshot.RepositoryIdentity(), "review-run")
	event, err := review.RecordAcquiredReviewSnapshot(context.Background(), ledger, scope, snapshot, time.UnixMilli(100))
	if err != nil || event.Kind() != audit.EventReviewSnapshotBound || event.SubjectIdentity() != snapshot.Identity() {
		t.Fatalf("snapshot audit = (%#v, %v)", event, err)
	}
	target, err := review.NewPublicationTarget("github", headRequest.Repository(), "pull-42", headRequest.Revision())
	if err != nil || !snapshot.MatchesPublicationTarget(target) {
		t.Fatalf("target match=(%#v,%v)", target, err)
	}
}

func TestBindAcquiredReviewSnapshotRejectsUnchangedRemovedAndCrossWiredInputs(t *testing.T) {
	adapter, baseRequest, headRequest, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	pair, _ := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
	for _, test := range []struct {
		name, path string
		want       error
	}{
		{"unchanged", "same.go", review.ErrAcquiredReviewRangeNotChanged},
		{"removed", "removed.go", review.ErrAcquiredReviewRangeNotInHead},
	} {
		t.Run(test.name, func(t *testing.T) {
			sourceRange, _ := evidence.NewSourceRange(test.path, 1, 1)
			snapshot, err := BindAcquiredReviewSnapshot("workspace", pair, baseRequest, headRequest, []evidence.SourceRange{sourceRange})
			if !errors.Is(err, test.want) || snapshot.Identity() != "" {
				t.Fatalf("snapshot=(%#v,%v),want %v", snapshot, err, test.want)
			}
		})
	}
	sourceRange, _ := evidence.NewSourceRange("changed.go", 1, 1)
	if snapshot, err := BindAcquiredReviewSnapshot("workspace", pair, headRequest, baseRequest, []evidence.SourceRange{sourceRange}); err == nil || snapshot.Identity() != "" {
		t.Fatalf("cross-wired snapshot=(%#v,%v)", snapshot, err)
	}
	bare, err := newLocalGitAcquisitionPair(pair.BaseEnvelope(), pair.HeadEnvelope(), pair.ManifestDelta())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := BindAcquiredReviewSnapshot("workspace", bare, baseRequest, headRequest, []evidence.SourceRange{sourceRange}); err == nil || snapshot.Identity() != "" {
		t.Fatalf("manifest-free snapshot=(%#v,%v)", snapshot, err)
	}
}

func TestBindAcquiredContextPacketRequiresExactHeadSlices(t *testing.T) {
	adapter, baseRequest, headRequest, _, headContents := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	pair, _ := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
	sourceRange, _ := evidence.NewSourceRange("changed.go", 1, 1)
	snapshot, err := BindAcquiredReviewSnapshot("workspace", pair, baseRequest, headRequest, []evidence.SourceRange{sourceRange})
	if err != nil {
		t.Fatal(err)
	}
	content := headContents["changed.go"]
	file, _ := pair.HeadManifest().File("changed.go")
	sliceBinding, err := evidence.BindSourceSlice(file, content, sourceRange, content)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	item, _ := evidence.NewEvidenceItem("changed-source", evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), sourceRange)
	source, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, content, sliceBinding)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant", snapshot.RepositoryIdentity(), "review-run")
	memoryScope, _ := memory.NewScope("tenant", snapshot.RepositoryIdentity(), "actor", memory.RefVisibilityExact, strings.Repeat("f", 64), []string{"changed.go"})
	query, _ := memory.NewLexicalQuery(memoryScope, "changed.go", []string{"changed"}, nil, time.UnixMilli(100), 10)
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := review.NewContextLimits(1024, 0)
	packet, err := review.NewContextPacket(scope, memoryScope, snapshot.PipelineSnapshot(), review.ContextTaskCandidateGeneration, []review.ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := review.BindAcquiredContextPacket(snapshot, packet)
	if err != nil || binding.Identity() == "" || binding.AcquiredSnapshotIdentity() != snapshot.Identity() || binding.ContextPacketIdentity() != packet.Identity() || binding.SliceBindingIdentities()[0] != sliceBinding.Identity() || binding.Validate() != nil {
		t.Fatalf("context binding=(%#v,%v)", binding, err)
	}
	ledger := audit.NewMemoryLedger()
	auditReceipt, err := review.RecordAcquiredGenerationContext(context.Background(), ledger, scope, snapshot, packet, binding, time.UnixMilli(100))
	if err != nil || auditReceipt.Identity() == "" || len(auditReceipt.Events()) != 4 || auditReceipt.Validate() != nil {
		t.Fatalf("acquired generation audit=(%#v,%v)", auditReceipt, err)
	}
	unbound, _ := review.NewContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, content)
	unboundPacket, _ := review.NewContextPacket(scope, memoryScope, snapshot.PipelineSnapshot(), review.ContextTaskCandidateGeneration, []review.ContextSource{unbound}, retrieval, limits)
	if invalid, err := review.BindAcquiredContextPacket(snapshot, unboundPacket); !errors.Is(err, review.ErrAcquiredContextSourceUnbound) || invalid.Identity() != "" {
		t.Fatalf("unbound context=(%#v,%v)", invalid, err)
	}
}
