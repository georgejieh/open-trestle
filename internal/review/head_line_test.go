package review

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
)

// headLinePacket is the removed-guard packet with the removed_lines source
// naming the given head line of its deletion point.
func headLinePacket(t *testing.T, headLine int) (ContextPacket, ReviewSnapshot, []byte) {
	t.Helper()
	reviewScope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	memoryScope, _ := memory.NewScope("tenant", "repository", "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"."})
	window := boundSource(t, ContextStageChangedHunk, "calc.go", removedGuardHead, 1, 5)
	plain := boundSource(t, ContextStageRemovedLines, "calc.go", removedGuardBase, 4, 6)
	removed, err := NewRemovedLinesContextSource(plain.EvidenceItem(), plain.Content(), plain.SliceBinding(), headLine)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewReviewSnapshot("workspace", strings.Repeat("b", 64), []evidence.SourceRange{window.EvidenceItem().SourceRange()})
	if err != nil {
		t.Fatal(err)
	}
	query, _ := memory.NewLexicalQuery(memoryScope, "calc.go", nil, nil, time.UnixMilli(200), 5)
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := NewContextLimits(1<<20, 5)
	packet, err := NewContextPacketWithAccounting(reviewScope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{removed, window}, []memory.LexicalRetrieval{retrieval}, nil, limits)
	if err != nil {
		t.Fatal(err)
	}
	request, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	return packet, snapshot, request.Payload()
}

func TestRemovedLinesHeadLineIsBoundToItsDeletionPoint(t *testing.T) {
	packet, snapshot, payload := headLinePacket(t, 3)
	if !bytes.Contains(payload, []byte(`"head_line":3`)) || bytes.Count(payload, []byte(`"head_line"`)) != 1 {
		t.Fatalf("head line not recorded once on the removed_lines source: %s", payload)
	}
	validate := func(payload []byte) error {
		return ValidateContextPacketRequest(payload, modelContractDigest(payload), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems())
	}
	if err := ValidateContextPacketRequest(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems()); err != nil {
		t.Fatalf("head line inside the deletion-point window rejected: %v", err)
	}
	// A head line outside every changed hunk of the file names no deletion
	// point of this packet.
	_, outsideSnapshot, outside := headLinePacket(t, 9)
	if outsideSnapshot.Identity() != snapshot.Identity() || validate(outside) == nil {
		t.Fatal("head line outside the deletion-point window accepted")
	}
	// Only a removed_lines source carries a head line.
	onHead := bytes.Replace(payload, []byte(`"end_line":5,"risk_flags"`), []byte(`"end_line":5,"head_line":3,"risk_flags"`), 1)
	if bytes.Equal(onHead, payload) || validate(onHead) == nil {
		t.Fatal("head line on a changed_hunk source accepted")
	}
	window := boundSource(t, ContextStageChangedHunk, "calc.go", removedGuardHead, 1, 5)
	if _, err := NewRemovedLinesContextSource(window.EvidenceItem(), window.Content(), window.SliceBinding(), -1); !errors.Is(err, ErrInvalidContextSource) {
		t.Fatalf("negative head line accepted: %v", err)
	}
}

// A base-side finding carries its deletion point's head line from admission
// through verification and its recorded forms.
func TestBaseSideFindingCarriesItsHeadLine(t *testing.T) {
	packet, snapshot, payload := headLinePacket(t, 3)
	var removedID, windowID string
	for _, source := range packet.Sources() {
		if source.Stage() == ContextStageRemovedLines {
			removedID = source.ReferenceID()
		} else {
			windowID = source.ReferenceID()
		}
	}
	document := `{"schema_version":2,"candidates":[{"title":"Removed zero guard","claim":"The removed check guarded the division by b.","category":"correctness","severity_hint":"high","source_range":{"source_id":"` + removedID + `","start_line":4,"end_line":6},"evidence_ids":["` + removedID + `","` + windowID + `"]}]}`
	candidates, err := ParseContextCandidateBatch(v7Response(t, document), payload, snapshot, packet.EvidenceItems())
	if err != nil || len(candidates.Findings()) != 1 {
		t.Fatalf("base-side candidate refused: %v", err)
	}
	candidate := candidates.Findings()[0]
	if candidate.Side() != LineSideBase || candidate.HeadLine() != 3 {
		t.Fatalf("candidate side=%s head line=%d", candidate.Side(), candidate.HeadLine())
	}
	encoded, err := EncodeCandidateBatch(candidates)
	if err != nil || !bytes.Contains(encoded, []byte(`"side":"base","head_line":3`)) {
		t.Fatalf("encoded candidate: %s, %v", encoded, err)
	}
	if parsed, err := ParseEncodedCandidateBatch(encoded); err != nil || parsed.Identity() != candidates.Identity() || !CandidateBatchMatchesContext(payload, parsed) {
		t.Fatalf("base-side candidate does not read back: %v", err)
	}
	if _, err := ParseEncodedCandidateBatch(bytes.Replace(encoded, []byte(`"head_line":3`), []byte(`"head_line":4`), 1)); err == nil {
		t.Fatal("candidate with another head line read back")
	}
	request, err := NewVerificationRequestContext(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	verdict := func(cited string) string {
		return `{"schema_version":1,"verdicts":[{"candidate_id":"c1","outcome":"verified","severity":"high","rationale":"The removed lines returned early when b was zero.","evidence_ids":` + cited + `}]}`
	}
	// Only removed_lines evidence covers a base-side location: a verdict that
	// cites only head evidence also cites the candidate's removed lines, as a
	// base binding.
	headCited, err := ParseContextVerificationBatch(v7Response(t, verdict(`["`+windowID+`"]`)), candidates, request)
	if err != nil || !slices.Contains(headCited.Results()[0].EvidenceIDs(), removedID) || !VerificationBatchMatchesContext(request, candidates, headCited) {
		t.Fatalf("head-cited verdict on a base-side candidate: %v", err)
	}
	if encoded, err := EncodeVerificationBatch(headCited); err != nil || !bytes.Contains(encoded, []byte(`"side":"base"`)) {
		t.Fatalf("the implied removed-lines citation is not a base binding: %s", encoded)
	}
	batch, err := ParseContextVerificationBatch(v7Response(t, verdict(`["`+removedID+`"]`)), candidates, request)
	if err != nil || batch.Results()[0].Side() != LineSideBase || !VerificationBatchMatchesContext(request, candidates, batch) {
		t.Fatalf("base-side verdict: %v", err)
	}
	if encoded, err := EncodeVerificationBatch(batch); err != nil || !bytes.Contains(encoded, []byte(`"schema_version":2`)) {
		t.Fatalf("base-side verdict is not a version 2 batch: %s", encoded)
	}
}
