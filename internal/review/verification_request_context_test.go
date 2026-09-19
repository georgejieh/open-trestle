package review

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/memory"
)

func TestNewVerificationRequestContextBuildsDistinctCanonicalRequest(t *testing.T) {
	scope, memoryScope, snapshot, source, retrieval := contextPacketFixture(t, "line 10\nline 11\n")
	limits, _ := NewContextLimits(1<<20, 5)
	generation, err := NewContextPacket(scope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, _ := generation.ProviderRequest()
	candidateResponse, _, _ := candidateFixture(t, `{"schema_version":1,"candidates":[{"title":"Issue","claim":"The value is unchecked.","severity_hint":"high","source_range":{"source_id":"source-1","start_line":10,"end_line":10},"evidence_ids":["source-1"]}]}`)
	candidates, err := ParseCandidateBatch(candidateResponse, snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	verification, err := NewVerificationRequestContext(
		generationRequest.Payload(), generation.Identity(), scope.Identity(), generation.MemoryScopeIdentity(), generation.MemoryIdentity(), snapshot,
		generation.EvidenceItems(), candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := verification.ProviderRequest()
	if err != nil || verification.Validate() != nil || request.Identity() == generationRequest.Identity() || verification.GenerationContextIdentity() != generation.Identity() || verification.CandidateBatchIdentity() != candidates.Identity() || verification.SnapshotIdentity() != snapshot.Identity() {
		t.Fatalf("verification context=(%#v,%v)", verification, err)
	}
	repeated, err := NewVerificationRequestContext(
		generationRequest.Payload(), generation.Identity(), scope.Identity(), generation.MemoryScopeIdentity(), generation.MemoryIdentity(), snapshot,
		generation.EvidenceItems(), candidates,
	)
	if err != nil || repeated.Identity() != verification.Identity() || !bytes.Equal(repeated.Payload(), verification.Payload()) {
		t.Fatalf("repeated context=(%#v,%v)", repeated, err)
	}
	changed := append([]byte(nil), generationRequest.Payload()...)
	changed[0] = ' '
	if value, err := NewVerificationRequestContext(changed, generation.Identity(), scope.Identity(), generation.MemoryScopeIdentity(), generation.MemoryIdentity(), snapshot, generation.EvidenceItems(), candidates); err == nil || value.Identity() != "" {
		t.Fatalf("changed generation context=(%#v,%v)", value, err)
	}
}

func TestVerificationRequestContextPreservesCountedGenerationOmissions(t *testing.T) {
	scope, memoryScope, snapshot, source, retrieval := contextPacketFixture(t, "line 10\n")
	limits, _ := NewContextLimits(1<<20, 5)
	omission, _ := NewCountedContextSourceOmission("other.go", 20, 20, "semantic_candidate_limit", 172)
	generation, err := NewContextPacketWithAccounting(scope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, []memory.LexicalRetrieval{retrieval}, []ContextSourceOmission{omission}, limits)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, _ := generation.ProviderRequest()
	candidateResponse, _, _ := candidateFixture(t, `{"schema_version":1,"candidates":[{"title":"Issue","claim":"The value is unchecked.","severity_hint":"high","source_range":{"source_id":"source-1","start_line":10,"end_line":10},"evidence_ids":["source-1"]}]}`)
	candidates, err := ParseCandidateBatch(candidateResponse, snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	verification, err := NewVerificationRequestContext(generationRequest.Payload(), generation.Identity(), scope.Identity(), generation.MemoryScopeIdentity(), generation.MemoryIdentity(), snapshot, generation.EvidenceItems(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	var wire verificationContextWire
	if json.Unmarshal(verification.Payload(), &wire) != nil {
		t.Fatal("decode")
	}
	coverage := verification.SourceCoverage()
	if wire.SourceCoverage.PreselectionOmitted != 172 || wire.SourceCoverage.Omitted != 172 || len(wire.SourceOmissions) != 1 || wire.SourceOmissions[0].Count != 172 ||
		coverage.Validate() != nil || coverage.VerificationContextIdentity() != verification.Identity() || coverage.ReviewScopeIdentity() != scope.Identity() || coverage.SnapshotIdentity() != snapshot.Identity() || coverage.CandidateBatchIdentity() != candidates.Identity() || coverage.AnalyzedCount() != 173 || coverage.SelectedCount() != 1 || coverage.OmittedCount() != 172 || len(coverage.OmissionSummaries()) != 1 || coverage.OmissionSummaries()[0].Reason() != ContextOmissionResourceLimit || coverage.OmissionSummaries()[0].Count() != 172 {
		t.Fatalf("coverage=%#v exported=%#v omissions=%#v", wire.SourceCoverage, coverage, wire.SourceOmissions)
	}
}

func TestContextSourceOmissionCategoriesCoverCanonicalReasons(t *testing.T) {
	tests := map[ContextSourceOmissionCategory][]string{
		ContextOmissionAuthorization:   {"path_not_authorized", "semantic_path_not_authorized"},
		ContextOmissionResourceLimit:   {"candidate_limit", "source_size_limit", "analysis_resource_limit", "analysis_slice_resource_limit", "analysis_evidence_limit", "semantic_limit_exceeded", "semantic_candidate_limit", "semantic_source_size_limit"},
		ContextOmissionUnsupported:     {"analysis_removed_file", "analysis_unsupported_content", "analysis_empty_added_file", "semantic_unsupported_language"},
		ContextOmissionAnalysisFailure: {"semantic_parse_failure", "semantic_source_unavailable"},
		ContextOmissionDuplicate:       {"semantic_duplicate_source"},
	}
	for want, reasons := range tests {
		for _, reason := range reasons {
			if got, err := contextSourceOmissionCategory(reason); err != nil || got != want {
				t.Fatalf("reason=%s category=%s want=%s err=%v", reason, got.String(), want.String(), err)
			}
		}
	}
	summaries, err := summarizeContextSourceOmissions(nil, 3)
	if err != nil || len(summaries) != 1 || summaries[0].Reason() != ContextOmissionSelectionLimit || summaries[0].Count() != 3 {
		t.Fatalf("selection summaries=%#v err=%v", summaries, err)
	}
	if _, err := contextSourceOmissionCategory("unknown"); err == nil {
		t.Fatal("unknown omission reason accepted")
	}
}
