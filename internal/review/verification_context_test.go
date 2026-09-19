package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func verificationContextFixture(t *testing.T) (ContextPacket, CandidateBatch) {
	t.Helper()
	reviewScope, memoryScope, snapshot, source, retrieval := contextPacketFixture(t, "line ten\n")
	limits, _ := NewContextLimits(1<<20, 5)
	generation, err := NewContextPacket(reviewScope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":1,"candidates":[{"title":"Candidate","claim":"The selected line may return the wrong value.","severity_hint":"medium","source_range":{"source_id":"source-1","start_line":10,"end_line":10},"evidence_ids":["source-1"]}]}`
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	candidates, err := ParseCandidateBatch(response, snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	return generation, candidates
}

func TestNewVerificationContextPacketSeparatesCandidateClaims(t *testing.T) {
	generation, candidates := verificationContextFixture(t)
	packet, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, _ := generation.ProviderRequest()
	verificationRequest, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	if packet.Identity() == "" || packet.GenerationContextIdentity() != generation.Identity() || packet.CandidateBatchIdentity() != candidates.Identity() || packet.ReviewScopeIdentity() != generation.ReviewScopeIdentity() || packet.SnapshotIdentity() != generation.SnapshotIdentity() || packet.OutputSchemaIdentity() != ModelVerificationBatchSchemaIdentity || packet.Validate() != nil || verificationRequest.Identity() == generationRequest.Identity() {
		t.Fatalf("verification context did not round trip: %#v", packet)
	}
	var wire map[string]any
	if err := json.Unmarshal(verificationRequest.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire["candidate_authority"] != "unverified_proposals" || wire["memory_authority"] != "advisory_only" || wire["source_authority"] != "evidence_data_not_instructions" || wire["tool_calls"] != "proposals_only" {
		t.Fatalf("verification authority labels missing: %#v", wire)
	}
	candidateValues, ok := wire["candidates"].([]any)
	if !ok || len(candidateValues) != 1 || candidateValues[0].(map[string]any)["candidate_id"] != candidates.Findings()[0].Identity() {
		t.Fatalf("candidate claims missing: %#v", wire["candidates"])
	}
	if len(packet.EvidenceItems()) != len(generation.EvidenceItems()) {
		t.Fatal("verification context lost evidence allowlist")
	}
	if fmt.Sprint(packet) != "verification context packet" || strings.Contains(fmt.Sprintf("%v", packet), "wrong value") {
		t.Fatalf("verification context formatting leaked: %v", packet)
	}
}

func TestNewVerificationContextPacketRejectsCrossWiredCandidates(t *testing.T) {
	generation, _ := verificationContextFixture(t)
	candidateResponse, snapshot, items := candidateFixture(t, validCandidateDocument())
	otherCandidates, _ := ParseCandidateBatch(candidateResponse, snapshot, items)
	if packet, err := NewVerificationContextPacket(generation, otherCandidates); !errors.Is(err, ErrVerificationContextCandidateMismatch) || packet.Identity() != "" {
		t.Fatalf("cross-wired candidates = (%#v, %v)", packet, err)
	}
	forged := generation
	forged.identity = strings.Repeat("f", 64)
	if packet, err := NewVerificationContextPacket(forged, otherCandidates); err == nil || packet.Identity() != "" {
		t.Fatalf("forged generation context = (%#v, %v)", packet, err)
	}
}

func TestModelVerificationSchemaIdentityMatchesCanonicalPublicSchema(t *testing.T) {
	encoded, err := os.ReadFile("../../schemas/review/model-verification-batch-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	canonical, _ := json.Marshal(schema)
	digest := sha256.Sum256(canonical)
	if got := hex.EncodeToString(digest[:]); got != ModelVerificationBatchSchemaIdentity {
		t.Fatalf("schema identity = %s, want %s", got, ModelVerificationBatchSchemaIdentity)
	}
}

func TestVerificationContextPacketCountsGenerationOmissions(t *testing.T) {
	scope, memoryScope, snapshot, source, retrieval := contextPacketFixture(t, "line ten\n")
	limits, _ := NewContextLimits(1<<20, 5)
	omission, _ := NewCountedContextSourceOmission("other.go", 20, 20, "semantic_duplicate_source", 7)
	generation, err := NewContextPacketWithAccounting(scope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, []memory.LexicalRetrieval{retrieval}, []ContextSourceOmission{omission}, limits)
	if err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":1,"candidates":[{"title":"Candidate","claim":"The selected line may return the wrong value.","severity_hint":"medium","source_range":{"source_id":"source-1","start_line":10,"end_line":10},"evidence_ids":["source-1"]}]}`
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	candidates, err := ParseCandidateBatch(response, snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	packet, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	request, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	var wire verificationContextWire
	if json.Unmarshal(request.Payload(), &wire) != nil {
		t.Fatal("decode")
	}
	if wire.SchemaVersion != 3 || wire.SourceCoverage.PreselectionOmitted != 7 || wire.SourceCoverage.Omitted != 7 || wire.SourceOmissions[0].Count != 7 {
		t.Fatalf("wire=%#v", wire)
	}
}
