package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const pinnedEmptyCandidateSentence = "When candidates is empty, return exactly {\"schema_version\":2,\"verdicts\":[]}; do not create a dummy candidate or verdict."

func TestVersionedVerifierClarificationFixedContract(t *testing.T) {
	generation, nonempty := verificationContextFixture(t)
	_, _, snapshot, _, _ := contextPacketFixture(t, "line ten\n")
	request, err := generation.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	generationFields := modelContractFields(t, request.Payload())
	if generationFields["instructions"] != nil || string(generationFields["instructions_identity"]) != `"`+modelInstructionsIdentity(candidateOutputInstructions)+`"` || string(generationFields["schema_version"]) != "11" {
		t.Error("generation must bind the pinned candidate instructions by identity")
	}
	response, _, _ := candidateFixture(t, `{"schema_version":1,"candidates":[]}`)
	empty, err := ParseCandidateBatch(response, snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	var baselineSchema json.RawMessage
	for _, tc := range []struct {
		name       string
		candidates CandidateBatch
	}{{"empty", empty}, {"nonempty", nonempty}} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := NewVerificationContextPacket(generation, tc.candidates)
			if err != nil {
				t.Fatal(err)
			}
			durable, err := NewVerificationRequestContext(request.Payload(), generation.Identity(), generation.ReviewScopeIdentity(), generation.MemoryScopeIdentity(), generation.MemoryIdentity(), snapshot, generation.EvidenceItems(), tc.candidates)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := packet.ProviderRequest()
			if err != nil {
				t.Fatal(err)
			}
			durableRequest, err := durable.ProviderRequest()
			if err != nil || !bytes.Equal(sent.Payload(), durable.Payload()) || sent.Identity() != durableRequest.Identity() {
				t.Fatal("packet and durable constructors disagree")
			}
			fields := modelContractFields(t, sent.Payload())
			if fields["instructions"] != nil || string(fields["instructions_identity"]) != `"`+modelInstructionsIdentity(verificationOutputInstructions)+`"` || string(fields["schema_version"]) != "11" {
				t.Error("verifier must use its contract bound by identity")
			}
			if trusted, err := TrustedModelRequestInstructions(sent.Payload()); err != nil || trusted != verificationOutputInstructions || !strings.HasPrefix(trusted, instructionHierarchy) {
				t.Error("verifier system channel is not the pinned contract")
			}
			if !strings.Contains(verificationOutputInstructions, pinnedEmptyCandidateSentence) {
				t.Error("verifier contract lost the empty-candidate clarification")
			}
			if tc.name == "empty" && string(fields["candidates"]) != "[]" {
				t.Error("empty candidates must be [] rather than null")
			}
			if baselineSchema == nil {
				baselineSchema = append(json.RawMessage(nil), fields["output_schema"]...)
			}
			if !bytes.Equal(baselineSchema, fields["output_schema"]) || string(fields["output_schema_identity"]) != `"a7f1ffc2ffc880ec3b959c24b7e4e60956a2f834b865be0fa18cabe89c175fd7"` {
				t.Error("candidate count changed the published schema")
			}
			var generated contextPacketWire
			var verified verificationContextWire
			if json.Unmarshal(request.Payload(), &generated) != nil || json.Unmarshal(sent.Payload(), &verified) != nil {
				t.Fatal("decode")
			}
			sourcesBefore, _ := json.Marshal(generated.Sources)
			sourcesAfter, _ := json.Marshal(verified.Sources)
			coverageBefore, _ := json.Marshal(generated.SourceCoverage)
			coverageAfter, _ := json.Marshal(verified.SourceCoverage)
			if !bytes.Equal(sourcesBefore, sourcesAfter) || !bytes.Equal(coverageBefore, coverageAfter) || len(durable.EvidenceItems()) != len(generation.EvidenceItems()) {
				t.Error("verifier changed evidence or coverage")
			}
		})
	}
}

func TestVersionedVerifierClarificationRejectsInventedEmptyVerdict(t *testing.T) {
	candidateResponse, snapshot, items := candidateFixture(t, `{"schema_version":1,"candidates":[]}`)
	candidates, err := ParseCandidateBatch(candidateResponse, snapshot, items)
	if err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":1,"verdicts":[{"candidate_id":"c1","outcome":"rejected","severity":"none","rationale":"No issue.","evidence_ids":[]}]}`
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	batch, err := ParseVerificationBatch(response, candidates, items)
	if !errors.Is(err, ErrVerificationCandidateNotAllowed) || batch.Identity() != "" {
		t.Fatalf("invented empty-batch verdict admitted: %v", err)
	}
}
