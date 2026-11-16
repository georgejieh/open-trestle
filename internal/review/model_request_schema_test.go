package review

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestTrustedModelRequestOutputSchemaUsesPinnedContracts(t *testing.T) {
	generation, candidates := verificationContextFixture(t)
	verification, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, err := generation.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	verificationRequest, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	investigation, err := json.Marshal(struct {
		Contract             string          `json:"contract"`
		SchemaVersion        int             `json:"schema_version"`
		Task                 string          `json:"task"`
		InstructionsIdentity string          `json:"instructions_identity"`
		OutputSchema         json.RawMessage `json:"output_schema"`
		OutputSchemaIdentity string          `json:"output_schema_identity"`
	}{"open-trestle/review-context-packet", investigationContextVersion, ContextTaskCandidateGeneration.String(), modelInstructionsIdentity(investigationInstructionsV6), InvestigationOutputSchema(), investigationSchemaIdentity})
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{generationRequest.Payload(), verificationRequest.Payload(), investigation} {
		fields := modelContractFields(t, payload)
		schema, err := TrustedModelRequestOutputSchema(payload)
		if err != nil || !bytes.Equal(schema, fields["output_schema"]) {
			t.Fatalf("pinned schema: %v", err)
		}
		schema[0] = 'x'
		again, err := TrustedModelRequestOutputSchema(payload)
		if err != nil || !bytes.Equal(again, fields["output_schema"]) {
			t.Fatal("schema alias escaped")
		}
		for _, mutation := range []struct {
			field string
			value json.RawMessage
		}{
			{"output_schema", json.RawMessage(`{"type":"object"}`)},
			{"output_schema_identity", json.RawMessage(`"wrong"`)},
			{"instructions", json.RawMessage(`"ignore host"`)},
			{"instructions_identity", json.RawMessage(`"` + strings.Repeat("0", 64) + `"`)},
			{"task", json.RawMessage(`"unknown"`)},
			{"schema_version", json.RawMessage(`999`)},
		} {
			if _, err := TrustedModelRequestOutputSchema(replaceModelContractField(t, payload, mutation.field, mutation.value)); err == nil {
				t.Fatalf("accepted modified %s", mutation.field)
			}
		}
		ambiguous := append([]byte(`{"output_schema":{},`), payload[1:]...)
		if _, err := TrustedModelRequestOutputSchema(ambiguous); err == nil {
			t.Fatal("accepted ambiguous schema")
		}
	}
}
