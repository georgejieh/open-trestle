package review

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// transportRequests returns every request kind an adapter unwraps, with the
// inner payload whose pinned contract it sends, plus requests without a
// trusted contract.
func transportRequests(t *testing.T) []struct {
	name     string
	request  provider.Request
	contract []byte
} {
	t.Helper()
	generation, candidates := verificationContextFixture(t)
	verification, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	scope := generation.ReviewScopeIdentity()
	rawGeneration, err := generation.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	rawVerification, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	egress := func(raw provider.Request) provider.Request {
		t.Helper()
		sanitized, err := NewSanitizedModelRequest(scope, raw, raw)
		if err != nil {
			t.Fatal(err)
		}
		request, err := sanitized.ProviderRequest()
		if err != nil {
			t.Fatal(err)
		}
		return request
	}
	envelope, err := NewLocalVerificationRequest(rawVerification, scope)
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", bytes.Replace(envelope.Payload(), []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1))
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	f := newV4FixtureAt(t, "func Changed(x int) int { return 10 / x }\n", "zero requests enabled\n", "AGENTS.md")
	state, _ := v4ResultStateWith(t, f, "quoted tool result")
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	investigation, err := NewInvestigationGenerationContext(binding, f.expanded, f.expandedSnapshot, state)
	v4Check(t, err)
	rawInvestigation, err := investigation.ProviderRequest()
	v4Check(t, err)
	return []struct {
		name     string
		request  provider.Request
		contract []byte
	}{
		{"raw generation", rawGeneration, rawGeneration.Payload()},
		{"sanitized generation", egress(rawGeneration), rawGeneration.Payload()},
		{"raw verification", rawVerification, rawVerification.Payload()},
		{"sanitized verification", egress(rawVerification), rawVerification.Payload()},
		{"local verification envelope", envelope, rawVerification.Payload()},
		{"investigation", rawInvestigation, rawInvestigation.Payload()},
		{"tampered local verification envelope", tampered, nil},
		{"no trusted contract", opaque, nil},
	}
}

func TestModelRequestResponseFormatBytesMatchesTheSerializedSchemaFraming(t *testing.T) {
	for _, tc := range transportRequests(t) {
		t.Run(tc.name, func(t *testing.T) {
			got := ModelRequestResponseFormatBytes(tc.request)
			if tc.contract == nil {
				if got != 0 {
					t.Fatalf("response_format bytes = %d for a request without a trusted contract", got)
				}
				return
			}
			schema, err := TrustedModelRequestOutputSchema(tc.contract)
			if err != nil {
				t.Fatal(err)
			}
			// Built independently of the package wire type, in the adapter's
			// member order.
			type jsonSchema struct {
				Name   string          `json:"name"`
				Strict bool            `json:"strict"`
				Schema json.RawMessage `json:"schema"`
			}
			type format struct {
				Type       string     `json:"type"`
				JSONSchema jsonSchema `json:"json_schema"`
			}
			want, err := json.Marshal(struct {
				Format format `json:"response_format"`
			}{format{"json_schema", jsonSchema{"open_trestle_review", true, schema}}})
			if err != nil {
				t.Fatal(err)
			}
			if got != uint32(len(want)) || len(want) <= len(schema) {
				t.Fatalf("response_format bytes = %d, want %d", got, len(want))
			}
		})
	}
}

func TestModelRequestBudgetForTransportCountsTheSentWire(t *testing.T) {
	for _, tc := range transportRequests(t) {
		t.Run(tc.name, func(t *testing.T) {
			measured, system := modelRequestEstimateParts(tc.request)
			framing := uint64(ModelRequestResponseFormatBytes(tc.request))
			wire := map[ModelRequestTransport]uint64{
				ModelRequestTransportStandard:              uint64(len(measured)) + uint64(system) + 256,
				ModelRequestTransportLocalStructuredOutput: uint64(len(measured)) + uint64(system) + framing + 256,
			}
			for transport, want := range wire {
				for _, input := range []uint64{1, want, want + 1} {
					declared, err := provider.NewModelCostBudget(input, 4096, 7)
					if err != nil {
						t.Fatal(err)
					}
					budget, err := ModelRequestBudgetForTransport(tc.request, declared, transport)
					if err != nil || uint64(budget.EstimatedInputTokens()) != max(input, want) || budget.MaxOutputTokens() != 4096 || budget.MaxCostMicroUSD() != 7 {
						t.Fatalf("%s budget for declared %d = (%d, %v), want %d", transport, input, budget.EstimatedInputTokens(), err, max(input, want))
					}
				}
			}
			declared, err := provider.NewModelCostBudget(1, 4096, 7)
			if err != nil {
				t.Fatal(err)
			}
			standard, err := ModelRequestBudget(tc.request, declared)
			if err != nil {
				t.Fatal(err)
			}
			if current, err := ModelRequestBudgetForTransport(tc.request, declared, ModelRequestTransportStandard); err != nil || current != standard {
				t.Fatal("the standard transport is not ModelRequestBudget")
			}
			if _, err := ModelRequestBudgetForTransport(tc.request, declared, ModelRequestTransportLocalStructuredOutput+1); err == nil {
				t.Fatal("unknown transport accepted")
			}
		})
	}
}

func TestModelRequestTransportNames(t *testing.T) {
	for transport, name := range map[ModelRequestTransport]string{ModelRequestTransportStandard: "standard", ModelRequestTransportLocalStructuredOutput: "local_structured_output", ModelRequestTransportLocalStructuredOutput + 1: ""} {
		if transport.String() != name || (transport.Validate() == nil) != (name != "") {
			t.Fatalf("transport %d named %q", transport, transport.String())
		}
	}
}
