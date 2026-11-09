package review

import (
	"bytes"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestModelRequestSystemChannelBytesMatchesTheSentChannel(t *testing.T) {
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
	generationSystem, err := TrustedModelRequestInstructions(rawGeneration.Payload())
	if err != nil {
		t.Fatal(err)
	}
	verificationSystem, err := TrustedModelRequestInstructions(rawVerification.Payload())
	if err != nil {
		t.Fatal(err)
	}
	opaque, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"contract":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	// A tampered envelope fails closed instead of unwrapping an unbound request.
	tampered, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", bytes.Replace(envelope.Payload(), []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1))
	if err != nil {
		t.Fatal(err)
	}
	declared, err := provider.NewModelCostBudget(1, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name          string
		request       provider.Request
		system        int
		measuredBytes int
	}{
		{"raw generation", rawGeneration, len(generationSystem), len(rawGeneration.Payload())},
		{"sanitized generation", egress(rawGeneration), len(generationSystem), len(egress(rawGeneration).Payload())},
		{"raw verification", rawVerification, len(verificationSystem), len(rawVerification.Payload())},
		{"sanitized verification", egress(rawVerification), len(verificationSystem), len(rawVerification.Payload())},
		{"local verification envelope", envelope, len(verificationSystem), len(envelope.Payload())},
		{"tampered local verification envelope", tampered, 0, len(tampered.Payload())},
		{"no trusted contract", opaque, 0, len(opaque.Payload())},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ModelRequestSystemChannelBytes(tc.request); got != uint32(tc.system) {
				t.Fatalf("system channel bytes = %d, want %d", got, tc.system)
			}
			budget, err := ModelRequestBudget(tc.request, declared)
			if err != nil || uint64(budget.EstimatedInputTokens()) != uint64(tc.measuredBytes+tc.system+modelRequestFramingReserve) {
				t.Fatalf("budget = (%d, %v), want payload %d + system %d + framing", budget.EstimatedInputTokens(), err, tc.measuredBytes, tc.system)
			}
		})
	}
	if len(generationSystem) == 0 || len(verificationSystem) == 0 {
		t.Fatal("fixture lacks a non-empty system channel")
	}
}
