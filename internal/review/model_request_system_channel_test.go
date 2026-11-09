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

// ModelRequestBudgetVersion 1 names the input estimate that the generation and
// verification route authorizers bind as input_estimate_version. They, and the
// local generation route planner, admit only sanitized generation or
// verification egress requests, so that is the estimate their identities and
// recorded selection budgets name. The local verification envelope measurement
// added later changed no admitted request: the egress gates refuse an envelope.
// If this test fails, version 1 changed for an admitted request; version the
// estimate with readback instead of editing this test.
func TestModelRequestBudgetVersion1IsUnchangedForAdmittedRequests(t *testing.T) {
	if ModelRequestBudgetVersion != 1 {
		t.Fatal("estimate version changed; pin the new version and keep version 1 readback")
	}
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
	instructions := func(raw provider.Request) uint64 {
		t.Helper()
		text, err := TrustedModelRequestInstructions(raw.Payload())
		if err != nil || text == "" {
			t.Fatal("fixture lacks a trusted system channel")
		}
		return uint64(len(text))
	}
	sanitizedGeneration, sanitizedVerification := egress(rawGeneration), egress(rawVerification)
	if ValidateCandidateEgressRequest(sanitizedGeneration, scope) != nil || ValidateVerificationEgressRequest(sanitizedVerification, scope) != nil {
		t.Fatal("fixture is not an admitted egress request")
	}
	envelope, err := NewLocalVerificationRequest(rawVerification, scope)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateCandidateEgressRequest(envelope, scope) == nil || ValidateVerificationEgressRequest(envelope, scope) == nil {
		t.Fatal("a version 1 egress gate admits a local verification envelope")
	}
	// Version 1: the larger of the declared estimate and the measured payload
	// (the complete sanitized generation request, or the inner verification
	// request) plus the inner request's trusted system channel plus 256.
	cases := []struct {
		name     string
		request  provider.Request
		measured uint64
		system   uint64
	}{
		{"sanitized generation", sanitizedGeneration, uint64(len(sanitizedGeneration.Payload())), instructions(rawGeneration)},
		{"sanitized verification", sanitizedVerification, uint64(len(rawVerification.Payload())), instructions(rawVerification)},
	}
	for _, tc := range cases {
		measured := tc.measured + tc.system + 256
		for _, input := range []uint64{1, measured - 1, measured, measured + 1, 1 << 30} {
			declared, err := provider.NewModelCostBudget(input, 4096, 7)
			if err != nil {
				t.Fatal(err)
			}
			budget, err := ModelRequestBudget(tc.request, declared)
			if err != nil || uint64(budget.EstimatedInputTokens()) != max(input, measured) || budget.MaxOutputTokens() != 4096 || budget.MaxCostMicroUSD() != 7 {
				t.Fatalf("%s: version 1 estimate for declared %d = (%d, %v), want %d", tc.name, input, budget.EstimatedInputTokens(), err, max(input, measured))
			}
		}
	}
}
