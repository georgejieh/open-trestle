package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newRouteCandidate(t *testing.T, zone provider.ProviderZone, logging provider.ContentLoggingMode, contextTokens, outputTokens uint64, features ...provider.ModelFeature) provider.RouteCandidateDeclaration {
	t.Helper()
	capability := newRouteCompatibilityDeclaration(t, zone, contextTokens, outputTokens, features...)
	candidate, err := provider.NewRouteCandidateDeclaration(capability, logging, provider.NewUnknownRoutePricing(), provider.RouteQualityTier1)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestCheckRouteCandidateCompatibilityAcceptsPolicyAndCapabilitySuperset(t *testing.T) {
	input := newContentLoggingInput(t, false)
	candidate := newRouteCandidate(t, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, 256_000, 32_000, provider.ModelFeatureStructuredOutput, provider.ModelFeatureVision)

	if err := CheckRouteCandidateCompatibility(input, candidate); err != nil {
		t.Fatalf("CheckRouteCandidateCompatibility() = %v", err)
	}
}

func TestCheckRouteCandidateCompatibilityUsesPolicyFirstOrder(t *testing.T) {
	input := newContentLoggingInput(t, false)
	for _, test := range []struct {
		name    string
		zone    provider.ProviderZone
		logging provider.ContentLoggingMode
		want    error
	}{
		{name: "zone before logging and capabilities", zone: provider.ProviderZoneBrokeredRemote, logging: provider.ContentLoggingEnabled, want: ErrRouteZoneNotAllowed},
		{name: "logging before capabilities", zone: provider.ProviderZoneLocal, logging: provider.ContentLoggingEnabled, want: ErrRouteContentLoggingNotAllowed},
		{name: "capabilities", zone: provider.ProviderZoneLocal, logging: provider.ContentLoggingDisabled, want: provider.ErrMissingModelFeature},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := newRouteCandidate(t, test.zone, test.logging, 1, 1)
			if err := CheckRouteCandidateCompatibility(input, candidate); err != test.want {
				t.Fatalf("CheckRouteCandidateCompatibility() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCheckRouteCandidateCompatibilityValidatesInputBeforeCandidate(t *testing.T) {
	validInput := newContentLoggingInput(t, false)
	validCandidate := newRouteCandidate(t, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	for _, test := range []struct {
		name      string
		input     ReviewRoutingInput
		candidate provider.RouteCandidateDeclaration
		want      error
	}{
		{name: "input", candidate: validCandidate, want: ErrInvalidRequestIdentity},
		{name: "candidate", input: validInput, want: provider.ErrInvalidProviderZone},
		{name: "input first", want: ErrInvalidRequestIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckRouteCandidateCompatibility(test.input, test.candidate); !errors.Is(err, test.want) {
				t.Fatalf("CheckRouteCandidateCompatibility() = %v, want %v", err, test.want)
			}
		})
	}
}
