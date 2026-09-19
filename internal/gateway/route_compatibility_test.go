package gateway

import (
	"errors"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newRouteCompatibilityDeclaration(t *testing.T, zone provider.ProviderZone, contextTokens, outputTokens uint64, features ...provider.ModelFeature) provider.RouteCapabilityDeclaration {
	t.Helper()
	route, err := provider.NewRouteReference(zone, "provider", "adapter", "connection", fmt.Sprintf("Model-%d", contextTokens), "Version")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := provider.NewModelCapabilities(contextTokens, outputTokens, features)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := provider.NewRouteCapabilityDeclaration(route, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return declaration
}

func TestCheckRouteCompatibilityAcceptsAllowedCapabilitySuperset(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("payload"))
	input, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	declaration := newRouteCompatibilityDeclaration(
		t,
		provider.ProviderZoneLocal,
		256_000,
		32_000,
		provider.ModelFeatureStructuredOutput,
		provider.ModelFeatureVision,
	)

	if err := CheckRouteCompatibility(input, declaration); err != nil {
		t.Fatalf("CheckRouteCompatibility() = %v", err)
	}
}

func TestCheckRouteCompatibilityAppliesZonePolicyBeforeCapabilities(t *testing.T) {
	input := newZoneCheckInput(t, provider.ProviderZoneLocal)
	declaration := newRouteCompatibilityDeclaration(t, provider.ProviderZoneBrokeredRemote, 1, 1)

	if err := CheckRouteCompatibility(input, declaration); err != ErrRouteZoneNotAllowed {
		t.Fatalf("CheckRouteCompatibility() = %v, want %v", err, ErrRouteZoneNotAllowed)
	}
}

func TestCheckRouteCompatibilityRejectsCapabilityMismatch(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("payload"))
	input, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	for _, test := range []struct {
		name     string
		context  uint64
		output   uint64
		features []provider.ModelFeature
		want     error
	}{
		{name: "feature", context: 128_000, output: 16_000, want: provider.ErrMissingModelFeature},
		{name: "context", context: 127_999, output: 16_000, features: []provider.ModelFeature{provider.ModelFeatureStructuredOutput}, want: provider.ErrInsufficientModelContext},
		{name: "output", context: 128_000, output: 15_999, features: []provider.ModelFeature{provider.ModelFeatureStructuredOutput}, want: provider.ErrInsufficientModelOutput},
	} {
		t.Run(test.name, func(t *testing.T) {
			declaration := newRouteCompatibilityDeclaration(t, provider.ProviderZoneLocal, test.context, test.output, test.features...)
			if err := CheckRouteCompatibility(input, declaration); err != test.want {
				t.Fatalf("CheckRouteCompatibility() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCheckRouteCompatibilityValidatesInputBeforeDeclaration(t *testing.T) {
	validInput := newZoneCheckInput(t, provider.ProviderZoneLocal)
	validDeclaration := newRouteCompatibilityDeclaration(t, provider.ProviderZoneLocal, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	for _, test := range []struct {
		name        string
		input       ReviewRoutingInput
		declaration provider.RouteCapabilityDeclaration
		want        error
	}{
		{name: "input", declaration: validDeclaration, want: ErrInvalidRequestIdentity},
		{name: "declaration", input: validInput, want: provider.ErrInvalidProviderZone},
		{name: "input first", want: ErrInvalidRequestIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckRouteCompatibility(test.input, test.declaration); !errors.Is(err, test.want) {
				t.Fatalf("CheckRouteCompatibility() = %v, want %v", err, test.want)
			}
		})
	}
}
