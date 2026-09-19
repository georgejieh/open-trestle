package provider

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func mustRouteCandidateCapability(t *testing.T) RouteCapabilityDeclaration {
	t.Helper()
	route := mustRouteCapabilityRoute(t)
	capabilities, err := NewModelCapabilities(128_000, 16_000, []ModelFeature{ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := NewRouteCapabilityDeclaration(route, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	return declaration
}

func TestNewRouteCandidateDeclarationBindsImmutableValues(t *testing.T) {
	capability := mustRouteCandidateCapability(t)
	pricing, _ := NewRoutePricing(10, 20)
	candidate, err := NewRouteCandidateDeclaration(capability, ContentLoggingDisabled, pricing, RouteQualityTier3)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.RouteCapabilityDeclaration() != capability || candidate.ContentLoggingMode() != ContentLoggingDisabled || candidate.RoutePricing() != pricing || candidate.RouteQualityTier() != RouteQualityTier3 || candidate.Validate() != nil {
		t.Fatal("route candidate declaration does not round trip")
	}
	copied := candidate
	if copied != candidate {
		t.Fatal("copied route candidate declaration changed")
	}
}

func TestNewRouteCandidateDeclarationRejectsInvalidValuesInOrder(t *testing.T) {
	validCapability := mustRouteCandidateCapability(t)
	for _, test := range []struct {
		name       string
		capability RouteCapabilityDeclaration
		logging    ContentLoggingMode
		pricing    RoutePricing
		quality    RouteQualityTier
		want       error
	}{
		{name: "capability", logging: ContentLoggingDisabled, pricing: NewUnknownRoutePricing(), quality: RouteQualityTier1, want: ErrInvalidProviderZone},
		{name: "logging", capability: validCapability, pricing: NewUnknownRoutePricing(), quality: RouteQualityTier1, want: ErrInvalidContentLoggingMode},
		{name: "pricing", capability: validCapability, logging: ContentLoggingDisabled, quality: RouteQualityTier1, want: ErrInvalidRoutePricing},
		{name: "quality", capability: validCapability, logging: ContentLoggingDisabled, pricing: NewUnknownRoutePricing(), want: ErrInvalidRouteQualityTier},
		{name: "capability first", want: ErrInvalidProviderZone},
	} {
		candidate, err := NewRouteCandidateDeclaration(test.capability, test.logging, test.pricing, test.quality)
		if !errors.Is(err, test.want) || candidate != (RouteCandidateDeclaration{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, candidate, err, test.want)
		}
	}
}

func TestRouteCandidateDeclarationZeroValueFailsValidation(t *testing.T) {
	if err := (RouteCandidateDeclaration{}).Validate(); !errors.Is(err, ErrInvalidProviderZone) {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestRouteCandidateDeclarationSurfaceIsMinimal(t *testing.T) {
	typeOfCandidate := reflect.TypeOf(RouteCandidateDeclaration{})
	want := []string{"routeCapabilityDeclaration", "contentLoggingMode", "routePricing", "routeQualityTier"}
	if typeOfCandidate.NumField() != len(want) {
		t.Fatalf("RouteCandidateDeclaration has %d fields, want %d", typeOfCandidate.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOfCandidate.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
}

func TestRouteCandidateDeclarationFormattingRedactsRouteLabels(t *testing.T) {
	candidate, _ := NewRouteCandidateDeclaration(mustRouteCandidateCapability(t), ContentLoggingDisabled, NewUnknownRoutePricing(), RouteQualityTier1)
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		for _, value := range []any{candidate, &candidate} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, "primary") || strings.Contains(formatted, "Model") || strings.Contains(formatted, "Version") {
				t.Fatalf("format %q exposed route labels: %q", format, formatted)
			}
		}
	}
}
