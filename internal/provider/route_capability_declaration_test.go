package provider

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func mustRouteCapabilityRoute(t *testing.T) RouteReference {
	t.Helper()
	route, err := NewRouteReference(ProviderZoneLocal, "provider", "adapter", "primary", "Model", "Version")
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func routeCapabilityDeclarationIsZero(declaration RouteCapabilityDeclaration) bool {
	route := declaration.RouteReference()
	if route.Zone() != 0 || route.ProviderID() != "" || route.AdapterID() != "" || route.ConnectionID() != "" || route.ModelID() != "" || route.ModelVersion() != "" {
		return false
	}
	capabilities := declaration.ModelCapabilities()
	return capabilities.MaxContextTokens() == 0 && capabilities.MaxOutputTokens() == 0 && capabilities.SupportedFeatures() == nil
}

func TestNewRouteCapabilityDeclarationBindsValues(t *testing.T) {
	route := mustRouteCapabilityRoute(t)
	capabilities, _ := NewModelCapabilities(128_000, 16_000, []ModelFeature{ModelFeatureStructuredOutput})
	declaration, err := NewRouteCapabilityDeclaration(route, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if declaration.RouteReference() != route || declaration.ModelCapabilities() != capabilities || declaration.Validate() != nil {
		t.Fatal("route capability declaration does not round trip")
	}
}

func TestNewRouteCapabilityDeclarationRejectsInvalidValuesInOrder(t *testing.T) {
	validRoute := mustRouteCapabilityRoute(t)
	validCapabilities, _ := NewModelCapabilities(1, 1, nil)
	for _, test := range []struct {
		name         string
		route        RouteReference
		capabilities ModelCapabilities
		want         error
	}{
		{name: "route", capabilities: validCapabilities, want: ErrInvalidProviderZone},
		{name: "capabilities", route: validRoute, want: ErrInvalidModelCapacity},
		{name: "route first", want: ErrInvalidProviderZone},
	} {
		declaration, err := NewRouteCapabilityDeclaration(test.route, test.capabilities)
		if !errors.Is(err, test.want) || !routeCapabilityDeclarationIsZero(declaration) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, declaration, err, test.want)
		}
	}
}

func TestRouteCapabilityDeclarationZeroValueFailsValidation(t *testing.T) {
	var declaration RouteCapabilityDeclaration
	if err := declaration.Validate(); !errors.Is(err, ErrInvalidProviderZone) {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestRouteCapabilityDeclarationCopiesPreservePublicState(t *testing.T) {
	route := mustRouteCapabilityRoute(t)
	capabilities, _ := NewModelCapabilities(100, 20, []ModelFeature{ModelFeatureVision})
	declaration, _ := NewRouteCapabilityDeclaration(route, capabilities)
	copied := declaration
	if copied.RouteReference().ModelID() != route.ModelID() || copied.RouteReference().ConnectionID() != route.ConnectionID() || copied.ModelCapabilities().MaxContextTokens() != capabilities.MaxContextTokens() || copied.ModelCapabilities().MaxOutputTokens() != capabilities.MaxOutputTokens() || !reflect.DeepEqual(copied.ModelCapabilities().SupportedFeatures(), capabilities.SupportedFeatures()) {
		t.Fatal("copied declaration changed")
	}
}

func TestRouteCapabilityDeclarationSurfaceContainsNoRegistryState(t *testing.T) {
	typeOfDeclaration := reflect.TypeOf(RouteCapabilityDeclaration{})
	want := []string{"routeReference", "modelCapabilities"}
	if typeOfDeclaration.NumField() != len(want) {
		t.Fatalf("RouteCapabilityDeclaration has %d fields, want %d", typeOfDeclaration.NumField(), len(want))
	}
	for index, name := range want {
		if field := typeOfDeclaration.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
}

func TestRouteCapabilityDeclarationFormattingRedactsLabels(t *testing.T) {
	route := mustRouteCapabilityRoute(t)
	capabilities, _ := NewModelCapabilities(100, 20, nil)
	declaration, _ := NewRouteCapabilityDeclaration(route, capabilities)
	for _, test := range []struct {
		format string
		want   string
	}{
		{format: "%s", want: "route capability declaration"},
		{format: "%v", want: "route capability declaration"},
		{format: "%+v", want: "route capability declaration"},
		{format: "%q", want: `"route capability declaration"`},
		{format: "%#v", want: "provider.RouteCapabilityDeclaration{<redacted>}"},
		{format: "%d", want: "route capability declaration"},
		{format: "%x", want: "route capability declaration"},
	} {
		for _, value := range []any{declaration, &declaration} {
			formatted := fmt.Sprintf(test.format, value)
			if formatted != test.want || strings.Contains(formatted, "primary") || strings.Contains(formatted, "Model") || strings.Contains(formatted, "Version") {
				t.Fatalf("format %q = %q, want %q", test.format, formatted, test.want)
			}
		}
	}
	formattedPointer := fmt.Sprintf("%p", &declaration)
	if !strings.HasPrefix(formattedPointer, "0x") {
		t.Fatalf("pointer format = %q, want hexadecimal address", formattedPointer)
	}
	if _, err := strconv.ParseUint(formattedPointer[2:], 16, 64); err != nil {
		t.Fatalf("pointer format = %q, want hexadecimal address: %v", formattedPointer, err)
	}
}
