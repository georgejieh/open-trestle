package gateway

import (
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
