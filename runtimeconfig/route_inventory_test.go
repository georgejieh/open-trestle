package runtimeconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func routeDefinition(t *testing.T, model string) RouteDefinition {
	t.Helper()
	route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-a", "adapter-a", "connection-a", model, "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		t.Fatal(err)
	}
	pricing, err := provider.NewRoutePricing(1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	return RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"benchmark":"operator-approved"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
}

func TestRouteInventoryResolvesEvidenceAndDynamicObservations(t *testing.T) {
	first := routeDefinition(t, "model-a")
	second := routeDefinition(t, "model-b")
	second.P95LatencyMilliseconds = 0
	second.LatencySampleCount = 0
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{second, first})
	if err != nil || inventory.Validate() != nil || len(inventory.Candidates()) != 2 || len(inventory.PerformanceObservations()) != 2 {
		t.Fatalf("inventory=(%#v,%v)", inventory, err)
	}
	if inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity() > inventory.Candidates()[1].ResolvedRecord().RouteRegistryRecord().Identity() {
		t.Fatal("inventory was not canonicalized")
	}
	if inventory.PerformanceObservations()[0].RecordIdentity() != inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity() {
		t.Fatal("performance observation lost exact record binding")
	}
}

func TestRouteInventoryRejectsMalformedOrAmbiguousInputs(t *testing.T) {
	valid := routeDefinition(t, "model-a")
	duplicate := valid
	oversized := valid
	oversized.EvidenceManifest = make([]byte, (1<<20)+1)
	emptyEvidence := valid
	emptyEvidence.EvidenceManifest = nil
	mixedPerformance := valid
	mixedPerformance.P95LatencyMilliseconds = 0
	mixedRevision := routeDefinition(t, "model-b")
	mixedRevision.RegistryRevision++
	tests := []struct {
		name        string
		ctx         context.Context
		definitions []RouteDefinition
	}{
		{"nil context", nil, []RouteDefinition{valid}},
		{"empty", context.Background(), nil},
		{"duplicate", context.Background(), []RouteDefinition{valid, duplicate}},
		{"empty evidence", context.Background(), []RouteDefinition{emptyEvidence}},
		{"oversized evidence", context.Background(), []RouteDefinition{oversized}},
		{"mixed performance representation", context.Background(), []RouteDefinition{mixedPerformance}},
		{"mixed registry revision", context.Background(), []RouteDefinition{valid, mixedRevision}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inventory, err := NewRouteInventory(test.ctx, test.definitions)
			if !errors.Is(err, ErrInvalidRouteInventory) || inventory.Identity() != "" {
				t.Fatalf("inventory=(%#v,%v)", inventory, err)
			}
		})
	}
}
