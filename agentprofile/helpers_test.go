package agentprofile

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func mustCatalog(t *testing.T) Catalog {
	t.Helper()
	catalog, err := DefaultCatalog()
	if err != nil {
		t.Fatalf("DefaultCatalog() error = %v", err)
	}
	return catalog
}

func mustRoute(t *testing.T, providerID, modelID string) provider.RouteReference {
	t.Helper()
	route, err := provider.NewRouteReference(provider.ProviderZoneLocal, providerID, "chat-completions", "local/"+providerID, modelID, "")
	if err != nil {
		t.Fatalf("NewRouteReference() error = %v", err)
	}
	return route
}

func mustFeatures(t *testing.T, spec ChangeFeaturesSpec) ChangeFeatures {
	t.Helper()
	features, err := NewChangeFeatures(spec)
	if err != nil {
		t.Fatalf("NewChangeFeatures() error = %v", err)
	}
	return features
}

func mustAssignments(t *testing.T, catalog Catalog, spec AssignmentsSpec) Assignments {
	t.Helper()
	assignments, err := NewAssignments(catalog, spec)
	if err != nil {
		t.Fatalf("NewAssignments() error = %v", err)
	}
	return assignments
}

func mustPlan(t *testing.T, catalog Catalog, assignments Assignments, features ChangeFeatures) RoutingPlan {
	t.Helper()
	plan, err := Plan(catalog, assignments, features)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan.Validate() error = %v", err)
	}
	return plan
}

func mustEntry(t *testing.T, plan RoutingPlan, id ProfileID) PlanEntry {
	t.Helper()
	entry, ok := plan.Entry(id)
	if !ok {
		t.Fatalf("plan has no entry for %s", id)
	}
	return entry
}

// fullAssignments assigns every generator and verifier tier on distinct providers.
func fullAssignments(t *testing.T, catalog Catalog) Assignments {
	t.Helper()
	return mustAssignments(t, catalog, AssignmentsSpec{
		Independence: gateway.RouteIndependenceDistinctProvider,
		Tiers: map[Tier]provider.RouteReference{
			TierLight: mustRoute(t, "ollama", "qwen3:8b"), TierStandard: mustRoute(t, "ollama", "qwen3:32b"), TierDeep: mustRoute(t, "ollama", "qwen3:235b"),
		},
		VerifierTiers: map[Tier]provider.RouteReference{
			TierLight: mustRoute(t, "llamacpp", "gemma-3-4b"), TierStandard: mustRoute(t, "llamacpp", "gemma-3-27b"), TierDeep: mustRoute(t, "llamacpp", "deepseek-r1"),
		},
	})
}
