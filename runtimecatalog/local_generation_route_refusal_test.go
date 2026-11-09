package runtimecatalog

import (
	"context"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// A bound route the request outgrows is refused with the shortfall counts, so
// a caller can record why the context task stopped.
func TestPlanLocalGenerationRouteExplainsContextShortfall(t *testing.T) {
	for _, test := range []struct {
		name    string
		shrink  int
		context uint32
	}{
		{name: "generation", shrink: 0, context: 32000},
		{name: "verification", shrink: 1, context: 32000},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, _ := readableGenerationRequest(t)
			large := largeSanitizedGenerationRequest(t, scope)
			definitions := localPairDefinitions(t)
			definitions[test.shrink].Capabilities, _ = provider.NewModelCapabilities(uint64(test.context), 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
			inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
			if err != nil {
				t.Fatal(err)
			}
			policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
			pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
			if err != nil {
				t.Fatal(err)
			}
			budget, err := review.ModelRequestBudget(large, policy.Budget())
			if err != nil {
				t.Fatal(err)
			}
			_, err = PlanLocalGenerationRoute(context.Background(), scope, large, policy, inventory, pair)
			if !errors.Is(err, ErrInvalidLocalGenerationRoutePair) || !errors.Is(err, gateway.ErrNoEligibleRoute) {
				t.Fatalf("refusal = %v", err)
			}
			shortfall, ok := gateway.RouteContextShortfallOf(err)
			want := gateway.RouteContextShortfall{EstimatedInputTokens: budget.EstimatedInputTokens(), MaxOutputTokens: budget.MaxOutputTokens(), RequiredTokens: uint64(budget.EstimatedInputTokens()) + uint64(budget.MaxOutputTokens()), DeclaredContextTokens: test.context}
			if !ok || shortfall != want {
				t.Fatalf("shortfall = %+v, %v; want %+v", shortfall, ok, want)
			}
		})
	}
}

// Malformed bindings stay a plain pair refusal, never a route refusal.
func TestPlanLocalGenerationRouteBindingRefusalIsNotRouteRefusal(t *testing.T) {
	scope, request := readableGenerationRequest(t)
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	_, err = PlanLocalGenerationRoute(context.Background(), scope, request, policy, inventory, LocalGenerationRoutePair{})
	if !errors.Is(err, ErrInvalidLocalGenerationRoutePair) || errors.Is(err, gateway.ErrNoEligibleRoute) {
		t.Fatalf("binding refusal = %v", err)
	}
}
