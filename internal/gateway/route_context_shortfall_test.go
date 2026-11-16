package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestRouteEligibilityRefusalNamesAContextShortfall(t *testing.T) {
	input := newContentLoggingInput(t, false)
	free, _ := provider.NewRoutePricing(0, 0)
	route := func(context uint64, health provider.RouteHealth) ObservedRouteCandidate {
		return newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, health, provider.RouteQuotaAvailable, context, 16_000, provider.ModelFeatureStructuredOutput)
	}
	reservation, _ := provider.NewModelCostBudget(130_000, 16_000, 0)
	small, _ := provider.NewModelCostBudget(2, 16_000, 0)
	for _, tc := range []struct {
		name      string
		budget    provider.ModelCostBudget
		routes    []ObservedRouteCandidate
		eligible  bool
		shortfall uint32
	}{
		{"every route too small", reservation, []ObservedRouteCandidate{route(128_000, provider.RouteHealthHealthy), route(140_000, provider.RouteHealthHealthy)}, false, 140_000},
		{"one route fits", reservation, []ObservedRouteCandidate{route(128_000, provider.RouteHealthHealthy), route(146_000, provider.RouteHealthHealthy)}, true, 0},
		{"too small beside an unhealthy route", reservation, []ObservedRouteCandidate{route(140_000, provider.RouteHealthHealthy), route(200_000, provider.RouteHealthUnhealthy)}, false, 140_000},
		{"unhealthy only", small, []ObservedRouteCandidate{route(200_000, provider.RouteHealthUnhealthy)}, false, 0},
		// Below the policy's 128,000-token minimum but large enough for the
		// reservation: a requirement refusal, not a shortfall.
		{"policy minimum only", small, []ObservedRouteCandidate{route(120_000, provider.RouteHealthHealthy)}, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eligibility, err := FilterEligibleRoutes(input, tc.budget, 7, tc.routes)
			if err != nil {
				t.Fatal(err)
			}
			refusal := RouteEligibilityRefusal(eligibility, tc.routes)
			if tc.eligible {
				if refusal != nil {
					t.Fatalf("eligible step refused: %v", refusal)
				}
				return
			}
			if !errors.Is(refusal, ErrNoEligibleRoute) {
				t.Fatalf("refusal %v does not report no eligible route", refusal)
			}
			shortfall, ok := RouteContextShortfallOf(refusal)
			if ok != (tc.shortfall != 0) {
				t.Fatalf("shortfall reported = %t, want %t", ok, tc.shortfall != 0)
			}
			if ok && (shortfall.DeclaredContextTokens != tc.shortfall || shortfall.RequiredTokens != 146_000 || shortfall.EstimatedInputTokens != 130_000 || shortfall.MaxOutputTokens != 16_000) {
				t.Fatalf("shortfall = %+v", shortfall)
			}
		})
	}
}
