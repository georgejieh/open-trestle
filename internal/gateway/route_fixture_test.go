package gateway

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type routeFixture struct {
	selection RouteSelectionReceipt
	ranking   RouteRankingResult
	routes    []ObservedRouteCandidate
	budget    provider.ModelCostBudget
}

func newFixtureRoute(t *testing.T, contextTokens uint64, zone provider.ProviderZone, logging provider.ContentLoggingMode, quality provider.RouteQualityTier, pricing provider.RoutePricing) ObservedRouteCandidate {
	t.Helper()
	return newObservedRouteWithQuality(t, 21, zone, logging, provider.RouteRegistryApproved, pricing, quality, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, contextTokens, 16_000, provider.ModelFeatureStructuredOutput)
}

func newRouteFixture(t *testing.T, maxCost uint64, routes ...ObservedRouteCandidate) routeFixture {
	t.Helper()
	request, requirements, _ := newRoutingFixture(t, []byte("fallback payload"))
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote, provider.ProviderZoneBrokeredRemote, provider.ProviderZoneSubscriptionOAuth)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, true)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := provider.NewModelCostBudget(1, 16_000, maxCost)
	if err != nil {
		t.Fatal(err)
	}
	eligibility, err := FilterEligibleRoutes(input, budget, 21, routes)
	if err != nil {
		t.Fatal(err)
	}
	rankingPolicy, _ := NewRouteRankingPolicy(nil)
	observations := make([]provider.RoutePerformanceObservation, len(routes))
	for index, route := range routes {
		observations[index] = routePerformance(t, route, 4, uint32(100+index))
	}
	ranking, err := RankEligibleRoutes(eligibility, rankingPolicy, 4, observations)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := NewRouteSelectionReceipt(eligibility, ranking)
	if err != nil {
		t.Fatal(err)
	}
	return routeFixture{selection: selection, ranking: ranking, routes: routes, budget: budget}
}
