package gateway

import (
	"errors"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func rankTestRoute(t *testing.T, contextTokens uint64, quality provider.RouteQualityTier, pricing provider.RoutePricing) ObservedRouteCandidate {
	t.Helper()
	return newObservedRouteWithQuality(t, 11, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, pricing, quality, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, contextTokens, 16_000, provider.ModelFeatureStructuredOutput)
}

func routePerformance(t *testing.T, route ObservedRouteCandidate, revision uint64, latency uint32) provider.RoutePerformanceObservation {
	t.Helper()
	identity := route.ResolvedRecord().RouteRegistryRecord().Identity()
	var observation provider.RoutePerformanceObservation
	var err error
	if latency == 0 {
		observation, err = provider.NewUnknownRoutePerformanceObservation(identity, revision)
	} else {
		observation, err = provider.NewKnownRoutePerformanceObservation(identity, revision, latency, 20)
	}
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

func eligibleRankingFixture(t *testing.T, routes []ObservedRouteCandidate, budget provider.ModelCostBudget) RouteEligibilityResult {
	t.Helper()
	input := newContentLoggingInput(t, false)
	result, err := FilterEligibleRoutes(input, budget, 11, routes)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.EligibleRoutes()) != len(routes) {
		t.Fatalf("eligible routes = %d, want %d", len(result.EligibleRoutes()), len(routes))
	}
	return result
}

func TestRankEligibleRoutesAppliesDocumentedPrecedence(t *testing.T) {
	free, _ := provider.NewRoutePricing(0, 0)
	expensive, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 20_000)
	pinned := rankTestRoute(t, 128_000, provider.RouteQualityTier1, expensive)
	preferred := rankTestRoute(t, 128_001, provider.RouteQualityTier1, expensive)
	quality := rankTestRoute(t, 128_002, provider.RouteQualityTier4, expensive)
	cheapFast := rankTestRoute(t, 128_003, provider.RouteQualityTier3, free)
	cheapSlow := rankTestRoute(t, 128_004, provider.RouteQualityTier3, free)
	cheapUnknown := rankTestRoute(t, 128_005, provider.RouteQualityTier3, free)
	expensiveFast := rankTestRoute(t, 128_006, provider.RouteQualityTier3, expensive)
	routes := []ObservedRouteCandidate{cheapUnknown, quality, expensiveFast, pinned, cheapSlow, preferred, cheapFast}
	eligibility := eligibleRankingFixture(t, routes, budget)
	pinReference := pinned.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	preferredReference := preferred.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	policy, _ := NewPinnedRouteRankingPolicy(pinReference, []provider.RouteReference{preferredReference})
	observations := []provider.RoutePerformanceObservation{
		routePerformance(t, cheapSlow, 5, 200),
		routePerformance(t, pinned, 5, 1_000),
		routePerformance(t, expensiveFast, 5, 50),
		routePerformance(t, cheapUnknown, 5, 0),
		routePerformance(t, preferred, 5, 900),
		routePerformance(t, quality, 5, 800),
		routePerformance(t, cheapFast, 5, 100),
	}
	result, err := RankEligibleRoutes(eligibility, policy, 5, observations)
	if err != nil {
		t.Fatal(err)
	}
	want := observedRouteIdentities([]ObservedRouteCandidate{pinned, preferred, quality, cheapFast, cheapSlow, cheapUnknown, expensiveFast})
	got := rankedRouteIdentities(result.RankedRoutes())
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ranked identities = %v, want %v", got, want)
	}
	selected, ok := result.SelectedRoute()
	if !ok || selected.Route().ResolvedRecord().RouteRegistryRecord().Identity() != want[0] || !selected.IsPinned() {
		t.Fatalf("selected route = (%#v, %v)", selected, ok)
	}
	if result.RequestIdentity() != eligibility.RequestIdentity() || result.ReviewScopeIdentity() != eligibility.ReviewScopeIdentity() || result.RoutingInputIdentity() != eligibility.RoutingInputIdentity() || result.RegistryRevision() != 11 || result.PerformanceRevision() != 5 || result.CostBudget() != budget || result.RankingPolicyIdentity() != policy.Identity() {
		t.Fatal("ranking result did not bind decision inputs")
	}
	firstPreferenceRank, preferredMatch := result.RankedRoutes()[1].PreferenceRank()
	if !preferredMatch || firstPreferenceRank != 1 || result.RankedRoutes()[2].QualityTier() != provider.RouteQualityTier4 || result.RankedRoutes()[3].MaximumCost().MaximumCostMicroUSD() != 0 || result.RankedRoutes()[5].Performance().LatencyKnown() {
		t.Fatal("ranking component scores did not round trip")
	}
}

func TestRankEligibleRoutesIsPermutationStableAndDefensive(t *testing.T) {
	free, _ := provider.NewRoutePricing(0, 0)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	first := rankTestRoute(t, 128_100, provider.RouteQualityTier2, free)
	second := rankTestRoute(t, 128_101, provider.RouteQualityTier2, free)
	eligibility := eligibleRankingFixture(t, []ObservedRouteCandidate{second, first}, budget)
	policy, _ := NewRouteRankingPolicy(nil)
	firstObservation := routePerformance(t, first, 9, 100)
	secondObservation := routePerformance(t, second, 9, 100)
	forward, err := RankEligibleRoutes(eligibility, policy, 9, []provider.RoutePerformanceObservation{firstObservation, secondObservation})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := RankEligibleRoutes(eligibility, policy, 9, []provider.RoutePerformanceObservation{secondObservation, firstObservation})
	if err != nil {
		t.Fatal(err)
	}
	forwardIDs := rankedRouteIdentities(forward.RankedRoutes())
	if !reflect.DeepEqual(forwardIDs, rankedRouteIdentities(reverse.RankedRoutes())) || forwardIDs[0] > forwardIDs[1] {
		t.Fatalf("ranking was not canonical: %v", forwardIDs)
	}
	returned := forward.RankedRoutes()
	returned[0] = RankedRoute{}
	if forward.RankedRoutes()[0].Route().ResolvedRecord().RouteRegistryRecord().Identity() == "" {
		t.Fatal("ranked route accessor exposed mutable slice")
	}
}

func TestRankEligibleRoutesRejectsInvalidPerformanceSets(t *testing.T) {
	free, _ := provider.NewRoutePricing(0, 0)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	route := rankTestRoute(t, 128_200, provider.RouteQualityTier2, free)
	extra := rankTestRoute(t, 128_201, provider.RouteQualityTier2, free)
	eligibility := eligibleRankingFixture(t, []ObservedRouteCandidate{route}, budget)
	policy, _ := NewRouteRankingPolicy(nil)
	valid := routePerformance(t, route, 4, 100)
	wrongRoute := routePerformance(t, extra, 4, 100)
	wrongRevision := routePerformance(t, route, 5, 100)
	for _, test := range []struct {
		name         string
		eligibility  RouteEligibilityResult
		policy       RouteRankingPolicy
		revision     uint64
		observations []provider.RoutePerformanceObservation
		want         error
	}{
		{name: "eligibility", policy: policy, revision: 4, observations: []provider.RoutePerformanceObservation{valid}, want: ErrInvalidRequestIdentity},
		{name: "policy", eligibility: eligibility, revision: 4, observations: []provider.RoutePerformanceObservation{valid}, want: ErrInvalidRouteRankingPolicyIdentity},
		{name: "revision", eligibility: eligibility, policy: policy, observations: []provider.RoutePerformanceObservation{valid}, want: provider.ErrInvalidRoutePerformanceRevision},
		{name: "missing", eligibility: eligibility, policy: policy, revision: 4, want: ErrRoutePerformanceSetMismatch},
		{name: "wrong route", eligibility: eligibility, policy: policy, revision: 4, observations: []provider.RoutePerformanceObservation{wrongRoute}, want: ErrRoutePerformanceSetMismatch},
		{name: "duplicate", eligibility: eligibility, policy: policy, revision: 4, observations: []provider.RoutePerformanceObservation{valid, valid}, want: ErrDuplicateRoutePerformanceObservation},
		{name: "mixed revision", eligibility: eligibility, policy: policy, revision: 4, observations: []provider.RoutePerformanceObservation{wrongRevision}, want: ErrRoutePerformanceRevisionMismatch},
		{name: "invalid observation", eligibility: eligibility, policy: policy, revision: 4, observations: []provider.RoutePerformanceObservation{{}}, want: provider.ErrInvalidRoutePerformanceIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := RankEligibleRoutes(test.eligibility, test.policy, test.revision, test.observations)
			if !errors.Is(err, test.want) || result.RankedRoutes() != nil || result.RequestIdentity() != "" {
				t.Fatalf("RankEligibleRoutes() = (%#v, %v), want %v", result, err, test.want)
			}
		})
	}
}

func TestRankEligibleRoutesFailsClosedWithoutEligiblePinOrRoute(t *testing.T) {
	input := newContentLoggingInput(t, false)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	emptyEligibility, _ := FilterEligibleRoutes(input, budget, 11, nil)
	emptyPolicy, _ := NewRouteRankingPolicy(nil)
	if result, err := RankEligibleRoutes(emptyEligibility, emptyPolicy, 1, nil); err != ErrNoEligibleRoute || result.RequestIdentity() != "" {
		t.Fatalf("empty ranking = (%#v, %v)", result, err)
	}
	route := rankTestRoute(t, 128_300, provider.RouteQualityTier1, mustKnownFreePricing(t))
	eligibility := eligibleRankingFixture(t, []ObservedRouteCandidate{route}, budget)
	missingPin := rankingRouteReference(t, "Missing")
	pinnedPolicy, _ := NewPinnedRouteRankingPolicy(missingPin, nil)
	observation := routePerformance(t, route, 1, 100)
	if result, err := RankEligibleRoutes(eligibility, pinnedPolicy, 1, []provider.RoutePerformanceObservation{observation}); err != ErrPinnedRouteNotEligible || result.RequestIdentity() != "" {
		t.Fatalf("missing pin ranking = (%#v, %v)", result, err)
	}
}

func TestFilterEligibleRoutesRejectsDuplicateRouteReferences(t *testing.T) {
	free := mustKnownFreePricing(t)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	first := rankTestRoute(t, 128_400, provider.RouteQualityTier1, free)
	second := rankTestRoute(t, 128_400, provider.RouteQualityTier2, free)
	input := newContentLoggingInput(t, false)
	if result, err := FilterEligibleRoutes(input, budget, 11, []ObservedRouteCandidate{first, second}); err != ErrDuplicateRouteReference || result.RequestIdentity() != "" {
		t.Fatalf("duplicate route reference = (%#v, %v)", result, err)
	}
}

func mustKnownFreePricing(t *testing.T) provider.RoutePricing {
	t.Helper()
	pricing, err := provider.NewRoutePricing(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return pricing
}

func rankedRouteIdentities(routes []RankedRoute) []string {
	identities := make([]string, len(routes))
	for index, route := range routes {
		identities[index] = route.Route().ResolvedRecord().RouteRegistryRecord().Identity()
	}
	return identities
}
