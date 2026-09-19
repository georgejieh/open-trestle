package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type fallbackFixture struct {
	selection RouteSelectionReceipt
	ranking   RouteRankingResult
	routes    []ObservedRouteCandidate
	budget    provider.ModelCostBudget
}

func newFallbackRoute(t *testing.T, contextTokens uint64, zone provider.ProviderZone, logging provider.ContentLoggingMode, quality provider.RouteQualityTier, pricing provider.RoutePricing) ObservedRouteCandidate {
	t.Helper()
	return newObservedRouteWithQuality(t, 21, zone, logging, provider.RouteRegistryApproved, pricing, quality, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, contextTokens, 16_000, provider.ModelFeatureStructuredOutput)
}

func newFallbackFixture(t *testing.T, maxCost uint64, routes ...ObservedRouteCandidate) fallbackFixture {
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
	return fallbackFixture{selection: selection, ranking: ranking, routes: routes, budget: budget}
}

func TestRouteFallbackReasonRoundTrips(t *testing.T) {
	values := []struct {
		value RouteFallbackReason
		token string
	}{
		{RouteFallbackSelected, "fallback_selected"},
		{RouteFallbackDisabled, "fallback_disabled"},
		{RouteFallbackLimitReached, "fallback_limit_reached"},
		{RouteFallbackNoCompatibleRoute, "no_compatible_fallback"},
		{RouteFallbackInsufficientBudget, "insufficient_remaining_budget"},
		{RouteFallbackUnsafeReplay, "unsafe_replay"},
		{RouteFallbackFailureNotEligible, "failure_not_eligible"},
	}
	for _, test := range values {
		parsed, err := ParseRouteFallbackReason(test.token)
		if err != nil || parsed != test.value || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("fallback reason %q = (%v, %v, %q)", test.token, parsed, err, parsed.String())
		}
	}
	if parsed, err := ParseRouteFallbackReason(""); !errors.Is(err, ErrInvalidRouteFallbackReason) || parsed != 0 {
		t.Fatalf("ParseRouteFallbackReason() = (%v, %v)", parsed, err)
	}
}

func TestRouteFallbackPolicyBindsDirectedTransitions(t *testing.T) {
	transition, err := NewRouteZoneTransition(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	if err != nil {
		t.Fatal(err)
	}
	fallbackPolicy, err := NewRouteFallbackPolicy(3, []RouteZoneTransition{transition})
	if err != nil {
		t.Fatal(err)
	}
	if fallbackPolicy.Identity() == "" || !fallbackPolicy.Enabled() || fallbackPolicy.MaxFallbacks() != 3 || !fallbackPolicy.AllowsZoneTransition(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote) || fallbackPolicy.AllowsZoneTransition(provider.ProviderZonePrivateRemote, provider.ProviderZoneLocal) || fallbackPolicy.Validate() != nil {
		t.Fatal("fallback policy did not round trip")
	}
	transitions := fallbackPolicy.AllowedZoneTransitions()
	transitions[0] = RouteZoneTransition{}
	if fallbackPolicy.AllowedZoneTransitions()[0] != transition {
		t.Fatal("transition accessor exposed mutable slice")
	}
	secondTransition, _ := NewRouteZoneTransition(provider.ProviderZonePrivateRemote, provider.ProviderZoneBrokeredRemote)
	ordered, _ := NewRouteFallbackPolicy(3, []RouteZoneTransition{transition, secondTransition})
	reversed, _ := NewRouteFallbackPolicy(3, []RouteZoneTransition{secondTransition, transition})
	if ordered.Identity() != reversed.Identity() || !reflect.DeepEqual(ordered.AllowedZoneTransitions(), reversed.AllowedZoneTransitions()) {
		t.Fatal("equivalent transition sets were not canonicalized")
	}
	disabled := NewNoRouteFallbackPolicy()
	if disabled.Identity() == "" || disabled.Enabled() || disabled.MaxFallbacks() != 0 || disabled.AllowedZoneTransitions() != nil || disabled.Validate() != nil || disabled.Identity() == fallbackPolicy.Identity() {
		t.Fatal("disabled fallback policy is not canonical")
	}
}

func TestRouteFallbackPolicyRejectsInvalidValues(t *testing.T) {
	valid, _ := NewRouteZoneTransition(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	for _, test := range []struct {
		name        string
		max         uint8
		transitions []RouteZoneTransition
		want        error
	}{
		{name: "max zero", want: ErrInvalidRouteFallbackLimit},
		{name: "max high", max: 5, want: ErrInvalidRouteFallbackLimit},
		{name: "invalid transition", max: 1, transitions: []RouteZoneTransition{{}}, want: provider.ErrInvalidProviderZone},
		{name: "duplicate transition", max: 1, transitions: []RouteZoneTransition{valid, valid}, want: ErrDuplicateRouteZoneTransition},
	} {
		t.Run(test.name, func(t *testing.T) {
			fallbackPolicy, err := NewRouteFallbackPolicy(test.max, test.transitions)
			if !errors.Is(err, test.want) || fallbackPolicy.Identity() != "" {
				t.Fatalf("NewRouteFallbackPolicy() = (%#v, %v), want %v", fallbackPolicy, err, test.want)
			}
		})
	}
	if transition, err := NewRouteZoneTransition(provider.ProviderZoneLocal, provider.ProviderZoneLocal); err != ErrInvalidRouteZoneTransition || transition != (RouteZoneTransition{}) {
		t.Fatalf("same-zone transition = (%#v, %v)", transition, err)
	}
	if err := (RouteFallbackPolicy{}).Validate(); !errors.Is(err, ErrInvalidRouteFallbackPolicyIdentity) {
		t.Fatalf("zero policy Validate() = %v", err)
	}
}

func TestPlanRouteFallbackSelectsSameZoneAndBindsReceipt(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 130_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 130_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, fallback, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(2, nil)
	decision, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.ShouldFallback() || decision.Reason() != RouteFallbackSelected || decision.FromRecordIdentity() != observedRouteIdentity(primary) || decision.NextRecordIdentity() != observedRouteIdentity(fallback) || decision.RemainingCostBeforeMicroUSD() != 0 || decision.ReservedCostMicroUSD() != 0 || decision.RemainingCostAfterMicroUSD() != 0 || decision.SelectionReceiptIdentity() != fixture.selection.Identity() || decision.FallbackPolicyIdentity() != fallbackPolicy.Identity() || decision.Validate() != nil {
		t.Fatalf("fallback decision did not round trip: %#v", decision)
	}
	attempted := decision.AttemptedRecordIdentities()
	attempted[0] = "changed"
	if decision.AttemptedRecordIdentities()[0] != observedRouteIdentity(primary) {
		t.Fatal("attempt accessor exposed mutable slice")
	}
}

func TestPlanRouteFallbackReservesPessimisticCumulativeCost(t *testing.T) {
	free := mustKnownFreePricing(t)
	expensive, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	primary := newFallbackRoute(t, 130_100, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 130_101, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, expensive)
	fixture := newFallbackFixture(t, 20_000, fallback, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	decision, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 20_000)
	if err != nil || !decision.ShouldFallback() || decision.ReservedCostMicroUSD() != 16_001 || decision.RemainingCostAfterMicroUSD() != 3_999 {
		t.Fatalf("cumulative reservation = (%#v, %v)", decision, err)
	}
}

func TestPlanRouteFallbackSkipsCandidatesOutsideRemainingBudget(t *testing.T) {
	free := mustKnownFreePricing(t)
	expensive, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	primary := newFallbackRoute(t, 131_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	overBudget := newFallbackRoute(t, 131_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, expensive)
	affordable := newFallbackRoute(t, 131_002, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier2, free)
	fixture := newFallbackFixture(t, 20_000, affordable, overBudget, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(2, nil)
	decision, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureProviderServer, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil || decision.NextRecordIdentity() != observedRouteIdentity(affordable) {
		t.Fatalf("budget fallback = (%#v, %v)", decision, err)
	}
	fixture = newFallbackFixture(t, 20_000, overBudget, primary)
	decision, err = planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureProviderServer, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil || decision.ShouldFallback() || decision.Reason() != RouteFallbackInsufficientBudget {
		t.Fatalf("budget denial = (%#v, %v)", decision, err)
	}
}

func TestPlanRouteFallbackRequiresDirectedZoneTransition(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 132_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	remote := newFallbackRoute(t, 132_001, provider.ProviderZonePrivateRemote, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, remote, primary)
	sameZoneOnly, _ := NewRouteFallbackPolicy(1, nil)
	decision, err := planRouteFallback(fixture.selection, fixture.ranking, sameZoneOnly, RouteFailureConnection, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil || decision.ShouldFallback() || decision.Reason() != RouteFallbackNoCompatibleRoute {
		t.Fatalf("implicit zone transition = (%#v, %v)", decision, err)
	}
	transition, _ := NewRouteZoneTransition(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	explicit, _ := NewRouteFallbackPolicy(1, []RouteZoneTransition{transition})
	decision, err = planRouteFallback(fixture.selection, fixture.ranking, explicit, RouteFailureConnection, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil || !decision.ShouldFallback() || decision.NextRecordIdentity() != observedRouteIdentity(remote) {
		t.Fatalf("explicit zone transition = (%#v, %v)", decision, err)
	}
}

func TestPlanRouteFallbackNeverWeakensContentLoggingPosture(t *testing.T) {
	free := mustKnownFreePricing(t)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	for _, test := range []struct {
		name string
		from provider.ContentLoggingMode
		to   provider.ContentLoggingMode
		want bool
	}{
		{name: "disabled to enabled", from: provider.ContentLoggingDisabled, to: provider.ContentLoggingEnabled},
		{name: "enabled to disabled", from: provider.ContentLoggingEnabled, to: provider.ContentLoggingDisabled, want: true},
		{name: "same", from: provider.ContentLoggingDisabled, to: provider.ContentLoggingDisabled, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			primary := newFallbackRoute(t, 133_000, provider.ProviderZoneLocal, test.from, provider.RouteQualityTier4, free)
			fallback := newFallbackRoute(t, 133_001, provider.ProviderZoneLocal, test.to, provider.RouteQualityTier3, free)
			fixture := newFallbackFixture(t, 0, fallback, primary)
			decision, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
			if err != nil || decision.ShouldFallback() != test.want {
				t.Fatalf("logging transition = (%#v, %v), want %v", decision, err, test.want)
			}
		})
	}
}

func TestPlanRouteFallbackBlocksUnsafeAndIneligibleFailures(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 134_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 134_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, fallback, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	for _, test := range []struct {
		name    string
		failure RouteFailureClass
		safety  RouteReplaySafety
		want    RouteFallbackReason
	}{
		{name: "unsafe", failure: RouteFailureTimeout, safety: RouteReplayUnsafe, want: RouteFallbackUnsafeReplay},
		{name: "unknown outcome", failure: RouteFailureTimeout, safety: RouteReplayOutcomeUnknown, want: RouteFallbackUnsafeReplay},
		{name: "cancelled", failure: RouteFailureCancelled, safety: RouteReplayNoSideEffect, want: RouteFallbackFailureNotEligible},
		{name: "policy", failure: RouteFailurePolicyDenied, safety: RouteReplayNoSideEffect, want: RouteFallbackFailureNotEligible},
		{name: "budget", failure: RouteFailureBudgetExhausted, safety: RouteReplayNoSideEffect, want: RouteFallbackFailureNotEligible},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, test.failure, test.safety, []string{observedRouteIdentity(primary)}, 0)
			if err != nil || decision.ShouldFallback() || decision.Reason() != test.want {
				t.Fatalf("blocked fallback = (%#v, %v), want %v", decision, err, test.want)
			}
		})
	}
}

func TestPlanRouteFallbackHandlesDisabledLimitAndExhaustion(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 135_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 135_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, fallback, primary)
	attempted := []string{observedRouteIdentity(primary)}
	decision, err := planRouteFallback(fixture.selection, fixture.ranking, NewNoRouteFallbackPolicy(), RouteFailureTimeout, RouteReplayNoSideEffect, attempted, 0)
	if err != nil || decision.Reason() != RouteFallbackDisabled {
		t.Fatalf("disabled = (%#v, %v)", decision, err)
	}
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	decision, err = planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary), observedRouteIdentity(fallback)}, 0)
	if err != nil || decision.Reason() != RouteFallbackLimitReached {
		t.Fatalf("limit = (%#v, %v)", decision, err)
	}
	fixture = newFallbackFixture(t, 0, primary)
	decision, err = planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, attempted, 0)
	if err != nil || decision.Reason() != RouteFallbackNoCompatibleRoute {
		t.Fatalf("exhausted = (%#v, %v)", decision, err)
	}
}

func TestPlanRouteFallbackRejectsInvalidBindingStateAndBudget(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 136_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 136_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 1, fallback, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(2, nil)
	other := newSelectionFixture(t, 1, 1, 100, 0, false)
	otherReceipt, _ := NewRouteSelectionReceipt(other.eligibility, other.ranking)
	for _, test := range []struct {
		name      string
		selection RouteSelectionReceipt
		ranking   RouteRankingResult
		policy    RouteFallbackPolicy
		failure   RouteFailureClass
		safety    RouteReplaySafety
		attempted []string
		remaining uint64
		want      error
	}{
		{name: "selection", ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary)}, want: ErrInvalidRequestIdentity},
		{name: "ranking", selection: fixture.selection, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary)}, want: ErrInvalidRequestIdentity},
		{name: "cross wired", selection: otherReceipt, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary)}, want: ErrRouteFallbackSelectionMismatch},
		{name: "policy", selection: fixture.selection, ranking: fixture.ranking, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary)}, want: ErrInvalidRouteFallbackPolicyIdentity},
		{name: "failure", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary)}, want: ErrInvalidRouteFailureClass},
		{name: "safety", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, attempted: []string{observedRouteIdentity(primary)}, want: ErrInvalidRouteReplaySafety},
		{name: "empty attempts", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, want: ErrInvalidRouteFallbackAttempts},
		{name: "wrong first", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(fallback)}, want: ErrInvalidRouteFallbackAttempts},
		{name: "duplicate", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary), observedRouteIdentity(primary)}, want: ErrInvalidRouteFallbackAttempts},
		{name: "unknown", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary), strings.Repeat("f", 64)}, want: ErrInvalidRouteFallbackAttempts},
		{name: "remaining", selection: fixture.selection, ranking: fixture.ranking, policy: fallbackPolicy, failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, attempted: []string{observedRouteIdentity(primary)}, remaining: 2, want: ErrInvalidRouteFallbackRemainingBudget},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := planRouteFallback(test.selection, test.ranking, test.policy, test.failure, test.safety, test.attempted, test.remaining)
			if !errors.Is(err, test.want) || decision.Identity() != "" {
				t.Fatalf("planRouteFallback() = (%#v, %v), want %v", decision, err, test.want)
			}
		})
	}
}

func TestRouteFallbackDecisionIsContentAddressedAndRedacted(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 137_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 137_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, fallback, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	decision, _ := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if decision.Identity() == "" || decision.Validate() != nil {
		t.Fatal("valid fallback decision rejected")
	}
	otherSafety, _ := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureTimeout, RouteReplayIdempotent, []string{observedRouteIdentity(primary)}, 0)
	otherFailure, _ := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureConnection, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	otherPolicy, _ := NewRouteFallbackPolicy(2, nil)
	otherPolicyDecision, _ := planRouteFallback(fixture.selection, fixture.ranking, otherPolicy, RouteFailureTimeout, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	identities := map[string]bool{decision.Identity(): true, otherSafety.Identity(): true, otherFailure.Identity(): true, otherPolicyDecision.Identity(): true}
	if len(identities) != 4 {
		t.Fatalf("fallback decision identities collided: %#v", identities)
	}
	forged := decision
	forged.identity = strings.Repeat("0", 64)
	if forged.Validate() != ErrInvalidRouteFallbackDecisionIdentity {
		t.Fatal("forged fallback identity accepted")
	}
	if reflect.TypeOf(decision).NumField() != 14 {
		t.Fatalf("fallback decision has %d fields", reflect.TypeOf(decision).NumField())
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, decision)
		if strings.Contains(formatted, observedRouteIdentity(primary)) {
			t.Fatalf("format %q exposed route identity: %q", format, formatted)
		}
	}
}
