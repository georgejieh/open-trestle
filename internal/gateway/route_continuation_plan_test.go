package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestPlanRouteContinuationCompletesSuccessfulAttempt(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("e", 64), provider.NewUnknownRouteTokenUsage(), 1)
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, NewNoRouteRetryPolicy(), NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Identity() == "" || plan.Action() != RouteContinuationComplete || plan.Reason() != RouteContinuationSucceeded || plan.AuthorizationIdentity() != authorization.Identity() || plan.OutcomeIdentity() != outcome.Identity() || plan.ReconciliationIdentity() != reconciliation.Identity() || plan.NextAuthorization().Identity() != "" || plan.HasRetryDecision() || plan.HasFallbackDecision() || plan.Validate() != nil {
		t.Fatalf("success plan did not round trip: %#v", plan)
	}
}

func TestPlanRouteContinuationSelectsRetryFirst(t *testing.T) {
	usage, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, fixture, authorization, outcome, reconciliation := failedInitialAttempt(t, RouteFailureTimeout, usage)
	retryPolicy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 2_000)
	plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, retryPolicy, NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	next := plan.NextAuthorization()
	if plan.Action() != RouteContinuationRetry || plan.Reason() != RouteContinuationRetrySelected || !plan.HasRetryDecision() || plan.HasFallbackDecision() || next.Kind() != RouteAttemptRetry || next.RouteRecordIdentity() != authorization.RouteRecordIdentity() || next.AttemptOrdinal() != 2 || next.RouteAttemptOrdinal() != 2 || plan.Validate() != nil {
		t.Fatalf("retry plan did not round trip: %#v", plan)
	}
}

func TestPlanRouteContinuationFallsBackAfterRetryDenial(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 151_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	nextRoute := newFallbackRoute(t, 151_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, nextRoute, primary)
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewFailedRouteAttemptOutcome(authorization, RouteFailureConnection, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 1)
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, NewNoRouteRetryPolicy(), fallbackPolicy, authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	next := plan.NextAuthorization()
	if plan.Action() != RouteContinuationFallback || plan.Reason() != RouteContinuationFallbackSelected || !plan.HasRetryDecision() || !plan.HasFallbackDecision() || next.Kind() != RouteAttemptFallback || next.RouteRecordIdentity() != observedRouteIdentity(nextRoute) || next.RouteAttemptOrdinal() != 1 || plan.Validate() != nil {
		t.Fatalf("fallback plan did not round trip: %#v", plan)
	}
}

func TestPlanRouteContinuationUsesCheaperFallbackWhenRetryIsUnaffordable(t *testing.T) {
	expensive, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 152_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, expensive)
	nextRoute := newFallbackRoute(t, 152_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 20_000, nextRoute, primary)
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewFailedRouteAttemptOutcome(authorization, RouteFailureTimeout, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 1)
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	retryPolicy, _ := NewRouteRetryPolicy(3, 1, 10, 0, 10)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, retryPolicy, fallbackPolicy, authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.RetryDecision().ShouldRetry() || plan.Action() != RouteContinuationFallback || plan.NextAuthorization().RouteRecordIdentity() != observedRouteIdentity(nextRoute) || plan.NextAuthorization().ReservedCostMicroUSD() != 0 {
		t.Fatalf("unaffordable retry did not use cheaper fallback: %#v", plan)
	}
}

func TestPlanRouteContinuationStopsOnBudgetOverrunOrNoFallback(t *testing.T) {
	usage, _ := provider.NewRouteTokenUsage(20_001, 0, 0)
	_, fixture, authorization, outcome, reconciliation := failedInitialAttempt(t, RouteFailureTimeout, usage)
	retryPolicy, _ := NewRouteRetryPolicy(3, 1, 10, 0, 10)
	plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, retryPolicy, NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil || plan.Action() != RouteContinuationStop || plan.Reason() != RouteContinuationBudgetExhausted || plan.NextAuthorization().Identity() != "" || plan.Validate() != nil {
		t.Fatalf("overrun plan = (%#v, %v)", plan, err)
	}
	zero, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, fixture, authorization, outcome, reconciliation = failedInitialAttempt(t, RouteFailureInvalidResponse, zero)
	plan, err = PlanRouteContinuation(fixture.selection, fixture.ranking, NewNoRouteRetryPolicy(), NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil || plan.Action() != RouteContinuationStop || plan.Reason() != RouteContinuationDenied || !plan.HasRetryDecision() || !plan.HasFallbackDecision() || plan.Validate() != nil {
		t.Fatalf("denied plan = (%#v, %v)", plan, err)
	}
}

func TestRouteContinuationPlanRejectsCrossWiringAndTampering(t *testing.T) {
	usage, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, fixture, authorization, outcome, reconciliation := failedInitialAttempt(t, RouteFailureTimeout, usage)
	forged := reconciliation
	forged.attemptOutcomeIdentity = strings.Repeat("f", 64)
	forged.identity = deriveRouteCostReconciliationIdentity(forged)
	if plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, NewNoRouteRetryPolicy(), NewNoRouteFallbackPolicy(), authorization, outcome, forged, []string{authorization.RouteRecordIdentity()}); !errors.Is(err, ErrRouteAttemptCostReconciliationMismatch) || plan.Identity() != "" {
		t.Fatalf("cross-wired plan = (%#v, %v)", plan, err)
	}
	plan, _ := PlanRouteContinuation(fixture.selection, fixture.ranking, NewNoRouteRetryPolicy(), NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	plan.identity = strings.Repeat("0", 64)
	if !errors.Is(plan.Validate(), ErrInvalidRouteContinuationPlanIdentity) {
		t.Fatal("forged continuation identity accepted")
	}
}
