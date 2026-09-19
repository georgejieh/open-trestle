package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func failedInitialAttempt(t *testing.T, failure RouteFailureClass, usage provider.RouteTokenUsage) (provider.Request, fallbackFixture, RouteAttemptAuthorization, RouteAttemptOutcome, RouteCostReconciliation) {
	t.Helper()
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := NewFailedRouteAttemptOutcome(authorization, failure, RouteReplayNoSideEffect, usage, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	return request, fixture, authorization, outcome, reconciliation
}

func TestEvaluateRouteAttemptRetryBindsConcreteFailure(t *testing.T) {
	usage, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, _, authorization, outcome, _ := failedInitialAttempt(t, RouteFailureTimeout, usage)
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 1_000, 2_000)
	decision, err := EvaluateRouteAttemptRetry(policy, authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Identity() == "" || !decision.ShouldRetry() || decision.Reason() != RouteRetryTransientFailure || decision.AuthorizationIdentity() != authorization.Identity() || decision.OutcomeIdentity() != outcome.Identity() || decision.RetryPolicyIdentity() != policy.Identity() || decision.RequestIdentity() != authorization.RequestIdentity() || decision.RouteRecordIdentity() != authorization.RouteRecordIdentity() || decision.RouteAttemptOrdinal() != 1 || decision.Failure() != RouteFailureTimeout || decision.ReplaySafety() != RouteReplayNoSideEffect || decision.MinimumDelayMilliseconds() != 90 || decision.MaximumDelayMilliseconds() != 110 || decision.Validate() != nil {
		t.Fatalf("bound retry decision did not round trip: %#v", decision)
	}
}

func TestNewRouteRetryAttemptAuthorizationUsesSettledBalance(t *testing.T) {
	usage, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, _, initial, outcome, reconciliation := failedInitialAttempt(t, RouteFailureTimeout, usage)
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 2_000)
	decision, _ := EvaluateRouteAttemptRetry(policy, initial, outcome)
	retry, err := NewRouteRetryAttemptAuthorization(initial, outcome, reconciliation, decision)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Kind() != RouteAttemptRetry || retry.RouteRecordIdentity() != initial.RouteRecordIdentity() || retry.RouteReference() != initial.RouteReference() || retry.AttemptOrdinal() != 2 || retry.RouteAttemptOrdinal() != 2 || retry.PreviousOutcomeIdentity() != outcome.Identity() || retry.ContinuationDecisionIdentity() != decision.Identity() || retry.RemainingCostBeforeMicroUSD() != 20_000 || retry.ReservedCostMicroUSD() != 16_001 || retry.RemainingCostAfterMicroUSD() != 3_999 || retry.Validate() != nil {
		t.Fatalf("retry authorization did not round trip: %#v", retry)
	}
}

func TestRouteRetryContinuationFailsClosed(t *testing.T) {
	knownZero, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, _, initial, timeout, reconciliation := failedInitialAttempt(t, RouteFailureTimeout, knownZero)
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 2_000)
	allowed, _ := EvaluateRouteAttemptRetry(policy, initial, timeout)
	invalidResponse, _ := NewFailedRouteAttemptOutcome(initial, RouteFailureInvalidResponse, RouteReplayNoSideEffect, knownZero, 0, 1)
	denied, err := EvaluateRouteAttemptRetry(policy, initial, invalidResponse)
	if err != nil || denied.ShouldRetry() || denied.Reason() != RouteRetryPermanentFailure {
		t.Fatalf("permanent retry decision = (%#v, %v)", denied, err)
	}
	invalidReconciliation, _ := ReconcileAuthorizedRouteAttemptCost(initial, invalidResponse)
	if authorization, err := NewRouteRetryAttemptAuthorization(initial, invalidResponse, invalidReconciliation, denied); !errors.Is(err, ErrRouteAttemptContinuationDenied) || authorization.Identity() != "" {
		t.Fatalf("denied retry authorization = (%#v, %v)", authorization, err)
	}
	success, _ := NewSuccessfulRouteAttemptOutcome(initial, strings.Repeat("e", 64), knownZero, 1)
	if decision, err := EvaluateRouteAttemptRetry(policy, initial, success); !errors.Is(err, ErrRouteAttemptNotFailed) || decision.Identity() != "" {
		t.Fatalf("successful retry planning = (%#v, %v)", decision, err)
	}
	unknown := provider.NewUnknownRouteTokenUsage()
	_, _, unknownInitial, unknownOutcome, unknownReconciliation := failedInitialAttempt(t, RouteFailureTimeout, unknown)
	unknownDecision, _ := EvaluateRouteAttemptRetry(policy, unknownInitial, unknownOutcome)
	if authorization, err := NewRouteRetryAttemptAuthorization(unknownInitial, unknownOutcome, unknownReconciliation, unknownDecision); !errors.Is(err, ErrRouteAttemptInsufficientBudget) || authorization.Identity() != "" {
		t.Fatalf("unaffordable retry = (%#v, %v)", authorization, err)
	}
	overUsage, _ := provider.NewRouteTokenUsage(20_001, 0, 0)
	overOutcome, _ := NewFailedRouteAttemptOutcome(initial, RouteFailureTimeout, RouteReplayNoSideEffect, overUsage, 0, 1)
	overReconciliation, _ := ReconcileAuthorizedRouteAttemptCost(initial, overOutcome)
	overDecision, _ := EvaluateRouteAttemptRetry(policy, initial, overOutcome)
	if authorization, err := NewRouteRetryAttemptAuthorization(initial, overOutcome, overReconciliation, overDecision); !errors.Is(err, ErrRouteAttemptInsufficientBudget) || authorization.Identity() != "" {
		t.Fatalf("over-budget retry = (%#v, %v)", authorization, err)
	}
	forgedReconciliation := reconciliation
	forgedReconciliation.attemptAuthorizationIdentity = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	forgedReconciliation.identity = deriveRouteCostReconciliationIdentity(forgedReconciliation)
	if authorization, err := NewRouteRetryAttemptAuthorization(initial, timeout, forgedReconciliation, allowed); !errors.Is(err, ErrRouteAttemptCostReconciliationMismatch) || authorization.Identity() != "" {
		t.Fatalf("cross-wired retry = (%#v, %v)", authorization, err)
	}
}

func TestPlanAndAuthorizeRouteAttemptFallback(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 141_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	next := newFallbackRoute(t, 141_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, next, primary)
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewFailedRouteAttemptOutcome(initial, RouteFailureConnection, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 5)
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(initial, outcome)
	policy, _ := NewRouteFallbackPolicy(2, nil)
	decision, err := PlanRouteAttemptFallback(fixture.selection, fixture.ranking, policy, initial, outcome, reconciliation, []string{initial.RouteRecordIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Identity() == "" || !decision.ShouldFallback() || decision.AuthorizationIdentity() != initial.Identity() || decision.OutcomeIdentity() != outcome.Identity() || decision.ReconciliationIdentity() != reconciliation.Identity() || decision.NextRecordIdentity() != observedRouteIdentity(next) || decision.Validate() != nil {
		t.Fatalf("bound fallback decision did not round trip: %#v", decision)
	}
	fallback, err := NewRouteFallbackAttemptAuthorization(initial, outcome, reconciliation, decision, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Kind() != RouteAttemptFallback || fallback.RouteRecordIdentity() != observedRouteIdentity(next) || fallback.AttemptOrdinal() != 2 || fallback.RouteAttemptOrdinal() != 1 || fallback.PreviousOutcomeIdentity() != outcome.Identity() || fallback.ContinuationDecisionIdentity() != decision.Identity() || fallback.RemainingCostBeforeMicroUSD() != 0 || fallback.ReservedCostMicroUSD() != 0 || fallback.Validate() != nil {
		t.Fatalf("fallback authorization did not round trip: %#v", fallback)
	}
}

func TestRouteAttemptFallbackRejectsSuccessfulAndDeniedOutcomes(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 142_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	next := newFallbackRoute(t, 142_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, next, primary)
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	success, _ := NewSuccessfulRouteAttemptOutcome(initial, strings.Repeat("e", 64), provider.NewUnknownRouteTokenUsage(), 1)
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(initial, success)
	policy, _ := NewRouteFallbackPolicy(1, nil)
	if decision, err := PlanRouteAttemptFallback(fixture.selection, fixture.ranking, policy, initial, success, reconciliation, []string{initial.RouteRecordIdentity()}); !errors.Is(err, ErrRouteAttemptNotFailed) || decision.Identity() != "" {
		t.Fatalf("successful fallback planning = (%#v, %v)", decision, err)
	}
	failed, _ := NewFailedRouteAttemptOutcome(initial, RouteFailureConnection, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 1)
	reconciliation, _ = ReconcileAuthorizedRouteAttemptCost(initial, failed)
	disabled, err := PlanRouteAttemptFallback(fixture.selection, fixture.ranking, NewNoRouteFallbackPolicy(), initial, failed, reconciliation, []string{initial.RouteRecordIdentity()})
	if err != nil || disabled.ShouldFallback() {
		t.Fatalf("disabled fallback = (%#v, %v)", disabled, err)
	}
	if authorization, err := NewRouteFallbackAttemptAuthorization(initial, failed, reconciliation, disabled, fixture.selection, fixture.ranking); !errors.Is(err, ErrRouteAttemptContinuationDenied) || authorization.Identity() != "" {
		t.Fatalf("disabled fallback authorization = (%#v, %v)", authorization, err)
	}
}
