package gateway

import (
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// A provider that rejects the request as invalid (HTTP 400 or 422, for
// example an unknown model ID or a parameter the endpoint does not accept)
// rejects the same request every time: the gateway never retries it, even
// when the policy allows retries and the replay is safe.
func TestRequestRejectedIsNeverRetried(t *testing.T) {
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 5_000)
	for _, safety := range []RouteReplaySafety{RouteReplayNoSideEffect, RouteReplayIdempotent, RouteReplayIdempotencyKey} {
		decision, err := evaluateRouteRetry(policy, RouteFailureRequestRejected, safety, 1, 0)
		if err != nil || decision.ShouldRetry() || decision.Reason() != RouteRetryPermanentFailure || decision.Validate() != nil {
			t.Fatalf("%v retry = (%#v, %v)", safety, decision, err)
		}
	}
	if routeFailureIsTransient(RouteFailureRequestRejected) {
		t.Fatal("a rejected request counts as a transient provider failure")
	}
	if _, err := evaluateRouteRetry(policy, RouteFailureRequestRejected, RouteReplayNoSideEffect, 1, 7_000); err == nil {
		t.Fatal("a rejected request carried a Retry-After")
	}
}

// Another route builds its own request for its own model ID, endpoint and
// parameters, so a rejection of this route's request leaves another route
// eligible, as a model refusal does. The decision binds the exact class.
func TestPlanRouteFallbackLeavesAnotherRouteAfterRequestRejected(t *testing.T) {
	free := mustKnownFreePricing(t)
	primary := newFallbackRoute(t, 136_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	fallback := newFallbackRoute(t, 136_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
	fixture := newFallbackFixture(t, 0, fallback, primary)
	fallbackPolicy, _ := NewRouteFallbackPolicy(1, nil)
	decision, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureRequestRejected, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil || !decision.ShouldFallback() || decision.Reason() != RouteFallbackSelected || decision.Failure() != RouteFailureRequestRejected || decision.NextRecordIdentity() != observedRouteIdentity(fallback) || decision.Validate() != nil {
		t.Fatalf("request rejected fallback = (%#v, %v)", decision, err)
	}
	invalid, err := planRouteFallback(fixture.selection, fixture.ranking, fallbackPolicy, RouteFailureInvalidResponse, RouteReplayNoSideEffect, []string{observedRouteIdentity(primary)}, 0)
	if err != nil || invalid.Identity() == decision.Identity() {
		t.Fatalf("request_rejected and invalid_response share a fallback decision identity: %v", err)
	}
	// The whole continuation, with retries allowed, skips the same-route
	// retry and falls back to the other route.
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := NewFailedRouteAttemptOutcome(authorization, RouteFailureRequestRejected, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	retryPolicy, _ := NewRouteRetryPolicy(3, 1, 10, 0, 10)
	plan, err := PlanRouteContinuation(fixture.selection, fixture.ranking, retryPolicy, fallbackPolicy, authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil || plan.RetryDecision().ShouldRetry() || plan.RetryDecision().Reason() != RouteRetryPermanentFailure || plan.Action() != RouteContinuationFallback || plan.NextAuthorization().RouteRecordIdentity() != observedRouteIdentity(fallback) || plan.Validate() != nil {
		t.Fatalf("request rejected continuation = (%#v, %v)", plan, err)
	}
	// Without a fallback route allowed, the run stops; it never retries.
	stopped, err := PlanRouteContinuation(fixture.selection, fixture.ranking, retryPolicy, NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	if err != nil || stopped.Action() != RouteContinuationStop || stopped.Reason() != RouteContinuationDenied || stopped.Validate() != nil {
		t.Fatalf("request rejected without fallback = (%#v, %v)", stopped, err)
	}
}

// The completed-attempt record, which holds failed attempts and exists only
// on this branch, reads the class back in place with the field set of every
// other failed attempt. Records of other classes keep their bytes.
func TestRequestRejectedAttemptSettlesAndReadsBack(t *testing.T) {
	_, transport := settleDispatch(t, failedDispatch(t, RouteFailureTransport, RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage()))
	transportEncoded, err := EncodeCompletedRouteAttemptRecord(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, record := settleDispatch(t, failedDispatch(t, RouteFailureRequestRejected, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage()))
	cost := record.Reconciliation()
	if record.Outcome().Status() != RouteAttemptFailed || record.Outcome().Failure() != RouteFailureRequestRejected || cost.Status() != RouteCostUsageUnknown || cost.RemainingCostMicroUSD() != cost.RemainingAfterReservationMicroUSD() {
		t.Fatalf("request rejected attempt settled %s", cost.Status())
	}
	encoded, err := EncodeCompletedRouteAttemptRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompletedRouteAttemptRecord(encoded)
	if err != nil || parsed.Identity() != record.Identity() || parsed.Outcome().Failure() != RouteFailureRequestRejected || parsed.Outcome().ReplaySafety() != RouteReplayNoSideEffect {
		t.Fatalf("request rejected attempt did not read back: %v", err)
	}
	if got, want := encodedKeys(t, encoded), encodedKeys(t, transportEncoded); !reflect.DeepEqual(got, want) {
		t.Fatalf("request rejected record fields %v differ from %v", got, want)
	}
	again, err := ParseCompletedRouteAttemptRecord(transportEncoded)
	if err != nil || again.Identity() != transport.Identity() {
		t.Fatalf("an existing failed attempt no longer reads back: %v", err)
	}
	// A route execution record, the published format that a successful
	// attempt settles into, refuses a failed outcome of this class.
	if _, err := NewRouteExecutionRecord(record.Authorization(), record.Outcome(), record.Reconciliation(), RouteOutputReceipt{}); err == nil {
		t.Fatal("a route execution record admitted a rejected request")
	}
}
