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
