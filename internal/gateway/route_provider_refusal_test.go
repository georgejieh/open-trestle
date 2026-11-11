package gateway

import (
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// TestProviderRefusalAttemptsSettleAndReadBack requires each provider refusal
// class to settle like any failure that reported no usage, holding the whole
// reservation, and to read back with its exact class from the completed-attempt
// record. The record keeps the field set of every other failed attempt.
func TestProviderRefusalAttemptsSettleAndReadBack(t *testing.T) {
	_, transport := settleDispatch(t, failedDispatch(t, RouteFailureTransport, RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage()))
	transportEncoded, err := EncodeCompletedRouteAttemptRecord(transport)
	if err != nil {
		t.Fatal(err)
	}
	keys := encodedKeys(t, transportEncoded)
	dispatches := map[string]RouteFailureClass{}
	for _, failure := range []RouteFailureClass{RouteFailurePaymentRequired, RouteFailureModelUnavailable, RouteFailureModelRetired} {
		_, record := settleDispatch(t, failedDispatch(t, failure, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage()))
		cost := record.Reconciliation()
		if record.Outcome().Status() != RouteAttemptFailed || record.Outcome().Failure() != failure || cost.Status() != RouteCostUsageUnknown || cost.RemainingCostMicroUSD() != cost.RemainingAfterReservationMicroUSD() {
			t.Fatalf("%v attempt settled %s", failure, cost.Status())
		}
		encoded, err := EncodeCompletedRouteAttemptRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseCompletedRouteAttemptRecord(encoded)
		if err != nil || parsed.Identity() != record.Identity() || parsed.Outcome().Failure() != failure || parsed.Outcome().ReplaySafety() != RouteReplayNoSideEffect {
			t.Fatalf("%v attempt did not read back: %v", failure, err)
		}
		if got := encodedKeys(t, encoded); !reflect.DeepEqual(got, keys) {
			t.Fatalf("%v attempt record fields %v differ from %v", failure, got, keys)
		}
		dispatch, err := parsed.DispatchResultIdentity()
		if err != nil {
			t.Fatal(err)
		}
		if previous, repeated := dispatches[dispatch]; repeated {
			t.Fatalf("%v and %v share a dispatch identity", previous, failure)
		}
		dispatches[dispatch] = failure
	}
}
