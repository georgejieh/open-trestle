package gateway

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// settleDispatch dispatches result for one fresh authorization and returns the
// settled attempt, as a model handler records it.
func settleDispatch(t *testing.T, result RouteDispatchResult) (RouteAttemptAuthorization, CompletedRouteAttemptRecord) {
	t.Helper()
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := DispatchAuthorizedRoute(context.Background(), &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: result}, authorization, request)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(authorization, dispatch, 25)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewCompletedRouteAttemptRecord(authorization, outcome, cost)
	if err != nil {
		t.Fatal(err)
	}
	return authorization, record
}

func failedDispatch(t *testing.T, failure RouteFailureClass, safety RouteReplaySafety, usage provider.RouteTokenUsage) RouteDispatchResult {
	t.Helper()
	result, err := NewFailedRouteDispatchResult(failure, safety, usage, 0)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func encodedKeys(t *testing.T, encoded []byte) []string {
	t.Helper()
	var walk func(prefix string, value any, keys *[]string)
	walk = func(prefix string, value any, keys *[]string) {
		if object, ok := value.(map[string]any); ok {
			for key, item := range object {
				*keys = append(*keys, prefix+key)
				walk(prefix+key+".", item, keys)
			}
		}
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	var keys []string
	walk("", value, &keys)
	sort.Strings(keys)
	return keys
}

// TestFailedAttemptSettlesFromTheUsageItReported requires a failed attempt
// whose provider reported usage, such as an exhausted output, to settle its
// cost from that usage exactly as a successful attempt with the same usage
// does, while a failure that reported nothing keeps the whole reservation
// held. Both settlements read back from the unchanged completed-attempt
// record format.
func TestFailedAttemptSettlesFromTheUsageItReported(t *testing.T) {
	usage, err := provider.NewRouteTokenUsage(100, 20, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, succeeded := settleDispatch(t, successfulDispatchResult(t))
	authorization, exhausted := settleDispatch(t, failedDispatch(t, RouteFailureOutputExhausted, RouteReplayOutcomeUnknown, usage))
	_, unreported := settleDispatch(t, failedDispatch(t, RouteFailureOutputExhausted, RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage()))
	_, transport := settleDispatch(t, failedDispatch(t, RouteFailureTransport, RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage()))

	want, settled := succeeded.Reconciliation(), exhausted.Reconciliation()
	expected, err := provider.CalculateActualRouteCost(authorization.Pricing(), usage)
	if err != nil {
		t.Fatal(err)
	}
	if !settled.ActualCost().IsKnown() || settled.ActualCost() != expected || settled.ActualCost() != want.ActualCost() || settled.Status() != want.Status() || settled.RemainingCostMicroUSD() != want.RemainingCostMicroUSD() || settled.BudgetOverrunMicroUSD() != want.BudgetOverrunMicroUSD() {
		t.Fatalf("exhausted attempt settled %s remaining %d, want %s remaining %d", settled.Status(), settled.RemainingCostMicroUSD(), want.Status(), want.RemainingCostMicroUSD())
	}
	if exhausted.Outcome().Usage() != usage {
		t.Fatal("exhausted attempt lost its reported usage")
	}
	for name, record := range map[string]CompletedRouteAttemptRecord{"unreported": unreported, "transport": transport} {
		cost := record.Reconciliation()
		if cost.Status() != RouteCostUsageUnknown || cost.ActualCost().IsKnown() || cost.RemainingCostMicroUSD() != cost.RemainingAfterReservationMicroUSD() || record.Outcome().Usage().IsKnown() {
			t.Fatalf("%s failure settled %s remaining %d of %d held", name, cost.Status(), cost.RemainingCostMicroUSD(), cost.RemainingAfterReservationMicroUSD())
		}
	}

	var keys []string
	for name, record := range map[string]CompletedRouteAttemptRecord{"exhausted": exhausted, "unreported": unreported, "transport": transport} {
		encoded, err := EncodeCompletedRouteAttemptRecord(record)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseCompletedRouteAttemptRecord(encoded)
		if err != nil || parsed.Identity() != record.Identity() || parsed.Reconciliation() != record.Reconciliation() || parsed.Outcome().Usage() != record.Outcome().Usage() {
			t.Fatalf("%s attempt did not read back with its settlement: %v", name, err)
		}
		dispatch, err := parsed.DispatchResultIdentity()
		if err != nil || dispatch == "" {
			t.Fatalf("%s attempt lost its dispatch identity: %v", name, err)
		}
		// Reported usage changes values only: one record format carries both.
		if got := encodedKeys(t, encoded); keys == nil {
			keys = got
		} else if !reflect.DeepEqual(got, keys) {
			t.Fatalf("%s attempt record fields %v differ from %v", name, got, keys)
		}
	}
}
