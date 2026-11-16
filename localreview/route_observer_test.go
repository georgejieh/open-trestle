package localreview

import (
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func observerUsage(t *testing.T, input, output, cached uint64) provider.RouteTokenUsage {
	t.Helper()
	usage, err := provider.NewRouteTokenUsage(input, output, cached)
	if err != nil {
		t.Fatal(err)
	}
	return usage
}

func observerSuccess(t *testing.T, usage provider.RouteTokenUsage) gateway.RouteDispatchResult {
	t.Helper()
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	if err != nil {
		t.Fatal(err)
	}
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func observerFailure(t *testing.T, usage provider.RouteTokenUsage) gateway.RouteDispatchResult {
	t.Helper()
	result, err := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureOutputExhausted, gateway.RouteReplayNoSideEffect, usage, 0)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func observerPricing(t *testing.T) provider.RoutePricing {
	t.Helper()
	// One micro-USD per input token and two per output token.
	pricing, err := provider.NewRoutePricing(1_000_000, 2_000_000)
	if err != nil {
		t.Fatal(err)
	}
	return pricing
}

func TestRouteObserverRecordsReportedUsageAndItsCostOfEachDispatch(t *testing.T) {
	observer := &routeFailureObserver{}
	pricing := observerPricing(t)
	observer.record("succeeded", provider.CapabilityReviewV1, pricing, observerSuccess(t, observerUsage(t, 120, 30, 20)))
	observer.record("failed", provider.CapabilityReviewV1, pricing, observerFailure(t, observerUsage(t, 90, 4096, 0)))
	observer.record("unreported", provider.CapabilityReviewV1, pricing, observerFailure(t, provider.NewUnknownRouteTokenUsage()))
	observer.record("unpriced", provider.CapabilityReviewV1, provider.RoutePricing{}, observerSuccess(t, observerUsage(t, 120, 30, 20)))
	observer.record("invalid", provider.CapabilityReviewV1, pricing, gateway.RouteDispatchResult{})
	observer.record("repeated", provider.CapabilityReviewV1, pricing, observerSuccess(t, observerUsage(t, 1, 1, 0)))
	observer.record("repeated", provider.CapabilityReviewV1, pricing, observerSuccess(t, observerUsage(t, 1, 1, 0)))
	for _, test := range []struct {
		authorization         string
		observed, known       bool
		input, output, cached uint32
		costKnown             bool
		cost                  uint64
	}{
		{"succeeded", true, true, 120, 30, 20, true, 120 + 60},
		{"failed", true, true, 90, 4096, 0, true, 90 + 8192},
		{"unreported", true, false, 0, 0, 0, false, 0},
		{"unpriced", true, true, 120, 30, 20, false, 0},
		{"invalid", true, false, 0, 0, 0, false, 0},
		{"repeated", true, false, 0, 0, 0, false, 0},
		{"never-dispatched", false, false, 0, 0, 0, false, 0},
	} {
		attempt, observed := observer.dispatchedAttempt(test.authorization)
		usage := attempt.usage
		if observed != test.observed || usage.IsKnown() != test.known || usage.InputTokens() != test.input || usage.OutputTokens() != test.output || usage.CachedInputTokens() != test.cached {
			t.Errorf("%s: observed=%t known=%t usage=%d/%d/%d", test.authorization, observed, usage.IsKnown(), usage.InputTokens(), usage.OutputTokens(), usage.CachedInputTokens())
		}
		if attempt.cost.IsKnown() != test.costKnown || attempt.cost.TotalCostMicroUSD() != test.cost {
			t.Errorf("%s: cost known=%t %d, want known=%t %d", test.authorization, attempt.cost.IsKnown(), attempt.cost.TotalCostMicroUSD(), test.costKnown, test.cost)
		}
	}
	if !observer.saw(gateway.RouteFailureOutputExhausted) {
		t.Fatal("failure class no longer observed")
	}
	observer.reset()
	if _, observed := observer.dispatchedAttempt("succeeded"); observed || observer.saw(gateway.RouteFailureOutputExhausted) {
		t.Fatal("reset kept an earlier run's observations")
	}
}

func TestRouteObserverBoundsItsUsageRecords(t *testing.T) {
	observer := &routeFailureObserver{}
	for index := range maxObservedRouteUsages + 1 {
		observer.record(fmt.Sprintf("attempt-%d", index), provider.CapabilityReviewV1, observerPricing(t), observerSuccess(t, observerUsage(t, 1, 1, 0)))
	}
	if _, observed := observer.dispatchedAttempt(fmt.Sprintf("attempt-%d", maxObservedRouteUsages-1)); !observed {
		t.Fatal("observer dropped a record within its bound")
	}
	if _, observed := observer.dispatchedAttempt(fmt.Sprintf("attempt-%d", maxObservedRouteUsages)); observed {
		t.Fatal("observer kept a record beyond its bound")
	}
}
