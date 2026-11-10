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

func TestRouteObserverRecordsReportedUsageOfEachDispatch(t *testing.T) {
	observer := &routeFailureObserver{}
	observer.record("succeeded", provider.CapabilityReviewV1, observerSuccess(t, observerUsage(t, 120, 30, 20)))
	observer.record("failed", provider.CapabilityReviewV1, observerFailure(t, observerUsage(t, 90, 4096, 0)))
	observer.record("unreported", provider.CapabilityReviewV1, observerFailure(t, provider.NewUnknownRouteTokenUsage()))
	observer.record("invalid", provider.CapabilityReviewV1, gateway.RouteDispatchResult{})
	observer.record("repeated", provider.CapabilityReviewV1, observerSuccess(t, observerUsage(t, 1, 1, 0)))
	observer.record("repeated", provider.CapabilityReviewV1, observerSuccess(t, observerUsage(t, 1, 1, 0)))
	for _, test := range []struct {
		authorization         string
		observed, known       bool
		input, output, cached uint32
	}{
		{"succeeded", true, true, 120, 30, 20},
		{"failed", true, true, 90, 4096, 0},
		{"unreported", true, false, 0, 0, 0},
		{"invalid", true, false, 0, 0, 0},
		{"repeated", true, false, 0, 0, 0},
		{"never-dispatched", false, false, 0, 0, 0},
	} {
		usage, observed := observer.dispatchedUsage(test.authorization)
		if observed != test.observed || usage.IsKnown() != test.known || usage.InputTokens() != test.input || usage.OutputTokens() != test.output || usage.CachedInputTokens() != test.cached {
			t.Errorf("%s: observed=%t known=%t usage=%d/%d/%d", test.authorization, observed, usage.IsKnown(), usage.InputTokens(), usage.OutputTokens(), usage.CachedInputTokens())
		}
	}
	if !observer.saw(gateway.RouteFailureOutputExhausted) {
		t.Fatal("failure class no longer observed")
	}
	observer.reset()
	if _, observed := observer.dispatchedUsage("succeeded"); observed || observer.saw(gateway.RouteFailureOutputExhausted) {
		t.Fatal("reset kept an earlier run's observations")
	}
}

func TestRouteObserverBoundsItsUsageRecords(t *testing.T) {
	observer := &routeFailureObserver{}
	for index := range maxObservedRouteUsages + 1 {
		observer.record(fmt.Sprintf("attempt-%d", index), provider.CapabilityReviewV1, observerSuccess(t, observerUsage(t, 1, 1, 0)))
	}
	if _, observed := observer.dispatchedUsage(fmt.Sprintf("attempt-%d", maxObservedRouteUsages-1)); !observed {
		t.Fatal("observer dropped a record within its bound")
	}
	if _, observed := observer.dispatchedUsage(fmt.Sprintf("attempt-%d", maxObservedRouteUsages)); observed {
		t.Fatal("observer kept a record beyond its bound")
	}
}
