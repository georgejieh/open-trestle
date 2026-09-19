package fake

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func fakeResponse(t *testing.T, payload string) provider.Response {
	t.Helper()
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestNewAdapterBindsExactRequestFixtures(t *testing.T) {
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"request":1}`))
	result, _ := gateway.NewSuccessfulRouteDispatchResult(fakeResponse(t, `{"response":1}`))
	fixture, err := NewFixture(request, result)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewAdapter("fake-review", []Fixture{fixture})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.AdapterID() != "fake-review" || adapter.FixtureCount() != 1 || adapter.Validate() != nil {
		t.Fatalf("adapter did not round trip: %#v", adapter)
	}
	if fmt.Sprint(adapter) != "fake provider adapter" || fmt.Sprintf("%#v", adapter) != "fake.Adapter{<redacted>}" {
		t.Fatalf("adapter formatting leaked: %v / %#v", adapter, adapter)
	}
}

func TestNewAdapterRejectsInvalidAndDuplicateFixtures(t *testing.T) {
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"request":1}`))
	result, _ := gateway.NewSuccessfulRouteDispatchResult(fakeResponse(t, `{"response":1}`))
	fixture, _ := NewFixture(request, result)
	for _, test := range []struct {
		name, adapterID string
		fixtures        []Fixture
		want            error
	}{
		{"adapter", "Bad", []Fixture{fixture}, provider.ErrInvalidAdapterID},
		{"empty", "fake", nil, ErrInvalidFixtureSet},
		{"duplicate", "fake", []Fixture{fixture, fixture}, ErrDuplicateFixtureRequest},
		{"invalid fixture", "fake", []Fixture{{}}, ErrInvalidFixture},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, err := NewAdapter(test.adapterID, test.fixtures)
			if !errors.Is(err, test.want) || adapter != nil {
				t.Fatalf("NewAdapter() = (%#v, %v), want %v", adapter, err, test.want)
			}
		})
	}
}

func TestAdapterFailsClosedForInvalidOrCanceledDispatch(t *testing.T) {
	request, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(`{"request":1}`))
	result, _ := gateway.NewSuccessfulRouteDispatchResult(fakeResponse(t, `{"response":1}`))
	fixture, _ := NewFixture(request, result)
	adapter, _ := NewAdapter("fake", []Fixture{fixture})
	invalid := adapter.DispatchRoute(context.Background(), gateway.RouteDispatchRequest{})
	if invalid.Status() != gateway.RouteDispatchFailed || invalid.Failure() != gateway.RouteFailureInvalidResponse || invalid.Validate() != nil {
		t.Fatalf("invalid dispatch = %#v", invalid)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := adapter.DispatchRoute(ctx, gateway.RouteDispatchRequest{})
	if canceled.Status() != gateway.RouteDispatchFailed || canceled.Failure() != gateway.RouteFailureCancelled || canceled.Validate() != nil {
		t.Fatalf("canceled dispatch = %#v", canceled)
	}
}

var _ gateway.RouteDispatcher = (*Adapter)(nil)
