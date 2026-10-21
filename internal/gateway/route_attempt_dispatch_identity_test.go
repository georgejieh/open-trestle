package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestCompletedAttemptDispatchIdentityMatchesActualDispatch(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := NewFailedRouteDispatchResult(RouteFailureRateLimited, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 17)
	if err != nil {
		t.Fatal(err)
	}
	for name, result := range map[string]RouteDispatchResult{"success": successfulDispatchResult(t), "failure": failed} {
		t.Run(name, func(t *testing.T) {
			dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: result}
			dispatch, err := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
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
			encoded, err := EncodeCompletedRouteAttemptRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseCompletedRouteAttemptRecord(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []CompletedRouteAttemptRecord{record, parsed} {
				identity, err := value.DispatchResultIdentity()
				if err != nil || identity != dispatch.Identity() {
					t.Fatalf("dispatch identity mismatch: %v", err)
				}
			}
			for _, invalid := range []CompletedRouteAttemptRecord{{}, record} {
				invalid.outcome.responseIdentity = strings.Repeat("f", 64)
				if identity, err := invalid.DispatchResultIdentity(); !errors.Is(err, ErrInvalidCompletedRouteAttemptRecord) || identity != "" {
					t.Fatalf("invalid record derived a dispatch identity: %v", err)
				}
			}
		})
	}
}
