package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func failedInitialAttempt(t *testing.T, failure RouteFailureClass, usage provider.RouteTokenUsage) (provider.Request, routeFixture, RouteAttemptAuthorization, RouteAttemptOutcome, RouteCostReconciliation) {
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

func TestEvaluateRouteAttemptRetryFailsClosed(t *testing.T) {
	knownZero, _ := provider.NewRouteTokenUsage(0, 0, 0)
	_, _, initial, _, _ := failedInitialAttempt(t, RouteFailureTimeout, knownZero)
	policy, _ := NewRouteRetryPolicy(3, 100, 1_000, 0, 2_000)
	invalidResponse, _ := NewFailedRouteAttemptOutcome(initial, RouteFailureInvalidResponse, RouteReplayNoSideEffect, knownZero, 0, 1)
	denied, err := EvaluateRouteAttemptRetry(policy, initial, invalidResponse)
	if err != nil || denied.ShouldRetry() || denied.Reason() != RouteRetryPermanentFailure {
		t.Fatalf("permanent retry decision = (%#v, %v)", denied, err)
	}
	success, _ := NewSuccessfulRouteAttemptOutcome(initial, strings.Repeat("e", 64), knownZero, 1)
	if decision, err := EvaluateRouteAttemptRetry(policy, initial, success); !errors.Is(err, ErrRouteAttemptNotFailed) || decision.Identity() != "" {
		t.Fatalf("successful retry planning = (%#v, %v)", decision, err)
	}
}
