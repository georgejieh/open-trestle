package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func answeredAttempt(t *testing.T, authorization RouteAttemptAuthorization) (RouteAttemptOutcome, RouteCostReconciliation) {
	t.Helper()
	usage, _ := provider.NewRouteTokenUsage(10, 5, 0)
	outcome, err := NewSuccessfulRouteAttemptOutcome(authorization, authorization.RequestIdentity(), usage, 10)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	return outcome, reconciliation
}

// A rejected answer's retry reserves the same amount under the same terms,
// binds the rejected outcome, and reads back as a same-route retry of the
// first authorization.
func TestAnswerRetryReservesAgainAndKeepsTheChain(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, reconciliation := answeredAttempt(t, initial)
	retry, err := NewAnswerRetryAttemptAuthorization(initial, outcome, reconciliation)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Kind() != RouteAttemptRetry || retry.Identity() == initial.Identity() || retry.RequestIdentity() != initial.RequestIdentity() || retry.RouteAttemptOrdinal() != 2 || retry.PreviousOutcomeIdentity() != outcome.Identity() || retry.ReservedCostMicroUSD() != initial.ReservedCostMicroUSD() || retry.RemainingCostBeforeMicroUSD() != initial.RemainingCostBeforeMicroUSD() || !IsSameReservationRetryOf(initial, retry) {
		t.Fatalf("answer retry authorization = %#v", retry)
	}
	exhausted, _ := provider.NewRouteTokenUsage(10, 5, 0)
	failed, err := NewFailedRouteAttemptOutcome(initial, RouteFailureOutputExhausted, RouteReplayOutcomeUnknown, exhausted, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	cost, _ := ReconcileAuthorizedRouteAttemptCost(initial, failed)
	if _, err := NewAnswerRetryAttemptAuthorization(initial, failed, cost); err != nil {
		t.Fatalf("output exhausted retry: %v", err)
	}
}

// Any other failure, a settlement of another attempt, an overrun, or a chain
// with no same-route retry left is refused.
func TestAnswerRetryRefusesOtherAttempts(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	limited, limitedCost := rateLimitedAttempt(t, initial, 0)
	if _, err := NewAnswerRetryAttemptAuthorization(initial, limited, limitedCost); !errors.Is(err, ErrRouteAttemptContinuationDenied) {
		t.Fatalf("rate limit err=%v", err)
	}
	outcome, reconciliation := answeredAttempt(t, initial)
	if _, err := NewAnswerRetryAttemptAuthorization(initial, outcome, limitedCost); !errors.Is(err, ErrRouteAttemptCostReconciliationMismatch) {
		t.Fatalf("foreign settlement err=%v", err)
	}
	over, err := reconcileRouteAttemptCost(initial.Identity(), outcome.Identity(), initial.ReservedCostMicroUSD(), initial.RemainingCostAfterMicroUSD(), knownActualCost(t, initial.RemainingCostBeforeMicroUSD()+1))
	if err != nil || over.Status() != RouteCostBudgetExceeded {
		t.Fatalf("overrun fixture err=%v", err)
	}
	if _, err := NewAnswerRetryAttemptAuthorization(initial, outcome, over); !errors.Is(err, ErrRouteAttemptInsufficientBudget) {
		t.Fatalf("overrun err=%v", err)
	}
	policy, _ := NewRateLimitRetryPolicy(1_000)
	current := initial
	for range MaxRateLimitRetries {
		refused, cost := rateLimitedAttempt(t, current, 0)
		next, err := NewRateLimitedRetryAttemptAuthorization(current, refused, cost, mustRetryDecision(t, policy, current, refused))
		if err != nil {
			t.Fatal(err)
		}
		current = next
	}
	outcome, reconciliation = answeredAttempt(t, current)
	if _, err := NewAnswerRetryAttemptAuthorization(current, outcome, reconciliation); !errors.Is(err, ErrRouteAttemptContinuationDenied) {
		t.Fatalf("spent chain err=%v", err)
	}
}
