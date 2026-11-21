package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// rateLimitedAttempt settles a rate-limited, no-side-effect attempt under
// authorization with the known zero usage the adapter records for an HTTP 429.
func rateLimitedAttempt(t *testing.T, authorization RouteAttemptAuthorization, retryAfter uint32) (RouteAttemptOutcome, RouteCostReconciliation) {
	t.Helper()
	zero, _ := provider.NewRouteTokenUsage(0, 0, 0)
	return settledRateLimit(t, authorization, retryAfter, zero)
}

func settledRateLimit(t *testing.T, authorization RouteAttemptAuthorization, retryAfter uint32, usage provider.RouteTokenUsage) (RouteAttemptOutcome, RouteCostReconciliation) {
	t.Helper()
	outcome, err := NewFailedRouteAttemptOutcome(authorization, RouteFailureRateLimited, RouteReplayNoSideEffect, usage, retryAfter, 10)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	return outcome, reconciliation
}

// A rate-limited attempt is retried at most twice on the same route, each
// retry holding the same reservation from the same balance: the refused
// attempt consumed nothing, so its known zero usage released its reservation.
func TestRateLimitedRetryTakesOverTheRefusedReservation(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewRateLimitRetryPolicy(1_000)
	if err != nil {
		t.Fatal(err)
	}
	current := initial
	for retry := 1; retry <= MaxRateLimitRetries; retry++ {
		outcome, reconciliation := rateLimitedAttempt(t, current, 7_000)
		if reconciliation.Status() != RouteCostWithinReservation || reconciliation.RemainingCostMicroUSD() != initial.RemainingCostBeforeMicroUSD() {
			t.Fatalf("refusal settled %s with %d remaining", reconciliation.Status(), reconciliation.RemainingCostMicroUSD())
		}
		decision := mustRetryDecision(t, policy, current, outcome)
		if !decision.ShouldRetry() || decision.MinimumDelayMilliseconds() != 7_000 || decision.MaximumDelayMilliseconds() != 7_000 {
			t.Fatalf("retry %d decision retry=%t delay=%d..%d", retry, decision.ShouldRetry(), decision.MinimumDelayMilliseconds(), decision.MaximumDelayMilliseconds())
		}
		next, err := NewRateLimitedRetryAttemptAuthorization(current, outcome, reconciliation, decision)
		if err != nil {
			t.Fatalf("retry %d: %v", retry, err)
		}
		if next.Kind() != RouteAttemptRetry || next.RouteRecordIdentity() != initial.RouteRecordIdentity() || next.RequestIdentity() != initial.RequestIdentity() || next.AttemptOrdinal() != uint8(retry+1) || next.RouteAttemptOrdinal() != uint8(retry+1) || next.PreviousOutcomeIdentity() != outcome.Identity() || next.ContinuationDecisionIdentity() != decision.Identity() || next.ReservedCostMicroUSD() != initial.ReservedCostMicroUSD() || next.RemainingCostBeforeMicroUSD() != initial.RemainingCostBeforeMicroUSD() || next.RemainingCostAfterMicroUSD() != initial.RemainingCostAfterMicroUSD() || next.Validate() != nil {
			t.Fatalf("retry %d authorization did not take over the reservation: %#v", retry, next)
		}
		current = next
	}
	outcome, reconciliation := rateLimitedAttempt(t, current, 7_000)
	exhausted := mustRetryDecision(t, policy, current, outcome)
	if exhausted.ShouldRetry() || exhausted.Reason() != RouteRetryAttemptsExhausted {
		t.Fatalf("a third retry was allowed: %s", exhausted.Reason())
	}
	if _, err := NewRateLimitedRetryAttemptAuthorization(current, outcome, reconciliation, exhausted); !errors.Is(err, ErrRouteAttemptContinuationDenied) {
		t.Fatalf("exhausted retry err=%v", err)
	}
}

// Without Retry-After the retry waits the task's fixed delay, a shorter one is
// raised to it, and one beyond the gateway's bound is not retried at all.
func TestRateLimitRetryPolicyDelays(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	policy, err := NewRateLimitRetryPolicy(1_000)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		retryAfter uint32
		retry      bool
		delay      uint32
	}{
		{0, true, 1_000},
		{500, true, 1_000},
		{7_000, true, 7_000},
		{maxRouteRetryAfterMilliseconds, true, maxRouteRetryAfterMilliseconds},
		{maxRouteRetryAfterMilliseconds + 1, false, 0},
	} {
		outcome, _ := rateLimitedAttempt(t, initial, test.retryAfter)
		decision := mustRetryDecision(t, policy, initial, outcome)
		if decision.ShouldRetry() != test.retry || decision.MinimumDelayMilliseconds() != test.delay || decision.MaximumDelayMilliseconds() != test.delay {
			t.Fatalf("Retry-After %d: retry=%t delay=%d..%d reason=%s", test.retryAfter, decision.ShouldRetry(), decision.MinimumDelayMilliseconds(), decision.MaximumDelayMilliseconds(), decision.Reason())
		}
	}
	if fixed, err := NewRateLimitRetryPolicy(0); err != nil || fixed.BaseDelayMilliseconds() != 1 || fixed.MaxAttempts() != MaxRateLimitRetries+1 {
		t.Fatalf("zero fixed delay policy = %v, %v", fixed, err)
	}
	if capped, err := NewRateLimitRetryPolicy(3_600_000); err != nil || capped.BaseDelayMilliseconds() != maxRouteRetryDelayMilliseconds {
		t.Fatalf("fixed delay beyond the gateway bound = %v, %v", capped, err)
	}
}

// Only a rate limit the provider refused before processing takes over a
// reservation; any other failure, a reported usage or an unsafe replay keeps
// the ordinary retry and its own reservation.
func TestRateLimitedRetryRefusesEveryOtherFailure(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	policy, _ := NewRateLimitRetryPolicy(1_000)
	spent, _ := provider.NewRouteTokenUsage(1, 1, 0)
	for name, outcome := range map[string]func() (RouteAttemptOutcome, error){
		"server error": func() (RouteAttemptOutcome, error) {
			return NewFailedRouteAttemptOutcome(initial, RouteFailureProviderServer, RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage(), 0, 10)
		},
		"transport": func() (RouteAttemptOutcome, error) {
			return NewFailedRouteAttemptOutcome(initial, RouteFailureTransport, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 10)
		},
		"rate limit with spent usage": func() (RouteAttemptOutcome, error) {
			return NewFailedRouteAttemptOutcome(initial, RouteFailureRateLimited, RouteReplayNoSideEffect, spent, 0, 10)
		},
		"rate limit never sent": func() (RouteAttemptOutcome, error) {
			return NewFailedRouteAttemptOutcome(initial, RouteFailureRateLimited, RouteReplayNotDispatched, provider.NewUnknownRouteTokenUsage(), 0, 10)
		},
	} {
		failed, err := outcome()
		if err != nil {
			t.Fatal(err)
		}
		reconciliation, err := ReconcileAuthorizedRouteAttemptCost(initial, failed)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := EvaluateRouteAttemptRetry(policy, initial, failed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewRateLimitedRetryAttemptAuthorization(initial, failed, reconciliation, decision); err == nil {
			t.Fatalf("%s took over the reservation", name)
		}
	}
	limited, reconciliation := rateLimitedAttempt(t, initial, 0)
	other, _ := rateLimitedAttempt(t, initial, 2_000)
	if _, err := NewRateLimitedRetryAttemptAuthorization(initial, limited, reconciliation, mustRetryDecision(t, policy, initial, other)); !errors.Is(err, ErrRouteAttemptContinuationMismatch) {
		t.Fatalf("a decision for another outcome err=%v", err)
	}
}

// A takeover retry chain descends from its first authorization; a retry whose
// balance moved, an ancestor or an invalid authorization does not.
func TestIsSameReservationRetryOfRecognizesOnlyTakeoverRetries(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	policy, _ := NewRateLimitRetryPolicy(1_000)
	outcome, reconciliation := rateLimitedAttempt(t, initial, 0)
	first, err := NewRateLimitedRetryAttemptAuthorization(initial, outcome, reconciliation, mustRetryDecision(t, policy, initial, outcome))
	if err != nil {
		t.Fatal(err)
	}
	outcome, reconciliation = rateLimitedAttempt(t, first, 0)
	second, err := NewRateLimitedRetryAttemptAuthorization(first, outcome, reconciliation, mustRetryDecision(t, policy, first, outcome))
	if err != nil {
		t.Fatal(err)
	}
	for name, attempt := range map[string]RouteAttemptAuthorization{"itself": initial, "first retry": first, "second retry": second} {
		if !IsSameReservationRetryOf(initial, attempt) {
			t.Fatalf("%s is not recognized", name)
		}
	}
	if IsSameReservationRetryOf(first, initial) || IsSameReservationRetryOf(initial, RouteAttemptAuthorization{}) {
		t.Fatal("an ancestor or an invalid authorization was recognized")
	}
	moved := first
	moved.remainingCostBeforeMicroUSD--
	moved.remainingCostAfterMicroUSD = moved.remainingCostBeforeMicroUSD - moved.reservedCostMicroUSD
	moved.identity = deriveRouteAttemptAuthorizationIdentity(moved)
	if err := moved.Validate(); err != nil {
		t.Fatal(err)
	}
	if IsSameReservationRetryOf(initial, moved) {
		t.Fatal("a retry whose balance moved was recognized")
	}
}

// A refusal settled with unknown usage, as an adapter that records none
// reports it, keeps its reservation held; the retry still holds the same
// amount from the same balance, so the two settle forms grant one authorization.
func TestRateLimitedRetryIsTheSameForHeldAndReleasedReservations(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	policy, _ := NewRateLimitRetryPolicy(1_000)
	held, heldCost := settledRateLimit(t, initial, 0, provider.NewUnknownRouteTokenUsage())
	if heldCost.Status() != RouteCostUsageUnknown || heldCost.RemainingCostMicroUSD() != initial.RemainingCostAfterMicroUSD() {
		t.Fatalf("unknown usage settled %s", heldCost.Status())
	}
	retry, err := NewRateLimitedRetryAttemptAuthorization(initial, held, heldCost, mustRetryDecision(t, policy, initial, held))
	if err != nil || retry.RemainingCostBeforeMicroUSD() != initial.RemainingCostBeforeMicroUSD() || retry.RemainingCostAfterMicroUSD() != initial.RemainingCostAfterMicroUSD() || !IsSameReservationRetryOf(initial, retry) {
		t.Fatalf("held reservation retry = %v", err)
	}
}

// A reader holding only the recorded identities of each refused outcome and
// retry decision derives every retry's identity in a chain, and nothing else.
func TestSameReservationRetryIdentityDerivesTheRecordedChain(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	initial, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	policy, _ := NewRateLimitRetryPolicy(1_000)
	current := initial
	for depth := 1; depth <= MaxRateLimitRetries; depth++ {
		outcome, reconciliation := rateLimitedAttempt(t, current, 0)
		decision := mustRetryDecision(t, policy, current, outcome)
		next, err := NewRateLimitedRetryAttemptAuthorization(current, outcome, reconciliation, decision)
		if err != nil {
			t.Fatal(err)
		}
		if derived, ok := SameReservationRetryIdentity(initial, depth, outcome.Identity(), decision.Identity()); !ok || derived != next.Identity() {
			t.Fatalf("depth %d derived %q, want %q", depth, derived, next.Identity())
		}
		current = next
	}
	digest := initial.Identity()
	for name, derive := range map[string]func() (string, bool){
		"depth zero": func() (string, bool) { return SameReservationRetryIdentity(initial, 0, digest, digest) },
		"too deep": func() (string, bool) {
			return SameReservationRetryIdentity(initial, MaxRateLimitRetries+1, digest, digest)
		},
		"not a digest": func() (string, bool) { return SameReservationRetryIdentity(initial, 1, "outcome", digest) },
		"no decision":  func() (string, bool) { return SameReservationRetryIdentity(initial, 1, digest, "") },
		"invalid initial": func() (string, bool) {
			return SameReservationRetryIdentity(RouteAttemptAuthorization{}, 1, digest, digest)
		},
		"retry as initial": func() (string, bool) { return SameReservationRetryIdentity(current, 1, digest, digest) },
	} {
		if derived, ok := derive(); ok || derived != "" {
			t.Fatalf("%s derived %q", name, derived)
		}
	}
}

func mustRetryDecision(t *testing.T, policy RouteRetryPolicy, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome) RouteAttemptRetryDecision {
	t.Helper()
	decision, err := EvaluateRouteAttemptRetry(policy, authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}
