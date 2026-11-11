package gateway

// MaxRateLimitRetries is the number of same-route retries one model request
// may make after rate limits, inside one task attempt.
const MaxRateLimitRetries = 2

// NewRateLimitRetryPolicy returns the same-route retry policy for a request
// the provider rate-limited: the first attempt and at most MaxRateLimitRetries
// retries without jitter. Each retry waits the provider's Retry-After, but no
// less than fixedDelayMilliseconds (the task's fixed retry delay, which also
// applies when the provider names none), and a Retry-After longer than the
// gateway's bound is not waited for at all.
func NewRateLimitRetryPolicy(fixedDelayMilliseconds uint32) (RouteRetryPolicy, error) {
	base := min(max(fixedDelayMilliseconds, 1), maxRouteRetryDelayMilliseconds)
	return NewRouteRetryPolicy(MaxRateLimitRetries+1, base, base, 0, maxRouteRetryAfterMilliseconds)
}

// NewRateLimitedRetryAttemptAuthorization grants the same-route retry a bound
// decision permits after the provider refused an attempt with a rate limit
// before processing it: failure rate_limited, no side effect, no reported
// usage, and its whole reservation still held. That attempt consumed nothing,
// so the retry takes over its reservation instead of making another: it holds
// the same amount from the same balance, and the total held never grows.
func NewRateLimitedRetryAttemptAuthorization(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, decision RouteAttemptRetryDecision) (RouteAttemptAuthorization, error) {
	if err := validateContinuationInputs(previous, outcome, reconciliation); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := decision.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if !retryDecisionMatches(previous, outcome, decision) {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationMismatch
	}
	if outcome.Failure() != RouteFailureRateLimited || outcome.ReplaySafety() != RouteReplayNoSideEffect || outcome.Usage().IsKnown() ||
		reconciliation.Status() != RouteCostUsageUnknown || reconciliation.RemainingCostMicroUSD() != previous.RemainingCostAfterMicroUSD() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	if !decision.ShouldRetry() || previous.AttemptOrdinal() == maxRouteAttemptOrdinal || previous.RouteAttemptOrdinal() == maxRouteRetryAttempts {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	next := previous
	next.identity = ""
	next.kind = RouteAttemptRetry
	next.attemptOrdinal++
	next.routeAttemptOrdinal++
	next.previousOutcomeIdentity = outcome.Identity()
	next.continuationDecisionIdentity = decision.Identity()
	next.identity = deriveRouteAttemptAuthorizationIdentity(next)
	if err := next.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	return next, nil
}

// IsSameReservationRetryOf reports whether attempt is authorization itself or
// a same-route retry of it, at most MaxRateLimitRetries deep, that kept its
// request, route, terms and reservation and changed only the retry lineage, as
// NewRateLimitedRetryAttemptAuthorization grants after a rate limit.
func IsSameReservationRetryOf(authorization, attempt RouteAttemptAuthorization) bool {
	if authorization.Validate() != nil || attempt.Validate() != nil {
		return false
	}
	if attempt.Identity() == authorization.Identity() {
		return true
	}
	if attempt.Kind() != RouteAttemptRetry || attempt.routeAttemptOrdinal <= authorization.routeAttemptOrdinal || attempt.attemptOrdinal <= authorization.attemptOrdinal {
		return false
	}
	depth := attempt.routeAttemptOrdinal - authorization.routeAttemptOrdinal
	if depth > MaxRateLimitRetries || attempt.attemptOrdinal-authorization.attemptOrdinal != depth {
		return false
	}
	expected := authorization
	expected.kind, expected.attemptOrdinal, expected.routeAttemptOrdinal = attempt.kind, attempt.attemptOrdinal, attempt.routeAttemptOrdinal
	expected.previousOutcomeIdentity, expected.continuationDecisionIdentity = attempt.previousOutcomeIdentity, attempt.continuationDecisionIdentity
	return deriveRouteAttemptAuthorizationIdentity(expected) == attempt.Identity()
}

// retryDecisionMatches reports whether decision was evaluated for exactly
// previous and its outcome.
func retryDecisionMatches(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, decision RouteAttemptRetryDecision) bool {
	return decision.AuthorizationIdentity() == previous.Identity() && decision.OutcomeIdentity() == outcome.Identity() && decision.RequestIdentity() == previous.RequestIdentity() &&
		decision.RouteRecordIdentity() == previous.RouteRecordIdentity() && decision.RouteAttemptOrdinal() == previous.RouteAttemptOrdinal() && decision.Failure() == outcome.Failure() &&
		decision.ReplaySafety() == outcome.ReplaySafety() && decision.RetryAfterMilliseconds() == outcome.RetryAfterMilliseconds()
}
