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
// before processing it: failure rate_limited and no side effect, settled with
// known zero usage (its reservation released) or, from an adapter that
// records none, unknown usage (its reservation still held). That attempt
// consumed nothing, so the retry holds the same amount from the same balance
// either way instead of making another reservation, and the total held never
// grows.
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
	usage := outcome.Usage()
	released := usage.IsKnown() && usage.InputTokens() == 0 && usage.OutputTokens() == 0 && usage.CachedInputTokens() == 0 &&
		reconciliation.Status() == RouteCostWithinReservation && reconciliation.RemainingCostMicroUSD() == previous.RemainingCostBeforeMicroUSD()
	held := !usage.IsKnown() && reconciliation.Status() == RouteCostUsageUnknown && reconciliation.RemainingCostMicroUSD() == previous.RemainingCostAfterMicroUSD()
	if outcome.Failure() != RouteFailureRateLimited || outcome.ReplaySafety() != RouteReplayNoSideEffect || !released && !held {
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
// NewRateLimitedRetryAttemptAuthorization grants after a rate limit and
// NewAnswerRetryAttemptAuthorization after a rejected answer.
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

// SameReservationRetryIdentity returns the identity the depth-th same-route
// retry of initial has when it follows the refused outcome previousOutcome
// under the retry decision decision, as NewRateLimitedRetryAttemptAuthorization
// grants it, so a reader holding only recorded identities can check a retry
// chain. It is false for an initial that is not a first attempt, a depth
// outside 1..MaxRateLimitRetries, or an identity that is not a digest.
func SameReservationRetryIdentity(initial RouteAttemptAuthorization, depth int, previousOutcome, decision string) (string, bool) {
	if initial.Validate() != nil || initial.Kind() == RouteAttemptRetry || depth < 1 || depth > MaxRateLimitRetries ||
		int(initial.routeAttemptOrdinal)+depth > int(maxRouteRetryAttempts) || int(initial.attemptOrdinal)+depth > int(maxRouteAttemptOrdinal) {
		return "", false
	}
	expected := initial
	expected.kind = RouteAttemptRetry
	expected.attemptOrdinal += uint8(depth)
	expected.routeAttemptOrdinal += uint8(depth)
	expected.previousOutcomeIdentity, expected.continuationDecisionIdentity = previousOutcome, decision
	expected.identity = deriveRouteAttemptAuthorizationIdentity(expected)
	if expected.Validate() != nil {
		return "", false
	}
	return expected.identity, true
}

// retryDecisionMatches reports whether decision was evaluated for exactly
// previous and its outcome.
func retryDecisionMatches(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, decision RouteAttemptRetryDecision) bool {
	return decision.AuthorizationIdentity() == previous.Identity() && decision.OutcomeIdentity() == outcome.Identity() && decision.RequestIdentity() == previous.RequestIdentity() &&
		decision.RouteRecordIdentity() == previous.RouteRecordIdentity() && decision.RouteAttemptOrdinal() == previous.RouteAttemptOrdinal() && decision.Failure() == outcome.Failure() &&
		decision.ReplaySafety() == outcome.ReplaySafety() && decision.RetryAfterMilliseconds() == outcome.RetryAfterMilliseconds()
}
