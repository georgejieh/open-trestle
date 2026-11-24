package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// NewAnswerRetryAttemptAuthorization grants the one same-route retry of a
// request whose answer the host could not use: an attempt that succeeded with
// an answer the host rejected, or one that failed as output_exhausted. That
// attempt was processed and stays settled at its own cost, so the retry is a
// new reservation of the same per-request amount under the same terms, and
// its claim binds the rejected attempt's outcome. The retry counts against
// the request's MaxRateLimitRetries same-route retries, so the chain stays one
// IsSameReservationRetryOf reads; it is refused when none is left.
func NewAnswerRetryAttemptAuthorization(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation) (RouteAttemptAuthorization, error) {
	if err := validateAttemptAndOutcome(previous, outcome); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := reconciliation.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if reconciliation.AttemptAuthorizationIdentity() != previous.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptCostReconciliationMismatch
	}
	if reconciliation.Status() == RouteCostBudgetExceeded {
		return RouteAttemptAuthorization{}, ErrRouteAttemptInsufficientBudget
	}
	answered := outcome.Status() == RouteAttemptSucceeded || outcome.Failure() == RouteFailureOutputExhausted
	if !answered || previous.RouteAttemptOrdinal() > MaxRateLimitRetries || previous.AttemptOrdinal() == maxRouteAttemptOrdinal {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	next := previous
	next.identity = ""
	next.kind = RouteAttemptRetry
	next.attemptOrdinal++
	next.routeAttemptOrdinal++
	next.previousOutcomeIdentity = outcome.Identity()
	next.continuationDecisionIdentity = answerRetryDecisionIdentity(previous, outcome, reconciliation)
	next.identity = deriveRouteAttemptAuthorizationIdentity(next)
	if err := next.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	return next, nil
}

// answerRetryDecisionIdentity binds the answer retry to the rejected attempt
// and its settlement.
func answerRetryDecisionIdentity(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation) string {
	encoded, _ := json.Marshal([]any{"open-trestle/route-answer-retry-decision", 1, previous.Identity(), outcome.Identity(), reconciliation.Identity()})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
