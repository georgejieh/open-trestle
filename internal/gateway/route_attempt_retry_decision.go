package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrRouteAttemptNotFailed identifies continuation planning after a successful attempt.
	ErrRouteAttemptNotFailed = errors.New("route attempt did not fail")
	// ErrRouteAttemptContinuationMismatch identifies cross-wired attempt lineage.
	ErrRouteAttemptContinuationMismatch = errors.New("route attempt continuation mismatch")
	// ErrRouteAttemptCostReconciliationMismatch identifies accounting for another attempt.
	ErrRouteAttemptCostReconciliationMismatch = errors.New("route attempt cost reconciliation mismatch")
	// ErrRouteAttemptContinuationDenied identifies a retry decision that grants no continuation.
	ErrRouteAttemptContinuationDenied = errors.New("route attempt continuation denied")
	// ErrRouteAttemptInsufficientBudget identifies a continuation whose reservation exceeds the settled balance.
	ErrRouteAttemptInsufficientBudget = errors.New("route attempt insufficient budget")
	// ErrInvalidRouteAttemptRetryDecisionIdentity identifies a bound retry identity that does not match its fields.
	ErrInvalidRouteAttemptRetryDecisionIdentity = errors.New("invalid route attempt retry decision identity")
)

// RouteAttemptRetryDecision binds retry classification to one concrete failed attempt.
type RouteAttemptRetryDecision struct {
	identity               string
	authorizationIdentity  string
	outcomeIdentity        string
	retryPolicy            RouteRetryPolicy
	requestIdentity        string
	routeRecordIdentity    string
	routeAttemptOrdinal    uint8
	failure                RouteFailureClass
	replaySafety           RouteReplaySafety
	retryAfterMilliseconds uint32
	decision               RouteRetryDecision
}

// EvaluateRouteAttemptRetry evaluates retry policy using only fields bound to the failed outcome.
func EvaluateRouteAttemptRetry(policy RouteRetryPolicy, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome) (RouteAttemptRetryDecision, error) {
	if err := validateAttemptAndOutcome(authorization, outcome); err != nil {
		return RouteAttemptRetryDecision{}, err
	}
	if outcome.Status() != RouteAttemptFailed {
		return RouteAttemptRetryDecision{}, ErrRouteAttemptNotFailed
	}
	decision, err := evaluateRouteRetry(policy, outcome.Failure(), outcome.ReplaySafety(), authorization.RouteAttemptOrdinal(), outcome.RetryAfterMilliseconds())
	if err != nil {
		return RouteAttemptRetryDecision{}, err
	}
	bound := RouteAttemptRetryDecision{
		authorizationIdentity: authorization.Identity(), outcomeIdentity: outcome.Identity(), retryPolicy: policy,
		requestIdentity: authorization.RequestIdentity(), routeRecordIdentity: authorization.RouteRecordIdentity(), routeAttemptOrdinal: authorization.RouteAttemptOrdinal(),
		failure: outcome.Failure(), replaySafety: outcome.ReplaySafety(), retryAfterMilliseconds: outcome.RetryAfterMilliseconds(), decision: decision,
	}
	bound.identity = deriveRouteAttemptRetryDecisionIdentity(bound)
	if err := bound.Validate(); err != nil {
		return RouteAttemptRetryDecision{}, err
	}
	return bound, nil
}

func (d RouteAttemptRetryDecision) Identity() string                { return d.identity }
func (d RouteAttemptRetryDecision) AuthorizationIdentity() string   { return d.authorizationIdentity }
func (d RouteAttemptRetryDecision) OutcomeIdentity() string         { return d.outcomeIdentity }
func (d RouteAttemptRetryDecision) RetryPolicyIdentity() string     { return d.retryPolicy.Identity() }
func (d RouteAttemptRetryDecision) RequestIdentity() string         { return d.requestIdentity }
func (d RouteAttemptRetryDecision) RouteRecordIdentity() string     { return d.routeRecordIdentity }
func (d RouteAttemptRetryDecision) RouteAttemptOrdinal() uint8      { return d.routeAttemptOrdinal }
func (d RouteAttemptRetryDecision) Failure() RouteFailureClass      { return d.failure }
func (d RouteAttemptRetryDecision) ReplaySafety() RouteReplaySafety { return d.replaySafety }
func (d RouteAttemptRetryDecision) RetryAfterMilliseconds() uint32  { return d.retryAfterMilliseconds }
func (d RouteAttemptRetryDecision) ShouldRetry() bool               { return d.decision.ShouldRetry() }
func (d RouteAttemptRetryDecision) Reason() RouteRetryReason        { return d.decision.Reason() }
func (d RouteAttemptRetryDecision) MinimumDelayMilliseconds() uint32 {
	return d.decision.MinimumDelayMilliseconds()
}
func (d RouteAttemptRetryDecision) MaximumDelayMilliseconds() uint32 {
	return d.decision.MaximumDelayMilliseconds()
}
func (d RouteAttemptRetryDecision) String() string { return "route attempt retry decision" }
func (d RouteAttemptRetryDecision) GoString() string {
	return "gateway.RouteAttemptRetryDecision{<redacted>}"
}
func (d RouteAttemptRetryDecision) Format(state fmt.State, verb rune) {
	formatted := "route attempt retry decision"
	if verb == 'q' {
		formatted = `"route attempt retry decision"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteAttemptRetryDecision{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies bound retry fields, decision consistency, and content-derived identity.
func (d RouteAttemptRetryDecision) Validate() error {
	if !validRequestIdentity(d.authorizationIdentity) || !validRequestIdentity(d.outcomeIdentity) || d.retryPolicy.Validate() != nil || !validRequestIdentity(d.requestIdentity) || !validRequestIdentity(d.routeRecordIdentity) || d.routeAttemptOrdinal == 0 || d.routeAttemptOrdinal > maxRouteRetryAttempts {
		return ErrRouteAttemptContinuationMismatch
	}
	if err := d.failure.Validate(); err != nil {
		return err
	}
	if err := d.replaySafety.Validate(); err != nil {
		return err
	}
	if d.retryAfterMilliseconds != 0 && d.failure != RouteFailureRateLimited {
		return ErrInvalidRouteRetryAfter
	}
	if err := d.decision.Validate(); err != nil {
		return err
	}
	expected, err := evaluateRouteRetry(d.retryPolicy, d.failure, d.replaySafety, d.routeAttemptOrdinal, d.retryAfterMilliseconds)
	if err != nil {
		return err
	}
	if d.decision != expected {
		return ErrRouteAttemptContinuationMismatch
	}
	if d.identity != deriveRouteAttemptRetryDecisionIdentity(d) {
		return ErrInvalidRouteAttemptRetryDecisionIdentity
	}
	return nil
}

func deriveRouteAttemptRetryDecisionIdentity(d RouteAttemptRetryDecision) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Authorization string `json:"authorization"`
		Outcome       string `json:"outcome"`
		Policy        string `json:"policy"`
		Request       string `json:"request"`
		Record        string `json:"record"`
		RouteAttempt  uint8  `json:"route_attempt"`
		Failure       string `json:"failure"`
		Safety        string `json:"safety"`
		RetryAfter    uint32 `json:"retry_after"`
		ShouldRetry   bool   `json:"should_retry"`
		Reason        string `json:"reason"`
		Minimum       uint32 `json:"minimum"`
		Maximum       uint32 `json:"maximum"`
	}{
		Contract: "open-trestle/route-attempt-retry-decision", Version: 1,
		Authorization: d.authorizationIdentity, Outcome: d.outcomeIdentity, Policy: d.retryPolicy.Identity(),
		Request: d.requestIdentity, Record: d.routeRecordIdentity, RouteAttempt: d.routeAttemptOrdinal,
		Failure: d.failure.String(), Safety: d.replaySafety.String(), RetryAfter: d.retryAfterMilliseconds,
		ShouldRetry: d.ShouldRetry(), Reason: d.Reason().String(),
		Minimum: d.MinimumDelayMilliseconds(), Maximum: d.MaximumDelayMilliseconds(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validateAttemptAndOutcome(authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome) error {
	if err := authorization.Validate(); err != nil {
		return err
	}
	if err := outcome.Validate(); err != nil {
		return err
	}
	if outcome.AuthorizationIdentity() != authorization.Identity() {
		return ErrRouteAttemptOutcomeMismatch
	}
	return nil
}
func validateContinuationInputs(authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation) error {
	if err := validateAttemptAndOutcome(authorization, outcome); err != nil {
		return err
	}
	if outcome.Status() != RouteAttemptFailed {
		return ErrRouteAttemptNotFailed
	}
	if err := reconciliation.Validate(); err != nil {
		return err
	}
	if reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() {
		return ErrRouteAttemptCostReconciliationMismatch
	}
	if reconciliation.Status() == RouteCostBudgetExceeded {
		return ErrRouteAttemptInsufficientBudget
	}
	return nil
}
