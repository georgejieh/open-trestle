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
	// ErrRouteAttemptContinuationDenied identifies a retry or fallback decision that grants no continuation.
	ErrRouteAttemptContinuationDenied = errors.New("route attempt continuation denied")
	// ErrRouteAttemptInsufficientBudget identifies a continuation whose reservation exceeds the settled balance.
	ErrRouteAttemptInsufficientBudget = errors.New("route attempt insufficient budget")
	// ErrInvalidRouteAttemptRetryDecisionIdentity identifies a bound retry identity that does not match its fields.
	ErrInvalidRouteAttemptRetryDecisionIdentity = errors.New("invalid route attempt retry decision identity")
	// ErrInvalidRouteAttemptFallbackDecisionIdentity identifies a bound fallback identity that does not match its fields.
	ErrInvalidRouteAttemptFallbackDecisionIdentity = errors.New("invalid route attempt fallback decision identity")
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

// NewRouteRetryAttemptAuthorization grants a same-route attempt from a permitted retry and settled balance.
func NewRouteRetryAttemptAuthorization(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, decision RouteAttemptRetryDecision) (RouteAttemptAuthorization, error) {
	if err := validateContinuationInputs(previous, outcome, reconciliation); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := decision.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if decision.AuthorizationIdentity() != previous.Identity() || decision.OutcomeIdentity() != outcome.Identity() || decision.RequestIdentity() != previous.RequestIdentity() || decision.RouteRecordIdentity() != previous.RouteRecordIdentity() || decision.RouteAttemptOrdinal() != previous.RouteAttemptOrdinal() || decision.Failure() != outcome.Failure() || decision.ReplaySafety() != outcome.ReplaySafety() || decision.RetryAfterMilliseconds() != outcome.RetryAfterMilliseconds() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationMismatch
	}
	if !decision.ShouldRetry() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	if previous.AttemptOrdinal() == maxRouteAttemptOrdinal || previous.RouteAttemptOrdinal() == maxRouteRetryAttempts {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	remaining := reconciliation.RemainingCostMicroUSD()
	if previous.ReservedCostMicroUSD() > remaining {
		return RouteAttemptAuthorization{}, ErrRouteAttemptInsufficientBudget
	}
	next := previous
	next.identity = ""
	next.kind = RouteAttemptRetry
	next.attemptOrdinal++
	next.routeAttemptOrdinal++
	next.previousOutcomeIdentity = outcome.Identity()
	next.continuationDecisionIdentity = decision.Identity()
	next.remainingCostBeforeMicroUSD = remaining
	next.remainingCostAfterMicroUSD = remaining - next.reservedCostMicroUSD
	next.identity = deriveRouteAttemptAuthorizationIdentity(next)
	if err := next.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	return next, nil
}

// RouteAttemptFallbackDecision binds fallback planning to a failed attempt and its settled balance.
type RouteAttemptFallbackDecision struct {
	identity               string
	authorizationIdentity  string
	outcomeIdentity        string
	reconciliationIdentity string
	decision               RouteFallbackDecision
}

// PlanRouteAttemptFallback plans fallback from one concrete failed and reconciled attempt.
func PlanRouteAttemptFallback(selection RouteSelectionReceipt, ranking RouteRankingResult, policy RouteFallbackPolicy, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, attemptedRecordIdentities []string) (RouteAttemptFallbackDecision, error) {
	if err := validateContinuationInputs(authorization, outcome, reconciliation); err != nil {
		return RouteAttemptFallbackDecision{}, err
	}
	if outcome.Status() != RouteAttemptFailed {
		return RouteAttemptFallbackDecision{}, ErrRouteAttemptNotFailed
	}
	if err := selection.Validate(); err != nil {
		return RouteAttemptFallbackDecision{}, err
	}
	if err := ranking.Validate(); err != nil {
		return RouteAttemptFallbackDecision{}, err
	}
	if !fallbackSelectionMatchesRanking(selection, ranking) || selection.Identity() != authorization.SelectionReceiptIdentity() || selection.ReviewScopeIdentity() != authorization.ReviewScopeIdentity() || selection.RequestIdentity() != authorization.RequestIdentity() || selection.RegistryRevision() != authorization.RegistryRevision() || selection.CostBudget() != authorization.CostBudget() {
		return RouteAttemptFallbackDecision{}, ErrRouteAttemptContinuationMismatch
	}
	if len(attemptedRecordIdentities) == 0 || attemptedRecordIdentities[len(attemptedRecordIdentities)-1] != authorization.RouteRecordIdentity() {
		return RouteAttemptFallbackDecision{}, ErrInvalidRouteFallbackAttempts
	}
	decision, err := planRouteFallback(selection, ranking, policy, outcome.Failure(), outcome.ReplaySafety(), attemptedRecordIdentities, reconciliation.RemainingCostMicroUSD())
	if err != nil {
		return RouteAttemptFallbackDecision{}, err
	}
	bound := RouteAttemptFallbackDecision{authorizationIdentity: authorization.Identity(), outcomeIdentity: outcome.Identity(), reconciliationIdentity: reconciliation.Identity(), decision: decision}
	bound.identity = deriveRouteAttemptFallbackDecisionIdentity(bound)
	if err := bound.Validate(); err != nil {
		return RouteAttemptFallbackDecision{}, err
	}
	return bound, nil
}

func (d RouteAttemptFallbackDecision) Identity() string              { return d.identity }
func (d RouteAttemptFallbackDecision) AuthorizationIdentity() string { return d.authorizationIdentity }
func (d RouteAttemptFallbackDecision) OutcomeIdentity() string       { return d.outcomeIdentity }
func (d RouteAttemptFallbackDecision) ReconciliationIdentity() string {
	return d.reconciliationIdentity
}
func (d RouteAttemptFallbackDecision) ShouldFallback() bool        { return d.decision.ShouldFallback() }
func (d RouteAttemptFallbackDecision) Reason() RouteFallbackReason { return d.decision.Reason() }
func (d RouteAttemptFallbackDecision) NextRecordIdentity() string {
	return d.decision.NextRecordIdentity()
}
func (d RouteAttemptFallbackDecision) String() string { return "route attempt fallback decision" }
func (d RouteAttemptFallbackDecision) GoString() string {
	return "gateway.RouteAttemptFallbackDecision{<redacted>}"
}
func (d RouteAttemptFallbackDecision) Format(state fmt.State, verb rune) {
	formatted := "route attempt fallback decision"
	if verb == 'q' {
		formatted = `"route attempt fallback decision"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteAttemptFallbackDecision{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
func (d RouteAttemptFallbackDecision) Validate() error {
	if !validRequestIdentity(d.authorizationIdentity) || !validRequestIdentity(d.outcomeIdentity) || !validRequestIdentity(d.reconciliationIdentity) {
		return ErrRouteAttemptContinuationMismatch
	}
	if err := d.decision.Validate(); err != nil {
		return err
	}
	if d.identity != deriveRouteAttemptFallbackDecisionIdentity(d) {
		return ErrInvalidRouteAttemptFallbackDecisionIdentity
	}
	return nil
}
func deriveRouteAttemptFallbackDecisionIdentity(d RouteAttemptFallbackDecision) string {
	preimage := struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		Authorization  string `json:"authorization"`
		Outcome        string `json:"outcome"`
		Reconciliation string `json:"reconciliation"`
		Decision       string `json:"decision"`
	}{"open-trestle/route-attempt-fallback-decision", 1, d.authorizationIdentity, d.outcomeIdentity, d.reconciliationIdentity, d.decision.Identity()}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// NewRouteFallbackAttemptAuthorization grants the selected route change from a bound fallback decision.
func NewRouteFallbackAttemptAuthorization(previous RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, decision RouteAttemptFallbackDecision, selection RouteSelectionReceipt, ranking RouteRankingResult) (RouteAttemptAuthorization, error) {
	if err := validateContinuationInputs(previous, outcome, reconciliation); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := decision.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if !decision.ShouldFallback() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	if decision.authorizationIdentity != previous.Identity() || decision.outcomeIdentity != outcome.Identity() || decision.reconciliationIdentity != reconciliation.Identity() || decision.decision.SelectionReceiptIdentity() != previous.SelectionReceiptIdentity() || decision.decision.FromRecordIdentity() != previous.RouteRecordIdentity() || decision.decision.Failure() != outcome.Failure() || decision.decision.ReplaySafety() != outcome.ReplaySafety() || decision.decision.RemainingCostBeforeMicroUSD() != reconciliation.RemainingCostMicroUSD() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationMismatch
	}
	if err := selection.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if err := ranking.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	if !fallbackSelectionMatchesRanking(selection, ranking) || selection.Identity() != previous.SelectionReceiptIdentity() || selection.ReviewScopeIdentity() != previous.ReviewScopeIdentity() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationMismatch
	}
	var selected *RankedRoute
	for index := range ranking.rankedRoutes {
		if observedRouteIdentity(ranking.rankedRoutes[index].route) == decision.NextRecordIdentity() {
			selected = &ranking.rankedRoutes[index]
			break
		}
	}
	if selected == nil || selected.maximumCost.MaximumCostMicroUSD() != decision.decision.ReservedCostMicroUSD() || decision.decision.RemainingCostAfterMicroUSD() != reconciliation.RemainingCostMicroUSD()-selected.maximumCost.MaximumCostMicroUSD() {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationMismatch
	}
	if previous.AttemptOrdinal() == maxRouteAttemptOrdinal {
		return RouteAttemptAuthorization{}, ErrRouteAttemptContinuationDenied
	}
	candidate := selected.route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
	next := RouteAttemptAuthorization{
		kind: RouteAttemptFallback, reviewScopeIdentity: previous.ReviewScopeIdentity(), requestIdentity: previous.RequestIdentity(),
		selectionReceiptIdentity: previous.SelectionReceiptIdentity(), registryRevision: previous.RegistryRevision(),
		routeRecordIdentity: observedRouteIdentity(selected.route), attemptOrdinal: previous.AttemptOrdinal() + 1,
		routeAttemptOrdinal: 1, previousOutcomeIdentity: outcome.Identity(),
		continuationDecisionIdentity: decision.Identity(), routeReference: candidate.RouteCapabilityDeclaration().RouteReference(),
		contentLoggingMode: candidate.ContentLoggingMode(), pricing: candidate.RoutePricing(),
		costBudget: previous.CostBudget(), maximumCost: selected.maximumCost,
		remainingCostBeforeMicroUSD: reconciliation.RemainingCostMicroUSD(),
		reservedCostMicroUSD:        selected.maximumCost.MaximumCostMicroUSD(),
		remainingCostAfterMicroUSD:  decision.decision.RemainingCostAfterMicroUSD(),
	}
	next.identity = deriveRouteAttemptAuthorizationIdentity(next)
	if err := next.Validate(); err != nil {
		return RouteAttemptAuthorization{}, err
	}
	return next, nil
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
