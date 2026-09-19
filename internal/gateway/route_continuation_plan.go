package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrInvalidRouteContinuationAction identifies an unknown next execution action.
	ErrInvalidRouteContinuationAction = errors.New("invalid route continuation action")
	// ErrInvalidRouteContinuationReason identifies an unknown continuation rationale.
	ErrInvalidRouteContinuationReason = errors.New("invalid route continuation reason")
	// ErrInvalidRouteContinuationPlan identifies inconsistent continuation fields.
	ErrInvalidRouteContinuationPlan = errors.New("invalid route continuation plan")
	// ErrInvalidRouteContinuationPlanIdentity identifies a plan identity inconsistent with its fields.
	ErrInvalidRouteContinuationPlanIdentity = errors.New("invalid route continuation plan identity")
)

// RouteContinuationAction identifies whether execution completes, retries, changes route, or stops.
type RouteContinuationAction uint8

const (
	RouteContinuationComplete RouteContinuationAction = iota + 1
	RouteContinuationRetry
	RouteContinuationFallback
	RouteContinuationStop
)

func (a RouteContinuationAction) String() string {
	switch a {
	case RouteContinuationComplete:
		return "complete"
	case RouteContinuationRetry:
		return "retry"
	case RouteContinuationFallback:
		return "fallback"
	case RouteContinuationStop:
		return "stop"
	default:
		return ""
	}
}

// ParseRouteContinuationAction parses one exact stable action token.
func ParseRouteContinuationAction(value string) (RouteContinuationAction, error) {
	for action := RouteContinuationComplete; action <= RouteContinuationStop; action++ {
		if action.String() == value {
			return action, nil
		}
	}
	return 0, fmt.Errorf("parse route continuation action: %w", ErrInvalidRouteContinuationAction)
}

func (a RouteContinuationAction) Validate() error {
	if a.String() == "" {
		return ErrInvalidRouteContinuationAction
	}
	return nil
}

// RouteContinuationReason identifies the deterministic reason for the action.
type RouteContinuationReason uint8

const (
	RouteContinuationSucceeded RouteContinuationReason = iota + 1
	RouteContinuationRetrySelected
	RouteContinuationFallbackSelected
	RouteContinuationDenied
	RouteContinuationBudgetExhausted
)

func (r RouteContinuationReason) String() string {
	switch r {
	case RouteContinuationSucceeded:
		return "route_succeeded"
	case RouteContinuationRetrySelected:
		return "retry_selected"
	case RouteContinuationFallbackSelected:
		return "fallback_selected"
	case RouteContinuationDenied:
		return "continuation_denied"
	case RouteContinuationBudgetExhausted:
		return "budget_exhausted"
	default:
		return ""
	}
}

// ParseRouteContinuationReason parses one exact stable reason token.
func ParseRouteContinuationReason(value string) (RouteContinuationReason, error) {
	for reason := RouteContinuationSucceeded; reason <= RouteContinuationBudgetExhausted; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, fmt.Errorf("parse route continuation reason: %w", ErrInvalidRouteContinuationReason)
}

func (r RouteContinuationReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidRouteContinuationReason
	}
	return nil
}

// RouteContinuationPlan is the content-addressed next action after one settled attempt.
type RouteContinuationPlan struct {
	identity                  string
	action                    RouteContinuationAction
	reason                    RouteContinuationReason
	selectionIdentity         string
	initialRecordIdentity     string
	currentRecordIdentity     string
	retryPolicyIdentity       string
	fallbackPolicyIdentity    string
	authorizationIdentity     string
	outcomeIdentity           string
	reconciliationIdentity    string
	attemptedRecordIdentities []string
	retryDecision             RouteAttemptRetryDecision
	fallbackDecision          RouteAttemptFallbackDecision
	nextAuthorization         RouteAttemptAuthorization
}

// PlanRouteContinuation chooses retry before fallback and stops on unsafe replay or exhausted budget.
func PlanRouteContinuation(selection RouteSelectionReceipt, ranking RouteRankingResult, retryPolicy RouteRetryPolicy, fallbackPolicy RouteFallbackPolicy, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, attemptedRecordIdentities []string) (RouteContinuationPlan, error) {
	if err := validateRouteContinuationContext(selection, ranking, retryPolicy, fallbackPolicy, authorization, outcome, reconciliation); err != nil {
		return RouteContinuationPlan{}, err
	}
	if err := validateContinuationAttemptedRoutes(selection, ranking, authorization, attemptedRecordIdentities); err != nil {
		return RouteContinuationPlan{}, err
	}
	plan := RouteContinuationPlan{
		selectionIdentity: selection.Identity(), initialRecordIdentity: selection.SelectedRecordIdentity(),
		currentRecordIdentity: authorization.RouteRecordIdentity(), retryPolicyIdentity: retryPolicy.Identity(), fallbackPolicyIdentity: fallbackPolicy.Identity(),
		authorizationIdentity: authorization.Identity(), outcomeIdentity: outcome.Identity(),
		reconciliationIdentity:    reconciliation.Identity(),
		attemptedRecordIdentities: append([]string(nil), attemptedRecordIdentities...),
	}
	if outcome.Status() == RouteAttemptSucceeded {
		return finalizeRouteContinuationPlan(plan, RouteContinuationComplete, RouteContinuationSucceeded)
	}
	if reconciliation.Status() == RouteCostBudgetExceeded {
		return finalizeRouteContinuationPlan(plan, RouteContinuationStop, RouteContinuationBudgetExhausted)
	}
	retryDecision, err := EvaluateRouteAttemptRetry(retryPolicy, authorization, outcome)
	if err != nil {
		return RouteContinuationPlan{}, err
	}
	plan.retryDecision = retryDecision
	if retryDecision.ShouldRetry() {
		next, retryErr := NewRouteRetryAttemptAuthorization(authorization, outcome, reconciliation, retryDecision)
		switch {
		case retryErr == nil:
			plan.nextAuthorization = next
			return finalizeRouteContinuationPlan(plan, RouteContinuationRetry, RouteContinuationRetrySelected)
		case errors.Is(retryErr, ErrRouteAttemptInsufficientBudget):
			// A lower-cost fallback can still fit the settled balance.
		case errors.Is(retryErr, ErrRouteAttemptContinuationDenied):
			return finalizeRouteContinuationPlan(plan, RouteContinuationStop, RouteContinuationDenied)
		default:
			return RouteContinuationPlan{}, retryErr
		}
	}
	fallbackDecision, err := PlanRouteAttemptFallback(selection, ranking, fallbackPolicy, authorization, outcome, reconciliation, attemptedRecordIdentities)
	if err != nil {
		return RouteContinuationPlan{}, err
	}
	plan.fallbackDecision = fallbackDecision
	if !fallbackDecision.ShouldFallback() {
		return finalizeRouteContinuationPlan(plan, RouteContinuationStop, RouteContinuationDenied)
	}
	next, err := NewRouteFallbackAttemptAuthorization(authorization, outcome, reconciliation, fallbackDecision, selection, ranking)
	if err != nil {
		return RouteContinuationPlan{}, err
	}
	plan.nextAuthorization = next
	return finalizeRouteContinuationPlan(plan, RouteContinuationFallback, RouteContinuationFallbackSelected)
}

func validateRouteContinuationContext(selection RouteSelectionReceipt, ranking RouteRankingResult, retryPolicy RouteRetryPolicy, fallbackPolicy RouteFallbackPolicy, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation) error {
	if err := selection.Validate(); err != nil {
		return err
	}
	if err := ranking.Validate(); err != nil {
		return err
	}
	if !fallbackSelectionMatchesRanking(selection, ranking) {
		return ErrRouteAttemptContinuationMismatch
	}
	if err := retryPolicy.Validate(); err != nil {
		return err
	}
	if err := fallbackPolicy.Validate(); err != nil {
		return err
	}
	if err := validateAttemptAndOutcome(authorization, outcome); err != nil {
		return err
	}
	if err := reconciliation.Validate(); err != nil {
		return err
	}
	if selection.Identity() != authorization.SelectionReceiptIdentity() || selection.ReviewScopeIdentity() != authorization.ReviewScopeIdentity() || selection.RequestIdentity() != authorization.RequestIdentity() || selection.RegistryRevision() != authorization.RegistryRevision() || selection.CostBudget() != authorization.CostBudget() {
		return ErrRouteAttemptContinuationMismatch
	}
	if reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() {
		return ErrRouteAttemptCostReconciliationMismatch
	}
	return nil
}

func validateContinuationAttemptedRoutes(selection RouteSelectionReceipt, ranking RouteRankingResult, authorization RouteAttemptAuthorization, attempted []string) error {
	if len(attempted) == 0 || len(attempted) > len(ranking.rankedRoutes) || attempted[0] != selection.SelectedRecordIdentity() || attempted[len(attempted)-1] != authorization.RouteRecordIdentity() {
		return ErrInvalidRouteFallbackAttempts
	}
	available := make(map[string]struct{}, len(ranking.rankedRoutes))
	for _, ranked := range ranking.rankedRoutes {
		available[observedRouteIdentity(ranked.route)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(attempted))
	for _, identity := range attempted {
		if _, exists := available[identity]; !exists {
			return ErrInvalidRouteFallbackAttempts
		}
		if _, exists := seen[identity]; exists {
			return ErrInvalidRouteFallbackAttempts
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func finalizeRouteContinuationPlan(plan RouteContinuationPlan, action RouteContinuationAction, reason RouteContinuationReason) (RouteContinuationPlan, error) {
	plan.action = action
	plan.reason = reason
	plan.identity = deriveRouteContinuationPlanIdentity(plan)
	if err := plan.Validate(); err != nil {
		return RouteContinuationPlan{}, err
	}
	return plan, nil
}

func (p RouteContinuationPlan) Identity() string                         { return p.identity }
func (p RouteContinuationPlan) Action() RouteContinuationAction          { return p.action }
func (p RouteContinuationPlan) Reason() RouteContinuationReason          { return p.reason }
func (p RouteContinuationPlan) AuthorizationIdentity() string            { return p.authorizationIdentity }
func (p RouteContinuationPlan) OutcomeIdentity() string                  { return p.outcomeIdentity }
func (p RouteContinuationPlan) ReconciliationIdentity() string           { return p.reconciliationIdentity }
func (p RouteContinuationPlan) HasRetryDecision() bool                   { return p.retryDecision.Identity() != "" }
func (p RouteContinuationPlan) HasFallbackDecision() bool                { return p.fallbackDecision.Identity() != "" }
func (p RouteContinuationPlan) RetryDecision() RouteAttemptRetryDecision { return p.retryDecision }
func (p RouteContinuationPlan) FallbackDecision() RouteAttemptFallbackDecision {
	return p.fallbackDecision
}
func (p RouteContinuationPlan) NextAuthorization() RouteAttemptAuthorization {
	return p.nextAuthorization
}
func (p RouteContinuationPlan) AttemptedRecordIdentities() []string {
	return append([]string(nil), p.attemptedRecordIdentities...)
}
func (p RouteContinuationPlan) String() string   { return "route continuation plan" }
func (p RouteContinuationPlan) GoString() string { return "gateway.RouteContinuationPlan{<redacted>}" }
func (p RouteContinuationPlan) Format(state fmt.State, verb rune) {
	formatted := "route continuation plan"
	if verb == 'q' {
		formatted = `"route continuation plan"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteContinuationPlan{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies decision lineage, action semantics, and the content-derived identity.
func (p RouteContinuationPlan) Validate() error {
	if err := p.action.Validate(); err != nil {
		return err
	}
	if err := p.reason.Validate(); err != nil {
		return err
	}
	for _, identity := range []string{p.selectionIdentity, p.initialRecordIdentity, p.currentRecordIdentity, p.retryPolicyIdentity, p.fallbackPolicyIdentity, p.authorizationIdentity, p.outcomeIdentity, p.reconciliationIdentity} {
		if !validRequestIdentity(identity) {
			return ErrInvalidRouteContinuationPlan
		}
	}
	if len(p.attemptedRecordIdentities) == 0 || len(p.attemptedRecordIdentities) > int(maxRouteFallbacks)+1 || p.attemptedRecordIdentities[0] != p.initialRecordIdentity || p.attemptedRecordIdentities[len(p.attemptedRecordIdentities)-1] != p.currentRecordIdentity {
		return ErrInvalidRouteContinuationPlan
	}
	seen := make(map[string]struct{}, len(p.attemptedRecordIdentities))
	for _, identity := range p.attemptedRecordIdentities {
		if !validRequestIdentity(identity) {
			return ErrInvalidRouteContinuationPlan
		}
		if _, exists := seen[identity]; exists {
			return ErrInvalidRouteContinuationPlan
		}
		seen[identity] = struct{}{}
	}
	if err := p.validateActionFields(); err != nil {
		return err
	}
	if p.identity != deriveRouteContinuationPlanIdentity(p) {
		return ErrInvalidRouteContinuationPlanIdentity
	}
	return nil
}

func (p RouteContinuationPlan) validateActionFields() error {
	hasRetry := p.HasRetryDecision()
	hasFallback := p.HasFallbackDecision()
	hasNext := p.nextAuthorization.Identity() != ""
	switch p.action {
	case RouteContinuationComplete:
		if p.reason != RouteContinuationSucceeded || hasRetry || hasFallback || hasNext {
			return ErrInvalidRouteContinuationPlan
		}
	case RouteContinuationRetry:
		if p.reason != RouteContinuationRetrySelected || !hasRetry || hasFallback || !hasNext || !p.retryDecision.ShouldRetry() || p.nextAuthorization.Kind() != RouteAttemptRetry || p.nextAuthorization.ContinuationDecisionIdentity() != p.retryDecision.Identity() {
			return ErrInvalidRouteContinuationPlan
		}
	case RouteContinuationFallback:
		if p.reason != RouteContinuationFallbackSelected || !hasRetry || !hasFallback || !hasNext || !p.fallbackDecision.ShouldFallback() || p.nextAuthorization.Kind() != RouteAttemptFallback || p.nextAuthorization.ContinuationDecisionIdentity() != p.fallbackDecision.Identity() {
			return ErrInvalidRouteContinuationPlan
		}
	case RouteContinuationStop:
		if hasNext {
			return ErrInvalidRouteContinuationPlan
		}
		if p.reason == RouteContinuationBudgetExhausted {
			if hasRetry || hasFallback {
				return ErrInvalidRouteContinuationPlan
			}
		} else if p.reason != RouteContinuationDenied || !hasRetry || !hasFallback || p.fallbackDecision.ShouldFallback() {
			return ErrInvalidRouteContinuationPlan
		}
	}
	if hasRetry {
		if err := p.retryDecision.Validate(); err != nil {
			return err
		}
		if p.retryDecision.AuthorizationIdentity() != p.authorizationIdentity || p.retryDecision.OutcomeIdentity() != p.outcomeIdentity || p.retryDecision.RetryPolicyIdentity() != p.retryPolicyIdentity {
			return ErrInvalidRouteContinuationPlan
		}
	}
	if hasFallback {
		if err := p.fallbackDecision.Validate(); err != nil {
			return err
		}
		if p.fallbackDecision.AuthorizationIdentity() != p.authorizationIdentity || p.fallbackDecision.OutcomeIdentity() != p.outcomeIdentity || p.fallbackDecision.ReconciliationIdentity() != p.reconciliationIdentity {
			return ErrInvalidRouteContinuationPlan
		}
	}
	if hasNext {
		if err := p.nextAuthorization.Validate(); err != nil {
			return err
		}
		if p.nextAuthorization.PreviousOutcomeIdentity() != p.outcomeIdentity || p.nextAuthorization.SelectionReceiptIdentity() != p.selectionIdentity {
			return ErrInvalidRouteContinuationPlan
		}
	}
	return nil
}

func deriveRouteContinuationPlanIdentity(plan RouteContinuationPlan) string {
	preimage := struct {
		Contract          string   `json:"contract"`
		Version           int      `json:"version"`
		Action            string   `json:"action"`
		Reason            string   `json:"reason"`
		Selection         string   `json:"selection"`
		Ranking           string   `json:"ranking"`
		RetryPolicy       string   `json:"retry_policy"`
		FallbackPolicy    string   `json:"fallback_policy"`
		Authorization     string   `json:"authorization"`
		Outcome           string   `json:"outcome"`
		Reconciliation    string   `json:"reconciliation"`
		Attempted         []string `json:"attempted"`
		RetryDecision     string   `json:"retry_decision"`
		FallbackDecision  string   `json:"fallback_decision"`
		NextAuthorization string   `json:"next_authorization"`
	}{
		Contract: "open-trestle/route-continuation-plan", Version: 1,
		Action: plan.action.String(), Reason: plan.reason.String(),
		Selection:   plan.selectionIdentity,
		RetryPolicy: plan.retryPolicyIdentity, FallbackPolicy: plan.fallbackPolicyIdentity,
		Authorization: plan.authorizationIdentity, Outcome: plan.outcomeIdentity,
		Reconciliation: plan.reconciliationIdentity,
		Attempted:      plan.attemptedRecordIdentities,
		RetryDecision:  plan.retryDecision.Identity(), FallbackDecision: plan.fallbackDecision.Identity(),
		NextAuthorization: plan.nextAuthorization.Identity(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
