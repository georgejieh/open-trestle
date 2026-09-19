package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrInvalidRouteCostReconciliationStatus identifies an unknown accounting outcome.
	ErrInvalidRouteCostReconciliationStatus = errors.New("invalid route cost reconciliation status")
	// ErrInvalidRouteCostReconciliationBudget identifies overflowing or inconsistent budget fields.
	ErrInvalidRouteCostReconciliationBudget = errors.New("invalid route cost reconciliation budget")
	// ErrInvalidRouteCostReconciliationIdentity identifies a reconciliation identity that does not match its fields.
	ErrInvalidRouteCostReconciliationIdentity = errors.New("invalid route cost reconciliation identity")
)

// RouteCostReconciliationStatus identifies how actual cost relates to reservation and request budget.
type RouteCostReconciliationStatus uint8

const (
	RouteCostWithinReservation RouteCostReconciliationStatus = iota + 1
	RouteCostWithinBudget
	RouteCostBudgetExceeded
	RouteCostUsageUnknown
)

// String returns the stable accounting token or an empty string for unknown values.
func (s RouteCostReconciliationStatus) String() string {
	switch s {
	case RouteCostWithinReservation:
		return "within_reservation"
	case RouteCostWithinBudget:
		return "within_budget"
	case RouteCostBudgetExceeded:
		return "budget_exceeded"
	case RouteCostUsageUnknown:
		return "usage_unknown"
	default:
		return ""
	}
}

// ParseRouteCostReconciliationStatus parses one exact stable accounting token.
func ParseRouteCostReconciliationStatus(value string) (RouteCostReconciliationStatus, error) {
	for candidate := RouteCostWithinReservation; candidate <= RouteCostUsageUnknown; candidate++ {
		if candidate.String() == value {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("parse route cost reconciliation status: %w", ErrInvalidRouteCostReconciliationStatus)
}

// Validate verifies that the accounting status is recognized.
func (s RouteCostReconciliationStatus) Validate() error {
	if s.String() == "" {
		return ErrInvalidRouteCostReconciliationStatus
	}
	return nil
}

// RouteCostReconciliation is a content-addressed accounting result for one authorized attempt.
type RouteCostReconciliation struct {
	identity                          string
	attemptAuthorizationIdentity      string
	attemptOutcomeIdentity            string
	status                            RouteCostReconciliationStatus
	reservedCostMicroUSD              uint64
	actualCost                        provider.RouteActualCost
	remainingAfterReservationMicroUSD uint64
	remainingCostMicroUSD             uint64
	budgetOverrunMicroUSD             uint64
}

// ReconcileAuthorizedRouteAttemptCost settles usage only for its matching authorization.
func ReconcileAuthorizedRouteAttemptCost(authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome) (RouteCostReconciliation, error) {
	if err := authorization.Validate(); err != nil {
		return RouteCostReconciliation{}, err
	}
	if err := outcome.Validate(); err != nil {
		return RouteCostReconciliation{}, err
	}
	if outcome.AuthorizationIdentity() != authorization.Identity() {
		return RouteCostReconciliation{}, ErrRouteAttemptOutcomeMismatch
	}
	actualCost, err := provider.CalculateActualRouteCost(authorization.Pricing(), outcome.Usage())
	if err != nil {
		return RouteCostReconciliation{}, err
	}
	return reconcileRouteAttemptCost(authorization.Identity(), outcome.Identity(), authorization.ReservedCostMicroUSD(), authorization.RemainingCostAfterMicroUSD(), actualCost)
}

func reconcileRouteAttemptCost(attemptAuthorizationIdentity, attemptOutcomeIdentity string, reservedCostMicroUSD, remainingAfterReservationMicroUSD uint64, actualCost provider.RouteActualCost) (RouteCostReconciliation, error) {
	if !validRequestIdentity(attemptAuthorizationIdentity) || !validRequestIdentity(attemptOutcomeIdentity) {
		return RouteCostReconciliation{}, ErrInvalidRequestIdentity
	}
	if reservedCostMicroUSD > math.MaxUint64-remainingAfterReservationMicroUSD {
		return RouteCostReconciliation{}, ErrInvalidRouteCostReconciliationBudget
	}
	if err := actualCost.Validate(); err != nil {
		return RouteCostReconciliation{}, err
	}
	reconciliation := RouteCostReconciliation{
		attemptAuthorizationIdentity:      attemptAuthorizationIdentity,
		attemptOutcomeIdentity:            attemptOutcomeIdentity,
		reservedCostMicroUSD:              reservedCostMicroUSD,
		actualCost:                        actualCost,
		remainingAfterReservationMicroUSD: remainingAfterReservationMicroUSD,
		remainingCostMicroUSD:             remainingAfterReservationMicroUSD,
	}
	if !actualCost.IsKnown() {
		reconciliation.status = RouteCostUsageUnknown
	} else {
		actual := actualCost.TotalCostMicroUSD()
		before := reservedCostMicroUSD + remainingAfterReservationMicroUSD
		switch {
		case actual <= reservedCostMicroUSD:
			reconciliation.status = RouteCostWithinReservation
			reconciliation.remainingCostMicroUSD = before - actual
		case actual <= before:
			reconciliation.status = RouteCostWithinBudget
			reconciliation.remainingCostMicroUSD = before - actual
		default:
			reconciliation.status = RouteCostBudgetExceeded
			reconciliation.remainingCostMicroUSD = 0
			reconciliation.budgetOverrunMicroUSD = actual - before
		}
	}
	reconciliation.identity = deriveRouteCostReconciliationIdentity(reconciliation)
	if err := reconciliation.Validate(); err != nil {
		return RouteCostReconciliation{}, err
	}
	return reconciliation, nil
}

// Identity returns the canonical SHA-256 reconciliation identity.
func (r RouteCostReconciliation) Identity() string { return r.identity }

// AttemptAuthorizationIdentity returns the bound attempt authorization identity.
func (r RouteCostReconciliation) AttemptAuthorizationIdentity() string {
	return r.attemptAuthorizationIdentity
}

// AttemptOutcomeIdentity returns the bound terminal outcome identity.
func (r RouteCostReconciliation) AttemptOutcomeIdentity() string { return r.attemptOutcomeIdentity }

// Status returns the accounting outcome.
func (r RouteCostReconciliation) Status() RouteCostReconciliationStatus { return r.status }

// ReservedCostMicroUSD returns the pessimistic pre-dispatch reservation.
func (r RouteCostReconciliation) ReservedCostMicroUSD() uint64 { return r.reservedCostMicroUSD }

// ActualCost returns the known or explicitly unknown actual cost.
func (r RouteCostReconciliation) ActualCost() provider.RouteActualCost { return r.actualCost }

// RemainingAfterReservationMicroUSD returns the balance held during the attempt.
func (r RouteCostReconciliation) RemainingAfterReservationMicroUSD() uint64 {
	return r.remainingAfterReservationMicroUSD
}

// RemainingCostMicroUSD returns the settled balance available for later attempts.
func (r RouteCostReconciliation) RemainingCostMicroUSD() uint64 { return r.remainingCostMicroUSD }

// BudgetOverrunMicroUSD returns the exact amount actual cost exceeded the pre-attempt balance.
func (r RouteCostReconciliation) BudgetOverrunMicroUSD() uint64 { return r.budgetOverrunMicroUSD }

// String returns a redacted reconciliation description.
func (r RouteCostReconciliation) String() string { return "route cost reconciliation" }

// GoString returns a redacted Go-syntax reconciliation description.
func (r RouteCostReconciliation) GoString() string {
	return "gateway.RouteCostReconciliation{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RouteCostReconciliation) Format(state fmt.State, verb rune) {
	formatted := "route cost reconciliation"
	if verb == 'q' {
		formatted = `"route cost reconciliation"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteCostReconciliation{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies accounting arithmetic and the content-derived identity.
func (r RouteCostReconciliation) Validate() error {
	if !validRequestIdentity(r.attemptAuthorizationIdentity) || !validRequestIdentity(r.attemptOutcomeIdentity) {
		return ErrInvalidRequestIdentity
	}
	if r.reservedCostMicroUSD > math.MaxUint64-r.remainingAfterReservationMicroUSD {
		return ErrInvalidRouteCostReconciliationBudget
	}
	if err := r.actualCost.Validate(); err != nil {
		return err
	}
	expectedStatus := RouteCostUsageUnknown
	expectedRemaining := r.remainingAfterReservationMicroUSD
	expectedOverrun := uint64(0)
	if r.actualCost.IsKnown() {
		actual := r.actualCost.TotalCostMicroUSD()
		before := r.reservedCostMicroUSD + r.remainingAfterReservationMicroUSD
		switch {
		case actual <= r.reservedCostMicroUSD:
			expectedStatus = RouteCostWithinReservation
			expectedRemaining = before - actual
		case actual <= before:
			expectedStatus = RouteCostWithinBudget
			expectedRemaining = before - actual
		default:
			expectedStatus = RouteCostBudgetExceeded
			expectedRemaining = 0
			expectedOverrun = actual - before
		}
	}
	if r.status != expectedStatus || r.remainingCostMicroUSD != expectedRemaining || r.budgetOverrunMicroUSD != expectedOverrun {
		return ErrInvalidRouteCostReconciliationBudget
	}
	if r.identity != deriveRouteCostReconciliationIdentity(r) {
		return ErrInvalidRouteCostReconciliationIdentity
	}
	return nil
}

func deriveRouteCostReconciliationIdentity(reconciliation RouteCostReconciliation) string {
	actual := reconciliation.actualCost
	preimage := struct {
		Contract                          string `json:"contract"`
		Version                           int    `json:"version"`
		AttemptAuthorizationIdentity      string `json:"attempt_authorization_identity"`
		AttemptOutcomeIdentity            string `json:"attempt_outcome_identity"`
		Status                            string `json:"status"`
		ReservedCostMicroUSD              uint64 `json:"reserved_cost_micro_usd"`
		ActualKnown                       bool   `json:"actual_known"`
		ActualInputCostMicroUSD           uint64 `json:"actual_input_cost_micro_usd"`
		ActualOutputCostMicroUSD          uint64 `json:"actual_output_cost_micro_usd"`
		ActualTotalCostMicroUSD           uint64 `json:"actual_total_cost_micro_usd"`
		RemainingAfterReservationMicroUSD uint64 `json:"remaining_after_reservation_micro_usd"`
		RemainingCostMicroUSD             uint64 `json:"remaining_cost_micro_usd"`
		BudgetOverrunMicroUSD             uint64 `json:"budget_overrun_micro_usd"`
	}{
		Contract: "open-trestle/route-cost-reconciliation", Version: 1,
		AttemptAuthorizationIdentity: reconciliation.attemptAuthorizationIdentity,
		AttemptOutcomeIdentity:       reconciliation.attemptOutcomeIdentity,
		Status:                       reconciliation.status.String(), ReservedCostMicroUSD: reconciliation.reservedCostMicroUSD,
		ActualKnown: actual.IsKnown(), ActualInputCostMicroUSD: actual.InputCostMicroUSD(), ActualOutputCostMicroUSD: actual.OutputCostMicroUSD(), ActualTotalCostMicroUSD: actual.TotalCostMicroUSD(),
		RemainingAfterReservationMicroUSD: reconciliation.remainingAfterReservationMicroUSD,
		RemainingCostMicroUSD:             reconciliation.remainingCostMicroUSD, BudgetOverrunMicroUSD: reconciliation.budgetOverrunMicroUSD,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
