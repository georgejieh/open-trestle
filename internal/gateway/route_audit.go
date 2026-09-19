package gateway

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const maxRouteAuditAppendConflicts = 16

var (
	// ErrInvalidRouteAuditLedger identifies a missing audit ledger.
	ErrInvalidRouteAuditLedger = errors.New("invalid route audit ledger")
	// ErrRouteAuditScopeMismatch identifies a route record from another tenant-owned review scope.
	ErrRouteAuditScopeMismatch = errors.New("route audit scope mismatch")
	// ErrRouteAuditRecordMismatch identifies cross-wired route execution records.
	ErrRouteAuditRecordMismatch = errors.New("route audit record mismatch")
	// ErrRouteAuditPrerequisiteMissing identifies an out-of-order route state transition.
	ErrRouteAuditPrerequisiteMissing = errors.New("route audit prerequisite missing")
	// ErrRouteAuditAppendConflict identifies sustained concurrent changes to one review stream.
	ErrRouteAuditAppendConflict = errors.New("route audit append conflict")
	// ErrRouteAuditTerminalConflict identifies a second terminal record for one authorization.
	ErrRouteAuditTerminalConflict = errors.New("route audit terminal conflict")
)

// RecordRouteSelection appends an idempotent selection event to its exact review scope.
func RecordRouteSelection(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, selection RouteSelectionReceipt, occurredAt time.Time) (audit.Event, error) {
	if err := validateRouteAuditInputs(ledger, scope); err != nil {
		return audit.Event{}, err
	}
	if err := selection.Validate(); err != nil {
		return audit.Event{}, err
	}
	if selection.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, ErrRouteAuditScopeMismatch
	}
	parents := []string{selection.RoutingInputIdentity(), selection.SelectedRecordIdentity(), selection.RankingPolicyIdentity()}
	event, _, err := appendUniqueRouteAuditEvent(ctx, ledger, scope, audit.EventRouteSelected, selection.Identity(), parents, "", occurredAt)
	return event, err
}

// ClaimRouteAttempt atomically records one idempotent dispatch claim after its selection.
func ClaimRouteAttempt(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization RouteAttemptAuthorization, occurredAt time.Time) (audit.Event, bool, error) {
	if err := validateRouteAuditInputs(ledger, scope); err != nil {
		return audit.Event{}, false, err
	}
	if err := authorization.Validate(); err != nil {
		return audit.Event{}, false, err
	}
	if authorization.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, false, ErrRouteAuditScopeMismatch
	}
	if err := requireRouteAuditEvent(ctx, ledger, scope, audit.EventRouteSelected, authorization.SelectionReceiptIdentity()); err != nil {
		return audit.Event{}, false, err
	}
	parents := []string{authorization.SelectionReceiptIdentity()}
	if authorization.PreviousOutcomeIdentity() != "" {
		parents = append(parents, authorization.PreviousOutcomeIdentity(), authorization.ContinuationDecisionIdentity())
	}
	return appendUniqueRouteAuditEvent(ctx, ledger, scope, audit.EventRouteAttemptClaimed, authorization.Identity(), parents, "", occurredAt)
}

// RecordRouteDispatchCompleted appends a terminal outcome only after its authorization claim.
func RecordRouteDispatchCompleted(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization RouteAttemptAuthorization, result RouteDispatchResult, outcome RouteAttemptOutcome, occurredAt time.Time) (audit.Event, error) {
	if err := validateRouteAuditInputs(ledger, scope); err != nil {
		return audit.Event{}, err
	}
	if err := authorization.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := result.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := outcome.Validate(); err != nil {
		return audit.Event{}, err
	}
	if authorization.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, ErrRouteAuditScopeMismatch
	}
	if result.AuthorizationIdentity() != authorization.Identity() || outcome.AuthorizationIdentity() != authorization.Identity() {
		return audit.Event{}, ErrRouteAuditRecordMismatch
	}
	if result.Status() == RouteDispatchSucceeded {
		if outcome.Status() != RouteAttemptSucceeded || outcome.ResponseIdentity() != result.Response().Identity() || outcome.Usage() != result.Usage() {
			return audit.Event{}, ErrRouteAuditRecordMismatch
		}
	} else if outcome.Status() != RouteAttemptFailed || outcome.ResponseIdentity() != "" || outcome.Failure() != result.Failure() || outcome.ReplaySafety() != result.ReplaySafety() || outcome.RetryAfterMilliseconds() != result.RetryAfterMilliseconds() || outcome.Usage() != result.Usage() {
		return audit.Event{}, ErrRouteAuditRecordMismatch
	}
	if err := requireRouteAuditEvent(ctx, ledger, scope, audit.EventRouteAttemptClaimed, authorization.Identity()); err != nil {
		return audit.Event{}, err
	}
	parents := []string{authorization.Identity(), result.Identity()}
	if result.Status() == RouteDispatchSucceeded {
		parents = append(parents, result.Response().Identity())
	}
	event, _, err := appendUniqueRouteAuditEvent(ctx, ledger, scope, audit.EventRouteDispatchCompleted, outcome.Identity(), parents, authorization.Identity(), occurredAt)
	return event, err
}

// RecordRouteCostReconciliation appends settled cost only after its terminal outcome.
func RecordRouteCostReconciliation(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, occurredAt time.Time) (audit.Event, error) {
	if err := validateRouteAuditInputs(ledger, scope); err != nil {
		return audit.Event{}, err
	}
	if err := validateAttemptAndOutcome(authorization, outcome); err != nil {
		return audit.Event{}, err
	}
	if err := reconciliation.Validate(); err != nil {
		return audit.Event{}, err
	}
	if authorization.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, ErrRouteAuditScopeMismatch
	}
	if reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() {
		return audit.Event{}, ErrRouteAuditRecordMismatch
	}
	if err := requireRouteAuditEvent(ctx, ledger, scope, audit.EventRouteDispatchCompleted, outcome.Identity()); err != nil {
		return audit.Event{}, err
	}
	parents := []string{authorization.Identity(), outcome.Identity()}
	event, _, err := appendUniqueRouteAuditEvent(ctx, ledger, scope, audit.EventRouteCostReconciled, reconciliation.Identity(), parents, outcome.Identity(), occurredAt)
	return event, err
}

// RecordRouteContinuationPlan appends the deterministic next action after cost settlement.
func RecordRouteContinuationPlan(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization RouteAttemptAuthorization, outcome RouteAttemptOutcome, reconciliation RouteCostReconciliation, plan RouteContinuationPlan, occurredAt time.Time) (audit.Event, error) {
	if err := validateRouteAuditInputs(ledger, scope); err != nil {
		return audit.Event{}, err
	}
	if err := authorization.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := outcome.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := reconciliation.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := plan.Validate(); err != nil {
		return audit.Event{}, err
	}
	if authorization.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, ErrRouteAuditScopeMismatch
	}
	if outcome.AuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() || plan.AuthorizationIdentity() != authorization.Identity() || plan.OutcomeIdentity() != outcome.Identity() || plan.ReconciliationIdentity() != reconciliation.Identity() {
		return audit.Event{}, ErrRouteAuditRecordMismatch
	}
	if err := requireRouteAuditEvent(ctx, ledger, scope, audit.EventRouteCostReconciled, reconciliation.Identity()); err != nil {
		return audit.Event{}, err
	}
	parents := []string{authorization.Identity(), outcome.Identity(), reconciliation.Identity()}
	if next := plan.NextAuthorization(); next.Identity() != "" {
		parents = append(parents, next.Identity())
	}
	event, _, err := appendUniqueRouteAuditEvent(ctx, ledger, scope, audit.EventRouteContinuationPlanned, plan.Identity(), parents, reconciliation.Identity(), occurredAt)
	return event, err
}

func validateRouteAuditInputs(ledger audit.Ledger, scope audit.ReviewScope) error {
	if isNilAuditLedger(ledger) {
		return ErrInvalidRouteAuditLedger
	}
	return scope.Validate()
}

func isNilAuditLedger(ledger audit.Ledger) bool {
	if ledger == nil {
		return true
	}
	value := reflect.ValueOf(ledger)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func requireRouteAuditEvent(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, kind audit.EventKind, subjectIdentity string) error {
	_, exists, err := findRouteAuditEvent(ctx, ledger, scope, kind, subjectIdentity)
	if err != nil {
		return err
	}
	if !exists {
		return ErrRouteAuditPrerequisiteMissing
	}
	return nil
}

func appendUniqueRouteAuditEvent(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, kind audit.EventKind, subjectIdentity string, parents []string, uniqueParent string, occurredAt time.Time) (audit.Event, bool, error) {
	for range maxRouteAuditAppendConflicts {
		before, hadBefore, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, false, err
		}
		existing, found, conflict, err := inspectRouteAuditEvents(ctx, ledger, scope, kind, subjectIdentity, uniqueParent)
		if err != nil {
			return audit.Event{}, false, err
		}
		if found {
			return existing, false, nil
		}
		if conflict {
			return audit.Event{}, false, ErrRouteAuditTerminalConflict
		}
		head, hasHead, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, false, err
		}
		if hadBefore != hasHead || hadBefore && before.Identity() != head.Identity() {
			continue
		}
		sequence, previous := uint64(1), ""
		if hasHead {
			sequence, previous = head.Sequence()+1, head.Identity()
		}
		event, err := audit.NewEvent(scope, sequence, previous, kind, subjectIdentity, parents, occurredAt)
		if err != nil {
			return audit.Event{}, false, err
		}
		err = ledger.Append(ctx, previous, event)
		if err == nil {
			return event, true, nil
		}
		if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, false, err
		}
	}
	return audit.Event{}, false, ErrRouteAuditAppendConflict
}

func inspectRouteAuditEvents(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, kind audit.EventKind, subjectIdentity, uniqueParent string) (audit.Event, bool, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, false, err
		}
		for _, event := range events {
			if event.Kind() != kind {
				continue
			}
			if event.SubjectIdentity() == subjectIdentity {
				return event, true, false, nil
			}
			if uniqueParent != "" && auditEventReferences(event, uniqueParent) {
				return audit.Event{}, false, true, nil
			}
		}
		if len(events) < 1_000 {
			return audit.Event{}, false, false, nil
		}
		after = events[len(events)-1].Sequence()
	}
}

func auditEventReferences(event audit.Event, identity string) bool {
	for _, parent := range event.CausalParentIdentities() {
		if parent == identity {
			return true
		}
	}
	return false
}

func findRouteAuditEvent(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, kind audit.EventKind, subjectIdentity string) (audit.Event, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, err
		}
		for _, event := range events {
			if event.Kind() == kind && event.SubjectIdentity() == subjectIdentity {
				return event, true, nil
			}
		}
		if len(events) < 1_000 {
			return audit.Event{}, false, nil
		}
		after = events[len(events)-1].Sequence()
		if after == 0 {
			return audit.Event{}, false, fmt.Errorf("read route audit stream: %w", ErrRouteAuditRecordMismatch)
		}
	}
}
