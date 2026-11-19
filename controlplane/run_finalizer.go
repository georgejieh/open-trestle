package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

var ErrInvalidRunFinalizer = errors.New("invalid review run finalizer")

var errRunAlreadyTerminal = errors.New("review run already terminal")

// RunFinalizer derives terminal disposition solely from the immutable plan and journal.
type RunFinalizer struct {
	journal     RunJournal
	coordinator *Coordinator
}

func NewRunFinalizer(journal RunJournal) (*RunFinalizer, error) {
	if isNilRunJournal(journal) {
		return nil, ErrInvalidRunFinalizer
	}
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidRunFinalizer
	}
	return &RunFinalizer{journal: journal, coordinator: coordinator}, nil
}

// ReconcileRun advances dependency state and records a deterministic terminal event when ready.
func (f *RunFinalizer) ReconcileRun(ctx context.Context, scope audit.ReviewScope, at time.Time) (ReviewRunState, bool, error) {
	if f == nil || isNilRunJournal(f.journal) || f.coordinator == nil || ctx == nil || ctx.Err() != nil || scope.Validate() != nil {
		return ReviewRunState{}, false, ErrInvalidRunFinalizer
	}
	if journal, ok := f.journal.(*FileRunJournal); ok {
		plan, found, err := journal.LoadPlan(ctx, scope)
		if err != nil {
			return ReviewRunState{}, false, err
		}
		if !found {
			return ReviewRunState{}, false, ErrRunNotOpened
		}
		var result ReviewRunState
		var changed bool
		err = journal.WithScopeIntentChecked(ctx, scope, "run-finalize", plan.Identity(), func(inner context.Context) error {
			_, observed, readErr := f.coordinator.Resume(inner, scope)
			if readErr != nil {
				return readErr
			}
			if observed.Status() != ReviewRunActive {
				result = observed
				return errRunAlreadyTerminal
			}
			if _, timely := transitionTime(observed, at); !timely {
				return ErrRunTransitionSequenceMismatch
			}
			return nil
		}, func(inner context.Context) error {
			var operationErr error
			result, changed, operationErr = f.reconcileRun(inner, scope, at)
			return operationErr
		}, func(inner context.Context) error {
			_, observed, readErr := f.coordinator.Resume(inner, scope)
			if readErr != nil || observed.HeadIdentity() != result.HeadIdentity() || observed.Revision() != result.Revision() {
				return errors.Join(ErrRunJournalHeadConflict, readErr)
			}
			return nil
		})
		if err == errRunAlreadyTerminal {
			return result, false, nil
		}
		return result, changed, err
	}
	return f.reconcileRun(ctx, scope, at)
}

func (f *RunFinalizer) reconcileRun(ctx context.Context, scope audit.ReviewScope, at time.Time) (ReviewRunState, bool, error) {
	plan, state, err := f.coordinator.Resume(ctx, scope)
	if err != nil {
		return ReviewRunState{}, false, err
	}
	if state.Status() != ReviewRunActive {
		return state, false, nil
	}
	state, err = f.coordinator.Advance(ctx, plan, at)
	if err != nil {
		return ReviewRunState{}, false, err
	}
	if state.Status() != ReviewRunActive {
		return state, false, nil
	}
	completion, ready, err := state.TerminalCompletion()
	if err != nil || !ready {
		return state, false, err
	}
	var finalized ReviewRunState
	if completion.Status() == TaskCompletionSucceeded {
		finalized, err = f.coordinator.SucceedRun(ctx, plan, completion.OutputIdentity(), at)
	} else {
		finalized, err = f.coordinator.FailRun(ctx, plan, completion.Failure(), at)
	}
	if err != nil {
		return ReviewRunState{}, false, err
	}
	return finalized, finalized.Status() != ReviewRunActive, nil
}

// ReconcileRepository finalizes a bounded tenant and repository plan partition.
func (f *RunFinalizer) ReconcileRepository(ctx context.Context, tenantID, repositoryID string, at time.Time) (int, int, error) {
	if f == nil || isNilRunJournal(f.journal) || f.coordinator == nil || ctx == nil || ctx.Err() != nil || !validRunPlanQuery(tenantID) || !validRunPlanQuery(repositoryID) || !validRunMillis(at.UnixMilli()) {
		return 0, 0, ErrInvalidRunFinalizer
	}
	const pageSize = 100
	const maximumRuns = 10_000
	after := ""
	runs, finalized := 0, 0
	for {
		plans, err := f.journal.ListPlans(ctx, tenantID, repositoryID, after, pageSize)
		if err != nil {
			return runs, finalized, err
		}
		for _, plan := range plans {
			if runs >= maximumRuns {
				return runs, finalized, ErrInvalidRunFinalizer
			}
			_, changed, err := f.ReconcileRun(ctx, plan.Scope(), at)
			if err != nil {
				return runs, finalized, err
			}
			runs++
			if changed {
				finalized++
			}
		}
		if len(plans) < pageSize {
			return runs, finalized, nil
		}
		after = plans[len(plans)-1].Scope().ReviewRunID()
	}
}
func (f *RunFinalizer) String() string   { return "review run finalizer" }
func (f *RunFinalizer) GoString() string { return "controlplane.RunFinalizer{<redacted>}" }
func (f *RunFinalizer) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review run finalizer", "controlplane.RunFinalizer{<redacted>}")
}
