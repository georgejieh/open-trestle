package controlplane

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

var ErrInvalidRunFinalizer = errors.New("invalid review run finalizer")

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
