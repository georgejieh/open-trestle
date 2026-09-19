package controlplane

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"strings"
	"sync"
	"testing"
	"time"
)

func singleTaskPlan(t *testing.T, attempts uint8) ReviewRunPlan {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant", "repository", "run-final")
	task, _ := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, attempts, 100, 1000, true)
	plan, err := NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunAdvisory, []TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func settledSingleTask(t *testing.T, failure RunFailure) (ReviewRunPlan, *MemoryRunJournal, ReviewRunState) {
	t.Helper()
	plan := singleTaskPlan(t, 1)
	journal := NewMemoryRunJournal()
	coordinator, _ := newCoordinator(journal, strings.NewReader(strings.Repeat("a", 128)))
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	task, _ := plan.Task("source")
	lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(101))
	if err != nil || !acquired {
		t.Fatalf("claim=(%v,%v)", acquired, err)
	}
	var completion TaskCompletion
	if failure == 0 {
		completion, _ = NewTaskSuccess(strings.Repeat("e", 64))
	} else {
		completion, _ = NewTaskFailure(failure)
	}
	state, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(102))
	if err != nil {
		t.Fatal(err)
	}
	return plan, journal, state
}
func TestReviewRunStateDerivesTerminalCompletion(t *testing.T) {
	_, _, success := settledSingleTask(t, 0)
	completion, ready, err := success.TerminalCompletion()
	if err != nil || !ready || completion.Status() != TaskCompletionSucceeded || completion.OutputIdentity() != strings.Repeat("e", 64) {
		t.Fatalf("success=(%#v,%v,%v)", completion, ready, err)
	}
	_, _, failed := settledSingleTask(t, RunFailurePolicy)
	completion, ready, err = failed.TerminalCompletion()
	if err != nil || !ready || completion.Status() != TaskCompletionFailed || completion.Failure() != RunFailurePolicy {
		t.Fatalf("failure=(%#v,%v,%v)", completion, ready, err)
	}
}
func TestRunFinalizerConvergesUnderConcurrentReconciliation(t *testing.T) {
	plan, journal, _ := settledSingleTask(t, 0)
	first, _ := NewRunFinalizer(journal)
	second, _ := NewRunFinalizer(journal)
	var wait sync.WaitGroup
	wait.Add(2)
	states := make(chan ReviewRunState, 2)
	errs := make(chan error, 2)
	for _, finalizer := range []*RunFinalizer{first, second} {
		go func(value *RunFinalizer) {
			defer wait.Done()
			state, _, err := value.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(103))
			states <- state
			errs <- err
		}(finalizer)
	}
	wait.Wait()
	close(states)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for state := range states {
		if state.Status() != ReviewRunSucceeded || state.OutputIdentity() != strings.Repeat("e", 64) {
			t.Fatalf("state=%#v", state)
		}
	}
	events, err := journal.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 5 || events[4].Kind() != RunEventSucceeded {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
}
func TestRunFinalizerDoesNotFinalizeRetryableWork(t *testing.T) {
	plan := singleTaskPlan(t, 2)
	journal := NewMemoryRunJournal()
	coordinator, _ := newCoordinator(journal, strings.NewReader(strings.Repeat("a", 128)))
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	task, _ := plan.Task("source")
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(101))
	failure, _ := NewTaskFailure(RunFailureTransient)
	_, _ = coordinator.CompleteTask(context.Background(), plan, lease, failure, time.UnixMilli(102))
	finalizer, _ := NewRunFinalizer(journal)
	state, changed, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(150))
	if err != nil || changed || state.Status() != ReviewRunActive {
		t.Fatalf("result=(%#v,%v,%v)", state, changed, err)
	}
}

func TestRunFinalizerPreservesEarliestRequiredFailureAcrossDependencySkips(t *testing.T) {
	plan := runPlanFixture(t)
	journal := NewMemoryRunJournal()
	coordinator, _ := newCoordinator(journal, strings.NewReader(strings.Repeat("a", 128)))
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	source, _ := plan.Task("source")
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", source.HandlerIdentity(), "worker", time.UnixMilli(101))
	failure, _ := NewTaskFailure(RunFailurePolicy)
	_, _ = coordinator.CompleteTask(context.Background(), plan, lease, failure, time.UnixMilli(102))
	finalizer, _ := NewRunFinalizer(journal)
	state, changed, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(103))
	if err != nil || !changed || state.Status() != ReviewRunFailed || state.Failure() != RunFailurePolicy {
		t.Fatalf("final=(%#v,%v,%v)", state, changed, err)
	}
}
