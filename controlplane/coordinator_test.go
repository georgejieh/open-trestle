package controlplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCoordinatorOpensAdvancesAndClaimsExactlyOnce(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	state, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil || state.Status() != ReviewRunActive || state.Revision() != 1 {
		t.Fatalf("open=(%#v,%v)", state, err)
	}
	state, err = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	if err != nil {
		t.Fatal(err)
	}
	if lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("e", 64), "worker-1", time.UnixMilli(120)); !errors.Is(err, ErrInvalidReviewTaskHandler) || acquired || lease.Identity() != "" {
		t.Fatalf("wrong handler claim=(%#v,%t,%v)", lease, acquired, err)
	}
	source, _ := state.Task("source")
	if source.Status() != TaskRuntimeAvailable {
		t.Fatalf("source=%#v", source)
	}
	leases := make(chan TaskLease, 2)
	acquiredValues := make(chan bool, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-1", time.UnixMilli(200))
			leases <- lease
			acquiredValues <- acquired
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(leases)
	close(acquiredValues)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	acquiredCount, leaseCount := 0, 0
	var lease TaskLease
	for acquired := range acquiredValues {
		if acquired {
			acquiredCount++
		}
	}
	for candidate := range leases {
		if candidate.Identity() != "" {
			leaseCount++
			lease = candidate
		}
	}
	if acquiredCount != 1 || leaseCount != 1 || lease.Validate() != nil || lease.TaskKey() != "source" || lease.Attempt() != 1 {
		t.Fatalf("claims acquired=%d leases=%d lease=%#v", acquiredCount, leaseCount, lease)
	}
}

func TestCoordinatorRejectsExpiredWorkerAfterLeaseRecovery(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	first, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-1", time.UnixMilli(200))
	if err != nil || !acquired {
		t.Fatal("first lease unavailable")
	}
	recovered, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-2", first.ExpiresAt().Add(time.Millisecond))
	if err != nil || !acquired || recovered.Attempt() != 2 {
		t.Fatalf("recovered=(%#v,%t,%v)", recovered, acquired, err)
	}
	success, _ := NewTaskSuccess(strings.Repeat("e", 64))
	if state, err := coordinator.CompleteTask(context.Background(), plan, first, success, first.ExpiresAt().Add(-time.Millisecond)); !errors.Is(err, ErrRunTransitionLeaseMismatch) || state.Revision() != 0 {
		t.Fatalf("stale completion=(%#v,%v)", state, err)
	}
	state, err := coordinator.CompleteTask(context.Background(), plan, recovered, success, recovered.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	source, _ := state.Task("source")
	if source.Status() != TaskRuntimeSucceeded || source.Attempts() != 2 {
		t.Fatalf("source=%#v", source)
	}
}

func TestCoordinatorRetriesOnlyAfterPlanDelay(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker", time.UnixMilli(200))
	failure, _ := NewTaskFailure(RunFailureTransient)
	failedAt := time.UnixMilli(300)
	state, err := coordinator.CompleteTask(context.Background(), plan, lease, failure, failedAt)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := state.Task("source")
	wantRetry := failedAt.Add(time.Duration(source.Definition().RetryDelayMilliseconds()) * time.Millisecond)
	if source.Status() != TaskRuntimeFailed || !source.RetryAt().Equal(wantRetry) {
		t.Fatalf("source=%#v want retry %v", source, wantRetry)
	}
	state, err = coordinator.Advance(context.Background(), plan, wantRetry.Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	source, _ = state.Task("source")
	if source.Status() != TaskRuntimeFailed {
		t.Fatal("task became available early")
	}
	state, err = coordinator.Advance(context.Background(), plan, wantRetry)
	if err != nil {
		t.Fatal(err)
	}
	source, _ = state.Task("source")
	if source.Status() != TaskRuntimeAvailable {
		t.Fatalf("source=%#v", source)
	}
}

func TestCoordinatorRenewsOnlyCurrentLiveLease(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker", time.UnixMilli(200))
	renewed, state, err := coordinator.RenewTaskLease(context.Background(), plan, lease, time.UnixMilli(500))
	if err != nil || renewed.ExpiresAt().Before(lease.ExpiresAt()) || state.Revision() != 4 {
		t.Fatalf("renew=(%#v,%#v,%v)", renewed, state, err)
	}
	forged := lease
	forged.token = "bad"
	if renewed, state, err := coordinator.RenewTaskLease(context.Background(), plan, forged, time.UnixMilli(600)); !errors.Is(err, ErrInvalidTaskLease) || renewed.Identity() != "" || state.Revision() != 0 {
		t.Fatalf("forged renew=(%#v,%#v,%v)", renewed, state, err)
	}
}

func TestCoordinatorFinalizesSuccessfulRunAndRejectsPrematureSuccess(t *testing.T) {
	task, _ := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 0, 1_000, true)
	plan, _ := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, []TaskDefinition{task})
	coordinator, _ := NewCoordinator(NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if state, err := coordinator.SucceedRun(context.Background(), plan, strings.Repeat("f", 64), time.UnixMilli(110)); !errors.Is(err, ErrRunTransitionInvalid) || state.Revision() != 0 {
		t.Fatalf("premature success=(%#v,%v)", state, err)
	}
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker", time.UnixMilli(200))
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	_, _ = coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(300))
	if _, err := coordinator.SucceedRun(context.Background(), plan, strings.Repeat("f", 64), time.UnixMilli(400)); !errors.Is(err, ErrRunTransitionInvalid) {
		t.Fatalf("foreign output=%v", err)
	}
	state, err := coordinator.SucceedRun(context.Background(), plan, strings.Repeat("e", 64), time.UnixMilli(400))
	if err != nil || state.Status() != ReviewRunSucceeded || state.OutputIdentity() != strings.Repeat("e", 64) {
		t.Fatalf("success=(%#v,%v)", state, err)
	}
	again, err := coordinator.SucceedRun(context.Background(), plan, strings.Repeat("e", 64), time.UnixMilli(500))
	if err != nil || again.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("idempotent success=(%#v,%v)", again, err)
	}
}
func TestCoordinatorPropagatesTerminalDependencyFailure(t *testing.T) {
	plan := runPlanFixture(t)
	coordinator, _ := NewCoordinator(NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker", time.UnixMilli(200))
	failure, _ := NewTaskFailure(RunFailurePolicy)
	_, _ = coordinator.CompleteTask(context.Background(), plan, lease, failure, time.UnixMilli(300))
	if _, err := coordinator.FailRun(context.Background(), plan, RunFailureDependency, time.UnixMilli(400)); !errors.Is(err, ErrRunTransitionInvalid) {
		t.Fatalf("foreign failure=%v", err)
	}
	state, err := coordinator.FailRun(context.Background(), plan, RunFailurePolicy, time.UnixMilli(400))
	if err != nil || state.Status() != ReviewRunFailed || state.Failure() != RunFailurePolicy {
		t.Fatalf("failed run=(%#v,%v)", state, err)
	}
	change, _ := state.Task("change")
	if change.Status() != TaskRuntimeSkipped {
		t.Fatalf("change=%#v", change)
	}
}
func TestCoordinatorCancellationInvalidatesLease(t *testing.T) {
	plan := runPlanFixture(t)
	coordinator, _ := NewCoordinator(NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker", time.UnixMilli(200))
	state, err := coordinator.CancelRun(context.Background(), plan, time.UnixMilli(300))
	if err != nil || state.Status() != ReviewRunCanceled {
		t.Fatalf("cancel=(%#v,%v)", state, err)
	}
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	if result, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(400)); !errors.Is(err, ErrTaskAlreadyCompleted) && !errors.Is(err, ErrRunTransitionLeaseMismatch) && !errors.Is(err, ErrRunAlreadyTerminal) {
		t.Fatalf("completion after cancel=(%#v,%v)", result, err)
	}
}

func TestCoordinatorResumesStoredPlanWithoutCallerCopy(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	opened, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	resumedPlan, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil || resumedPlan.Identity() != plan.Identity() || state.HeadIdentity() != opened.HeadIdentity() {
		t.Fatalf("resume=(%#v,%#v,%v)", resumedPlan, state, err)
	}
}
