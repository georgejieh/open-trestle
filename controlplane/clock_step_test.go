package controlplane

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func clockStepPlan(t *testing.T) ReviewRunPlan {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant", "repository", "run-clock-step")
	task, err := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 100, 60_000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunAdvisory, []TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestRunCompletesAcrossBackwardClockStep(t *testing.T) {
	ctx := context.Background()
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	plan := clockStepPlan(t)
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := plan.Task("source")
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100_000)); err != nil {
		t.Fatal(err)
	}
	claimedAt := time.UnixMilli(102_000)
	lease, acquired, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "worker", claimedAt)
	if err != nil || !acquired {
		t.Fatalf("claim acquired=%v err=%v", acquired, err)
	}

	stepped := claimedAt.Add(-2 * time.Second)
	renewed, _, err := coordinator.RenewTaskLease(ctx, plan, lease, stepped)
	if err != nil || !renewed.ExpiresAt().Equal(lease.ExpiresAt()) {
		t.Fatalf("renewal after step expires=%v err=%v", renewed.ExpiresAt(), err)
	}
	if _, acquired, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "other", stepped.Add(time.Millisecond)); err != nil || acquired {
		t.Fatalf("second claim after step acquired=%v err=%v", acquired, err)
	}
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	if _, err := coordinator.CompleteTask(ctx, plan, renewed, completion, stepped.Add(2*time.Millisecond)); err != nil {
		t.Fatalf("completion after step: %v", err)
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	state, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), stepped.Add(3*time.Millisecond))
	if err != nil || !changed || state.Status() != ReviewRunSucceeded {
		t.Fatalf("finalize after step status=%v changed=%v err=%v", state.Status(), changed, err)
	}

	events, err := journal.Read(ctx, plan.Scope(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 || events[len(events)-1].Kind() != RunEventSucceeded {
		t.Fatalf("events=%d", len(events))
	}
	for _, event := range events[2:] {
		if !event.OccurredAt().Equal(claimedAt) {
			t.Fatalf("%v recorded at %v, want %v", event.Kind(), event.OccurredAt(), claimedAt)
		}
	}
	if _, resumed, err := coordinator.Resume(ctx, plan.Scope()); err != nil || resumed.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("replay after step: %v", err)
	}
}

func TestLargeBackwardClockStepNeitherExpiresNorExtendsLease(t *testing.T) {
	ctx := context.Background()
	plan := clockStepPlan(t)
	coordinator, err := NewCoordinator(NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	task, _ := plan.Task("source")
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(1_800_000_000_000)); err != nil {
		t.Fatal(err)
	}
	claimedAt := time.UnixMilli(1_800_000_002_000)
	lease, acquired, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "worker", claimedAt)
	if err != nil || !acquired {
		t.Fatalf("claim acquired=%v err=%v", acquired, err)
	}
	stepped := claimedAt.Add(-time.Hour)
	renewed, _, err := coordinator.RenewTaskLease(ctx, plan, lease, stepped)
	if err != nil || !renewed.ExpiresAt().Equal(lease.ExpiresAt()) {
		t.Fatalf("renewal after step expires=%v err=%v", renewed.ExpiresAt(), err)
	}
	if _, acquired, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "other", stepped); err != nil || acquired {
		t.Fatalf("claim during step acquired=%v err=%v", acquired, err)
	}
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	if _, err := coordinator.CompleteTask(ctx, plan, renewed, completion, lease.ExpiresAt().Add(time.Millisecond)); err != ErrRunTransitionLeaseMismatch {
		t.Fatalf("completion past recorded expiry err=%v", err)
	}
}
