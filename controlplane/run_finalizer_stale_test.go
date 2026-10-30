package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileFinalizerStaleObservationDefersBeforeIntent(t *testing.T) {
	ctx := context.Background()
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := singleTaskPlan(t, 1)
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	task, _ := plan.Task("source")
	lease, acquired, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(102))
	if err != nil || !acquired {
		t.Fatalf("claim %v/%v", acquired, err)
	}
	before, err := journal.Read(ctx, plan.Scope(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	observed, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), time.UnixMilli(101))
	if err != nil || changed || observed.Status() != ReviewRunActive || observed.HeadIdentity() != before[len(before)-1].Identity() {
		t.Fatalf("stale finalizer changed=%v error=%v", changed, err)
	}
	if _, err = os.Lstat(journal.scopeIntentPath(plan.Scope())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only stale observation poisoned scope: %v", err)
	}
	after, err := journal.Read(ctx, plan.Scope(), 0, 10)
	if err != nil || len(after) != len(before) || after[len(after)-1].Identity() != before[len(before)-1].Identity() {
		t.Fatal("stale observation mutated journal")
	}
	completion, err := NewTaskSuccess("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(103)); err != nil {
		t.Fatal(err)
	}
	state, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), time.UnixMilli(104))
	if err != nil || !changed || state.Status() != ReviewRunSucceeded {
		t.Fatalf("fresh finalizer %v/%v/%v", state.Status(), changed, err)
	}
}
