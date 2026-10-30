package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func staleBoundaryFixture(t *testing.T) (*FileRunJournal, *Coordinator, *RunFinalizer, ReviewRunPlan, TaskLease) {
	t.Helper()
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	plan := singleTaskPlan(t, 1)
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	task, _ := plan.Task("source")
	lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(102))
	if err != nil || !acquired {
		t.Fatalf("claim acquired=%v err=%v", acquired, err)
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	return journal, coordinator, finalizer, plan, lease
}

func staleBoundaryJournal(t *testing.T, journal *FileRunJournal, plan ReviewRunPlan) []byte {
	t.Helper()
	body, err := os.ReadFile(journal.streamPath(plan.Scope()))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func staleBoundaryNoIntent(t *testing.T, journal *FileRunJournal, plan ReviewRunPlan) {
	t.Helper()
	if _, err := os.Lstat(journal.scopeIntentPath(plan.Scope())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected scope intent: %v", err)
	}
}

func TestFileFinalizerInvalidTimeIsNotStaleObservation(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"zero", time.Time{}}, {"epoch", time.UnixMilli(0)}, {"negative", time.UnixMilli(-1)},
		{"above_limit", time.UnixMilli(maxRunEventUnixMilliseconds + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			journal, _, finalizer, plan, _ := staleBoundaryFixture(t)
			before := staleBoundaryJournal(t, journal, plan)
			_, changed, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), tc.at)
			if !errors.Is(err, ErrRunTransitionSequenceMismatch) || errors.Is(err, ErrScopeIntentUnresolved) || changed {
				t.Fatalf("invalid time changed=%v err=%v", changed, err)
			}
			staleBoundaryNoIntent(t, journal, plan)
			if !bytes.Equal(before, staleBoundaryJournal(t, journal, plan)) {
				t.Fatal("invalid time changed journal")
			}
		})
	}
}

func TestFileFinalizerStaleObservationPreservesExistingIntent(t *testing.T) {
	journal, _, finalizer, plan, _ := staleBoundaryFixture(t)
	before := staleBoundaryJournal(t, journal, plan)
	marker := []byte("unknown existing effect")
	path := journal.scopeIntentPath(plan.Scope())
	if err := os.WriteFile(path, marker, 0600); err != nil {
		t.Fatal(err)
	}
	_, changed, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(101))
	if !errors.Is(err, ErrScopeIntentUnresolved) || changed {
		t.Fatalf("quarantine changed=%v err=%v", changed, err)
	}
	retained, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(marker, retained) {
		t.Fatalf("existing intent changed: %v", err)
	}
	if !bytes.Equal(before, staleBoundaryJournal(t, journal, plan)) {
		t.Fatal("existing intent journal changed")
	}
}

func TestFileFinalizerStaleObservationDoesNotExpireLease(t *testing.T) {
	journal, coordinator, finalizer, plan, lease := staleBoundaryFixture(t)
	ctx := context.Background()
	_, beforeState, err := coordinator.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	before := staleBoundaryJournal(t, journal, plan)
	observed, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), time.UnixMilli(101))
	task, found := observed.Task("source")
	if err != nil || changed || !found || observed.Status() != ReviewRunActive || observed.HeadIdentity() != beforeState.HeadIdentity() || observed.Revision() != beforeState.Revision() {
		t.Fatalf("stale observation changed=%v err=%v", changed, err)
	}
	if task.Status() != TaskRuntimeLeased || task.OutputIdentity() != "" || task.Attempts() != lease.Attempt() || !task.LeaseExpiresAt().Equal(lease.ExpiresAt()) {
		t.Fatal("stale observation changed leased task authority")
	}
	staleBoundaryNoIntent(t, journal, plan)
	if !bytes.Equal(before, staleBoundaryJournal(t, journal, plan)) {
		t.Fatal("stale observation changed journal")
	}
	freshAt := lease.ExpiresAt()
	terminal, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), freshAt)
	expired, found := terminal.Task("source")
	if err != nil || !changed || !found || terminal.Status() != ReviewRunFailed || terminal.Failure() != RunFailureResourceLimit || expired.Status() != TaskRuntimeFailed || expired.Failure() != RunFailureResourceLimit || expired.OutputIdentity() != "" || expired.Attempts() != lease.Attempt() {
		t.Fatalf("fresh expiry changed=%v err=%v", changed, err)
	}
	staleBoundaryNoIntent(t, journal, plan)
	events, err := journal.Read(ctx, plan.Scope(), beforeState.Revision(), 10)
	if err != nil || len(events) != 2 || events[0].Kind() != RunEventTaskFailed || events[1].Kind() != RunEventFailed {
		t.Fatalf("fresh expiry events=%d err=%v", len(events), err)
	}
	for _, event := range events {
		if !event.OccurredAt().Equal(freshAt) {
			t.Fatal("expiry used a substituted timestamp")
		}
	}
}

func TestFileFinalizerEqualMillisecondObservationCanFinalize(t *testing.T) {
	journal, coordinator, finalizer, plan, lease := staleBoundaryFixture(t)
	completion, err := NewTaskSuccess("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(103)
	if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at); err != nil {
		t.Fatal(err)
	}
	terminal, changed, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), at.Add(500*time.Nanosecond))
	if err != nil || !changed || terminal.Status() != ReviewRunSucceeded || terminal.LastOccurredAt().UnixMilli() != at.UnixMilli() {
		t.Fatalf("equal millisecond changed=%v err=%v", changed, err)
	}
	staleBoundaryNoIntent(t, journal, plan)
}
