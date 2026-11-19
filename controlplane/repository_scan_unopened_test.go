package controlplane

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRepositoryScansSkipPlanSavedBeforeItsRunOpens(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := singleTaskPlan(t, 1)
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	scheduler, err := NewTaskNotificationScheduler(journal, NewMemoryTaskNotificationQueue())
	if err != nil {
		t.Fatal(err)
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(200)
	if runs, notices, err := scheduler.ReconcileRepository(context.Background(), "tenant", "repository", at); err != nil || runs != 1 || notices != 0 {
		t.Fatalf("scheduler scan=(%d,%d,%v)", runs, notices, err)
	}
	if runs, finalized, err := finalizer.ReconcileRepository(context.Background(), "tenant", "repository", at); err != nil || runs != 1 || finalized != 0 {
		t.Fatalf("finalizer scan=(%d,%d,%v)", runs, finalized, err)
	}
	// Neither scan left a scope intent, so the run still opens.
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatalf("Open() after the scans=%v", err)
	}
}
