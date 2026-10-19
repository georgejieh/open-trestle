package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFileJournalFinalizerSharesScopeGate(t *testing.T) {
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
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- journal.WithScopeGate(context.Background(), plan.Scope(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waiting, stop, err := journal.WatchEffectGateContention()
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer stop()
	resolved := make(chan error, 1)
	go func() { _, _, err := finalizer.ReconcileRun(ctx, plan.Scope(), time.UnixMilli(101)); resolved <- err }()
	select {
	case <-waiting:
	case <-ctx.Done():
		close(release)
		t.Fatal("finalizer did not wait")
	}
	select {
	case err := <-resolved:
		close(release)
		t.Fatalf("finalizer entered held gate: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-resolved; err != nil {
		t.Fatal(err)
	}
	if err := journal.SavePlan(context.Background(), plan); errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("clean finalizer left quarantine: %v", err)
	}
}
