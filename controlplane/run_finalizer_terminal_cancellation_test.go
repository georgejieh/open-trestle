package controlplane

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type cancelAtFinalizerIntent struct {
	context.Context
	path   string
	cancel context.CancelFunc
}

func (c cancelAtFinalizerIntent) Err() error {
	if _, err := os.Lstat(c.path); err == nil {
		c.cancel()
	}
	return c.Context.Err()
}

func TestTerminalFinalizerCancellationDoesNotCreateQuarantine(t *testing.T) {
	plan, memory, _ := settledSingleTask(t, 0)
	finalizer, err := NewRunFinalizer(memory)
	if err != nil {
		t.Fatal(err)
	}
	terminal, _, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(103))
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	events, err := memory.Read(context.Background(), plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	previous := ""
	for _, event := range events {
		if err := journal.Append(context.Background(), previous, event); err != nil {
			t.Fatal(err)
		}
		previous = event.Identity()
	}
	finalizer, err = NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed, changed, err := finalizer.ReconcileRun(cancelAtFinalizerIntent{ctx, journal.scopeIntentPath(plan.Scope()), cancel}, plan.Scope(), time.UnixMilli(104))
	if err != nil || changed || observed.HeadIdentity() != terminal.HeadIdentity() {
		t.Fatalf("terminal no-op crosses cancellation effect boundary: changed=%v err=%v", changed, err)
	}
	if _, err := os.Lstat(journal.scopeIntentPath(plan.Scope())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal no-op left marker: %v", err)
	}
	head, present, err := journal.Head(context.Background(), plan.Scope())
	if err != nil || !present || head.Identity() != terminal.HeadIdentity() {
		t.Fatalf("terminal journal changed: %v", err)
	}
}
