package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTerminalFinalizerDoesNotCreateIntent(t *testing.T) {
	plan, memory, _ := settledSingleTask(t, 0)
	memFinalizer, err := NewRunFinalizer(memory)
	if err != nil {
		t.Fatal(err)
	}
	terminal, _, err := memFinalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(103))
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
	var previous string
	for _, event := range events {
		if err := journal.Append(context.Background(), previous, event); err != nil {
			t.Fatal(err)
		}
		previous = event.Identity()
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	// A terminal replay must not require writing a new intent.
	if err := os.Chmod(journal.root, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(journal.root, 0700)
	observed, changed, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(104))
	if err != nil || changed || observed.HeadIdentity() != terminal.HeadIdentity() {
		t.Fatalf("terminal read requires effect: changed=%v err=%v", changed, err)
	}
	if _, err := os.Lstat(journal.scopeIntentPath(plan.Scope())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("terminal replay wrote marker: %v", err)
	}
}

func TestTerminalFinalizerPreservesUnresolvedIntent(t *testing.T) {
	plan, memory, _ := settledSingleTask(t, 0)
	coordinator, err := NewCoordinator(memory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.SucceedRun(context.Background(), plan, strings.Repeat("e", 64), time.UnixMilli(103)); err != nil {
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
	marker := []byte("unknown existing effect")
	if err := os.WriteFile(journal.scopeIntentPath(plan.Scope()), marker, 0600); err != nil {
		t.Fatal(err)
	}
	finalizer, err := NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := finalizer.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(104)); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("quarantine bypassed: %v", err)
	}
	retained, err := os.ReadFile(journal.scopeIntentPath(plan.Scope()))
	if err != nil || !bytes.Equal(retained, marker) {
		t.Fatalf("quarantine changed: %v", err)
	}
}
