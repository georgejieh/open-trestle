package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalScopeGateNestedAppendBlocksOtherCoordinators(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- journal.WithScopeGate(context.Background(), plan.Scope(), func(ctx context.Context) error {
			close(entered)
			<-release
			return journal.Append(ctx, "", opened)
		})
	}()
	<-entered
	if err := journal.Append(context.Background(), "", opened); !errors.Is(err, ErrScopeGateBusy) {
		t.Fatalf("unscoped append=%v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestJournalScopeGateNestedEffectSectionAndRetiredContext(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	var retained context.Context
	if err := journal.WithScopeGate(context.Background(), plan.Scope(), func(ctx context.Context) error {
		retained = ctx
		return journal.WithEffectSection(ctx, func() error { return journal.Append(ctx, "", opened) })
	}); err != nil {
		t.Fatal(err)
	}
	if journal.insideScopeGate(retained) {
		t.Fatal("retained callback still live")
	}
}

func TestJournalScopeGateCancellationWaitsForNestedAppend(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := journal.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	canceled := canceledFileEvent(t, plan, opened)
	entered, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- journal.WithScopeGate(context.Background(), plan.Scope(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	waiting := make(chan struct{}, 1)
	journal.onContendedGateWait = func() { waiting <- struct{}{} }
	canceledDone := make(chan error, 1)
	go func() { canceledDone <- journal.Append(ctx, opened.Identity(), canceled) }()
	select {
	case <-waiting:
	case <-ctx.Done():
		t.Fatal("cancel never waited")
	}
	select {
	case err := <-canceledDone:
		t.Fatalf("canceled early: %v", err)
	default:
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if err := <-canceledDone; err != nil {
		t.Fatal(err)
	}
}

func TestJournalScopeGateRetainedContextCannotAppendAfterExit(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := runPlanFixture(t)
	var retained context.Context
	if err := journal.WithScopeGate(context.Background(), plan.Scope(), func(ctx context.Context) error { retained = ctx; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := journal.Append(retained, "", runOpenedEventFixture(t, plan)); !errors.Is(err, ErrScopeGateBusy) {
		t.Fatalf("retained grant allowed append: %v", err)
	}
}

func TestJournalScopeGateCloseWaitsForEffect(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	sectionDone := make(chan error, 1)
	go func() {
		sectionDone <- journal.WithScopeGate(context.Background(), plan.Scope(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	closeDone := make(chan error, 1)
	go func() { closeDone <- journal.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("closed before effect returned: %v", err)
	default:
	}
	close(release)
	if err := <-sectionDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestJournalScopeGateCoversDistinctCoordinatorAdvance(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	first, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	if _, err := first.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- journal.WithScopeGate(context.Background(), plan.Scope(), func(ctx context.Context) error {
			close(entered)
			<-release
			_, err := first.Advance(ctx, plan, time.UnixMilli(101))
			return err
		})
	}()
	<-entered
	_, err = second.Advance(context.Background(), plan, time.UnixMilli(101))
	if !errors.Is(err, ErrScopeGateBusy) {
		t.Fatalf("second coordinator advanced=%v", err)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
