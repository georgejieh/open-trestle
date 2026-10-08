package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/filelock"
	"path/filepath"
	"testing"
	"time"
)

func canceledFileEvent(t *testing.T, plan ReviewRunPlan, opened RunEvent) RunEvent {
	t.Helper()
	event, err := NewRunEvent(plan, 2, opened.Identity(), RunEventCanceled, TaskDefinition{}, 0, "", "", time.Time{}, "", RunFailureCanceled, time.Time{}, time.UnixMilli(120))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestFileRunJournalEffectSectionSerializesDirectCancellation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := j.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	canceled := canceledFileEvent(t, plan, opened)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	held := make(chan struct{})
	release := make(chan struct{})
	sectionResult := make(chan error, 1)
	go func() {
		sectionResult <- j.WithEffectSection(ctx, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	select {
	case <-held:
	case <-ctx.Done():
		t.Fatal("section did not enter")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	contended := make(chan struct{}, 1)
	j.onContendedGateWait = func() { contended <- struct{}{} }
	appendResult := make(chan error, 1)
	go func() { appendResult <- j.Append(ctx, opened.Identity(), canceled) }()
	select {
	case <-contended:
	case <-ctx.Done():
		t.Fatal("cancellation did not reach contended gate")
	}
	events, err := j.Read(ctx, plan.Scope(), 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events during section=%d, %v", len(events), err)
	}
	select {
	case err := <-appendResult:
		t.Fatalf("cancellation completed during section: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-appendResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("cancellation did not finish after release")
	}
	select {
	case err := <-sectionResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("effect did not finish after release")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	events, err = reopened.Read(ctx, plan.Scope(), 0, 10)
	if err != nil || len(events) != 2 || events[1].Identity() != canceled.Identity() {
		t.Fatalf("reopened cancellation=%d, %v", len(events), err)
	}
}

func TestFileRunJournalCanceledWaiterTimeoutHasNoLateAppend(t *testing.T) {
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := j.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- j.WithEffectSection(ctx, func() error { close(entered); <-release; return nil }) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("section did not enter")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	waitCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	contended := make(chan struct{}, 1)
	j.onContendedGateWait = func() { contended <- struct{}{} }
	result := make(chan error, 1)
	canceled := canceledFileEvent(t, plan, opened)
	go func() { result <- j.Append(waitCtx, opened.Identity(), canceled) }()
	select {
	case <-contended:
	case <-ctx.Done():
		t.Fatal("timed waiter did not reach contended gate")
	}
	select {
	case err := <-result:
		t.Fatalf("waiter returned early: %v", err)
	default:
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrRunJournalContextDone) {
			t.Fatalf("waiter=%v", err)
		}
	case <-ctx.Done():
		t.Fatal("waiter did not stop")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("effect did not finish after release")
	}
	events, err := j.Read(ctx, plan.Scope(), 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("late cancellation: events=%d, %v", len(events), err)
	}
}

func TestFileRunJournalCloseDrainsEffectBeforeReleasingWriter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	entered := make(chan struct{})
	release := make(chan struct{})
	effectDone := make(chan error, 1)
	go func() { effectDone <- j.WithEffectSection(ctx, func() error { close(entered); <-release; return nil }) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("section did not enter")
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		_ = j.Close()
	}()
	closeDone := make(chan error, 1)
	go func() { closeDone <- j.Close() }()
	select {
	case <-j.closingSignal:
	case <-ctx.Done():
		t.Fatal("Close did not mark closing")
	}
	if _, err := NewFileRunJournal(root); !errors.Is(err, ErrRunJournalLocked) {
		t.Fatalf("writer lock released during effect: %v", err)
	}
	if err := j.WithEffectSection(ctx, func() error { return nil }); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("new effect during close=%v", err)
	}
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := j.Append(ctx, opened.Identity(), canceledFileEvent(t, plan, opened)); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("cancellation during close=%v", err)
	}
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned during effect: %v", err)
	default:
	}
	close(release)
	select {
	case err := <-effectDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("effect did not finish after release")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("Close did not finish")
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}

func TestFileRunJournalEffectAllowsOrdinaryJournalOperations(t *testing.T) {
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := j.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	available := taskAvailableEventFixture(t, plan, "source", 2, opened.Identity())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = j.WithEffectSection(ctx, func() error {
		if err := j.Append(ctx, opened.Identity(), available); err != nil {
			return err
		}
		events, err := j.Read(ctx, plan.Scope(), 0, 10)
		if err != nil {
			return err
		}
		if len(events) != 2 || events[1].Identity() != available.Identity() {
			return errors.New("ordinary journal operations did not complete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The injected close releases the real advisory lease before reporting a failure.
// A former owner must never remain usable after that error.
func TestFileRunJournalFailedLockCloseRetiresOldOwner(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := j.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	available := taskAvailableEventFixture(t, plan, "source", 2, opened.Identity())
	released := false
	j.closeLock = func(lock *filelock.Lock) error {
		if err := lock.Close(); err != nil {
			return err
		}
		released = true
		return fmt.Errorf("injected close error")
	}
	if err := j.Close(); !errors.Is(err, ErrRunJournalPersistence) {
		t.Fatalf("Close=%v", err)
	}
	if !released {
		t.Fatal("lease was not released")
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatalf("second owner after release: %v", err)
	}
	defer reopened.Close()
	if err := j.Append(context.Background(), opened.Identity(), available); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("old Append=%v", err)
	}
	if _, err := j.Read(context.Background(), plan.Scope(), 0, 10); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("old Read=%v", err)
	}
	if err := j.SavePlan(context.Background(), plan); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("old SavePlan=%v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("idempotent Close=%v", err)
	}
	events, err := reopened.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 1 || events[0].Identity() != opened.Identity() {
		t.Fatalf("new owner events=%d, %v", len(events), err)
	}
}

func TestFileRunJournalZeroValueCloseRejects(t *testing.T) {
	var j FileRunJournal
	if err := j.Close(); !errors.Is(err, ErrInvalidRunJournal) {
		t.Fatalf("Close=%v", err)
	}
}

func TestFileRunJournalZeroValueEffectAndCancellationReject(t *testing.T) {
	var j FileRunJournal
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := j.WithEffectSection(ctx, func() error { t.Error("zero-value callback ran"); return nil }); !errors.Is(err, ErrInvalidRunJournal) {
		t.Fatalf("WithEffectSection=%v", err)
	}
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := j.Append(ctx, opened.Identity(), canceledFileEvent(t, plan, opened)); !errors.Is(err, ErrInvalidRunJournal) {
		t.Fatalf("canceled Append=%v", err)
	}
}

func TestFileRunJournalCloseSyncFailureStillReleasesOwner(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	syncedWhileLocked := false
	j.syncOnClose = func() error {
		if other, err := NewFileRunJournal(root); !errors.Is(err, ErrRunJournalLocked) {
			if other != nil {
				_ = other.Close()
			}
			return fmt.Errorf("writer lock lost before directory sync: %v", err)
		}
		syncedWhileLocked = true
		return fmt.Errorf("%w: injected directory sync error", ErrRunJournalPersistence)
	}
	if err := j.Close(); !errors.Is(err, ErrRunJournalPersistence) {
		t.Fatalf("Close=%v", err)
	}
	if !syncedWhileLocked {
		t.Fatal("sync was skipped")
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatalf("writer lock not released after sync failure: %v", err)
	}
	defer reopened.Close()
	if err := j.WithEffectSection(context.Background(), func() error { t.Error("old effect ran"); return nil }); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("old effect=%v", err)
	}
}
