package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func TestFileRunJournalCanceledPostRenameErrorRetainsVisibleHeadAfterReopen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release := make(chan struct{})
	sectionResult := make(chan error, 1)
	type cancellationResult struct {
		state ReviewRunState
		err   error
	}
	cancelResult := make(chan cancellationResult, 1)
	sectionStarted, cancellationStarted := false, false
	sectionJoined, cancellationJoined, journalClosed := false, false, false
	var unsubscribe func()
	defer func() {
		// Release first and join both workers before touching the plain hook or closing.
		select {
		case <-release:
		default:
			close(release)
		}
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		joinedSafely := true
		if sectionStarted && !sectionJoined {
			select {
			case err := <-sectionResult:
				if err != nil {
					t.Errorf("section cleanup: %v", err)
				}
			case <-cleanupCtx.Done():
				joinedSafely = false
				t.Error("section did not join; journal left open for safety")
			}
			sectionJoined = true
		}
		if cancellationStarted && !cancellationJoined {
			select {
			case result := <-cancelResult:
				if result.err == nil {
					t.Error("cancellation cleanup returned without injected error")
				}
			case <-cleanupCtx.Done():
				joinedSafely = false
				t.Error("cancellation did not join; journal left open for safety")
			}
			cancellationJoined = true
		}
		if !joinedSafely {
			return
		}
		journal.afterCanceledStreamRename = nil
		if unsubscribe != nil {
			unsubscribe()
		}
		if !journalClosed {
			if err := journal.Close(); err != nil {
				t.Errorf("journal close: %v", err)
			}
		}
	}()
	coordinator, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	openedState, err := coordinator.Open(ctx, plan, time.UnixMilli(100))
	if err != nil || openedState.Status() != ReviewRunActive || openedState.Revision() != 1 {
		t.Fatalf("open: state=%#v err=%v", openedState, err)
	}
	opened := runOpenedEventFixture(t, plan)
	if openedState.HeadIdentity() != opened.Identity() {
		t.Fatalf("opened head=%s expected=%s", openedState.HeadIdentity(), opened.Identity())
	}
	injected := errors.New("injected canceled stream post-rename error")
	hookCalls, wrongScope := 0, false
	journal.afterCanceledStreamRename = func(scope audit.ReviewScope) error {
		hookCalls++
		if scope.Identity() != plan.Scope().Identity() {
			wrongScope = true
			return nil
		}
		return injected
	}
	contention, stopWatching, err := journal.WatchEffectGateContention()
	if err != nil {
		t.Fatal(err)
	}
	unsubscribe = stopWatching
	entered := make(chan struct{})
	sectionStarted = true
	go func() {
		sectionResult <- journal.WithEffectSection(ctx, func() error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("section did not enter")
	}
	cancellationStarted = true
	go func() {
		state, err := coordinator.CancelRun(ctx, plan, time.UnixMilli(120))
		cancelResult <- cancellationResult{state, err}
	}()
	select {
	case <-contention:
	case <-ctx.Done():
		t.Fatal("cancellation did not contend for effect gate")
	}
	during, err := journal.Read(ctx, plan.Scope(), 0, 10)
	if err != nil || len(during) != 1 {
		t.Fatalf("events before release: count=%d err=%v", len(during), err)
	}
	if during[0].Identity() != opened.Identity() || during[0].Kind() != RunEventOpened {
		t.Fatal("opened event changed before release")
	}
	select {
	case result := <-cancelResult:
		cancellationJoined = true
		t.Fatalf("cancellation returned before release: %v", result.err)
	default:
	}
	close(release)
	select {
	case err := <-sectionResult:
		sectionJoined = true
		if err != nil {
			t.Fatalf("section: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("section did not finish")
	}
	var result cancellationResult
	select {
	case result = <-cancelResult:
		cancellationJoined = true
	case <-ctx.Done():
		t.Fatal("cancellation did not finish")
	}
	if hookCalls != 1 || wrongScope {
		t.Fatalf("hook calls=%d wrong scope=%t", hookCalls, wrongScope)
	}
	if !reflect.DeepEqual(result.state, ReviewRunState{}) || !errors.Is(result.err, ErrRunJournalPersistence) || !errors.Is(result.err, injected) {
		t.Fatalf("cancellation returned state=%#v err=%v", result.state, result.err)
	}
	journal.afterCanceledStreamRename = nil
	unsubscribe()
	unsubscribe = nil
	if err := journal.Close(); err != nil {
		journalClosed = true
		t.Fatalf("journal close: %v", err)
	}
	journalClosed = true
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("reopened close: %v", err)
		}
	}()
	events, err := reopened.Read(ctx, plan.Scope(), 0, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("reopened events: count=%d err=%v", len(events), err)
	}
	canceled := canceledFileEvent(t, plan, opened)
	if events[0].Validate() != nil || events[0].Identity() != opened.Identity() || events[0].Kind() != RunEventOpened || events[0].Sequence() != 1 || events[0].PreviousIdentity() != "" || !events[0].OccurredAt().Equal(time.UnixMilli(100)) || events[0].PlanIdentity() != plan.Identity() || events[0].Scope().Identity() != plan.Scope().Identity() {
		t.Fatal("reopened opened event mismatch")
	}
	if events[1].Validate() != nil || events[1].Identity() != canceled.Identity() || events[1].Kind() != RunEventCanceled || events[1].Sequence() != 2 || events[1].PreviousIdentity() != opened.Identity() || !events[1].OccurredAt().Equal(time.UnixMilli(120)) || events[1].Failure() != RunFailureCanceled || events[1].OutputIdentity() != "" || events[1].PlanIdentity() != plan.Identity() || events[1].Scope().Identity() != plan.Scope().Identity() {
		t.Fatal("reopened canceled event mismatch")
	}
	restarted, err := NewCoordinator(reopened)
	if err != nil {
		t.Fatal(err)
	}
	resumedPlan, state, err := restarted.Resume(ctx, plan.Scope())
	if err != nil || resumedPlan.Identity() != plan.Identity() || state.Status() != ReviewRunCanceled || state.Revision() != 2 || state.HeadIdentity() != canceled.Identity() || state.Failure() != RunFailureCanceled || state.OutputIdentity() != "" {
		t.Fatalf("resumed: plan=%s status=%v revision=%d head=%s failure=%v output=%s err=%v", resumedPlan.Identity(), state.Status(), state.Revision(), state.HeadIdentity(), state.Failure(), state.OutputIdentity(), err)
	}
	receipt, err := restarted.Receipt(ctx, plan.Scope())
	if err != nil || receipt.Validate() != nil || receipt.PlanIdentity() != plan.Identity() || receipt.Scope().Identity() != plan.Scope().Identity() || !receipt.LastOccurredAt().Equal(time.UnixMilli(120)) || receipt.Status() != ReviewRunCanceled || receipt.Revision() != 2 || receipt.HeadIdentity() != canceled.Identity() || receipt.Failure() != RunFailureCanceled || receipt.OutputIdentity() != "" {
		t.Fatalf("receipt: status=%v revision=%d head=%s failure=%v output=%s err=%v", receipt.Status(), receipt.Revision(), receipt.HeadIdentity(), receipt.Failure(), receipt.OutputIdentity(), err)
	}
	for _, task := range receipt.Tasks() {
		if task.OutputIdentity() != "" || task.Status() == TaskRuntimeSucceeded {
			t.Fatalf("canceled receipt carries task success output: key=%s status=%v", task.Key(), task.Status())
		}
	}
}
