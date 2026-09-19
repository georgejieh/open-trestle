package controlplane

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func runPlanFixture(t *testing.T) ReviewRunPlan {
	t.Helper()
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, runPlanTasks(t))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func runOpenedEventFixture(t *testing.T, plan ReviewRunPlan) RunEvent {
	t.Helper()
	event, err := NewRunEvent(plan, 1, "", RunEventOpened, TaskDefinition{}, 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	return event
}
func taskAvailableEventFixture(t *testing.T, plan ReviewRunPlan, taskKey string, sequence uint64, previous string) RunEvent {
	t.Helper()
	task, _ := plan.Task(taskKey)
	event, err := NewRunEvent(plan, sequence, previous, RunEventTaskAvailable, task, 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestMemoryRunJournalAppendsWithExpectedHead(t *testing.T) {
	journal := NewMemoryRunJournal()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if err := journal.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	head, found, err := journal.Head(context.Background(), plan.Scope())
	if err != nil || !found || head.Identity() != opened.Identity() {
		t.Fatalf("head=(%#v,%t,%v)", head, found, err)
	}
	available := taskAvailableEventFixture(t, plan, "source", 2, opened.Identity())
	if err := journal.Append(context.Background(), opened.Identity(), available); err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 2 || events[0].Identity() != opened.Identity() || events[1].Identity() != available.Identity() {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
	events[0] = RunEvent{}
	again, _ := journal.Read(context.Background(), plan.Scope(), 0, 10)
	if again[0].Identity() != opened.Identity() {
		t.Fatal("journal exposed mutable events")
	}
}

func TestMemoryRunJournalSerializesConcurrentWriters(t *testing.T) {
	journal := NewMemoryRunJournal()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	_ = journal.Append(context.Background(), "", opened)
	first := taskAvailableEventFixture(t, plan, "source", 2, opened.Identity())
	second := taskAvailableEventFixture(t, plan, "change", 2, opened.Identity())
	events := []RunEvent{first, second}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, event := range events {
		event := event
		wait.Add(1)
		go func() { defer wait.Done(); results <- journal.Append(context.Background(), opened.Identity(), event) }()
	}
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrRunJournalHeadConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestMemoryRunJournalRejectsInvalidScopeSequenceAndContext(t *testing.T) {
	journal := NewMemoryRunJournal()
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := journal.Append(ctx, "", opened); !errors.Is(err, ErrRunJournalContextDone) {
		t.Fatalf("canceled append=%v", err)
	}
	if _, _, err := journal.Head(nil, plan.Scope()); !errors.Is(err, ErrInvalidRunJournalContext) {
		t.Fatalf("nil head=%v", err)
	}
	forged := opened
	forged.identity = strings.Repeat("f", 64)
	if err := journal.Append(context.Background(), "", forged); !errors.Is(err, ErrInvalidRunEventIdentity) {
		t.Fatalf("forged append=%v", err)
	}
	if err := journal.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	bad := taskAvailableEventFixture(t, plan, "source", 3, opened.Identity())
	if err := journal.Append(context.Background(), opened.Identity(), bad); !errors.Is(err, ErrRunJournalSequenceMismatch) {
		t.Fatalf("bad sequence=%v", err)
	}
	if _, err := journal.Read(context.Background(), plan.Scope(), 0, 0); !errors.Is(err, ErrInvalidRunJournalReadLimit) {
		t.Fatalf("bad limit=%v", err)
	}
}

func TestRunEventClosedSemanticsAndIdentity(t *testing.T) {
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	if opened.Kind() != RunEventOpened || opened.PlanIdentity() != plan.Identity() || opened.Scope().Identity() != plan.Scope().Identity() || opened.Sequence() != 1 || opened.Validate() != nil {
		t.Fatalf("opened=%#v", opened)
	}
	task, _ := plan.Task("source")
	leased, err := NewRunEvent(plan, 2, opened.Identity(), RunEventTaskLeased, task, 1, strings.Repeat("d", 64), "worker-1", time.UnixMilli(2_000), "", 0, time.Time{}, time.UnixMilli(1_000))
	if err != nil || leased.TaskKey() != "source" || leased.Attempt() != 1 || leased.WorkerIdentity() != "worker-1" || leased.Validate() != nil {
		t.Fatalf("leased=(%#v,%v)", leased, err)
	}
	if event, err := NewRunEvent(plan, 2, opened.Identity(), RunEventTaskSucceeded, task, 1, strings.Repeat("d", 64), "", time.Time{}, "bad", 0, time.Time{}, time.UnixMilli(1_000)); !errors.Is(err, ErrInvalidRunEventOutput) || event.Identity() != "" {
		t.Fatalf("invalid success=(%#v,%v)", event, err)
	}
}

func TestMemoryRunJournalStoresPlanIdempotently(t *testing.T) {
	journal := NewMemoryRunJournal()
	plan := runPlanFixture(t)
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := journal.LoadPlan(context.Background(), plan.Scope())
	if err != nil || !found || loaded.Identity() != plan.Identity() {
		t.Fatalf("loaded=(%#v,%t,%v)", loaded, found, err)
	}
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatalf("idempotent save=%v", err)
	}
	other, _ := NewReviewRunPlan(plan.Scope(), strings.Repeat("f", 64), plan.PolicyIdentity(), plan.Mode(), plan.Tasks())
	if err := journal.SavePlan(context.Background(), other); !errors.Is(err, ErrRunPlanConflict) {
		t.Fatalf("plan conflict=%v", err)
	}
}

func TestMemoryRunJournalListsOnlyExactTenantRepository(t *testing.T) {
	journal := NewMemoryRunJournal()
	first := runPlanFixture(t)
	_ = journal.SavePlan(context.Background(), first)
	otherScope, _ := audit.NewReviewScope("other", "repository", "run-2")
	other, _ := NewReviewRunPlan(otherScope, first.RequestIdentity(), first.PolicyIdentity(), first.Mode(), first.Tasks())
	_ = journal.SavePlan(context.Background(), other)
	plans, err := journal.ListPlans(context.Background(), "tenant", "repository", "", 10)
	if err != nil || len(plans) != 1 || plans[0].Identity() != first.Identity() {
		t.Fatalf("plans=(%#v,%v)", plans, err)
	}
	if plans, err := journal.ListPlans(context.Background(), "tenant", "other", "", 10); err != nil || len(plans) != 0 {
		t.Fatalf("cross repository=(%#v,%v)", plans, err)
	}
}
