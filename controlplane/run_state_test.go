package controlplane

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func appendRunEventFixture(t *testing.T, plan ReviewRunPlan, events []RunEvent, kind RunEventKind, taskKey string, attempt uint8, token, worker string, lease time.Time, output string, failure RunFailure, retryAt, at time.Time) []RunEvent {
	t.Helper()
	task := TaskDefinition{}
	if taskKey != "" {
		task, _ = plan.Task(taskKey)
	}
	previous := ""
	if len(events) > 0 {
		previous = events[len(events)-1].Identity()
	}
	event, err := NewRunEvent(plan, uint64(len(events)+1), previous, kind, task, attempt, token, worker, lease, output, failure, retryAt, at)
	if err != nil {
		t.Fatal(err)
	}
	return append(events, event)
}

func TestReplayReviewRunTracksDependenciesAndLeaseLineage(t *testing.T) {
	plan := runPlanFixture(t)
	var events []RunEvent
	events = appendRunEventFixture(t, plan, events, RunEventOpened, "", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
	events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "source", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
	events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "source", 1, strings.Repeat("d", 64), "worker-1", time.UnixMilli(2_000), "", 0, time.Time{}, time.UnixMilli(1_000))
	events = appendRunEventFixture(t, plan, events, RunEventTaskSucceeded, "source", 1, strings.Repeat("d", 64), "", time.Time{}, strings.Repeat("e", 64), 0, time.Time{}, time.UnixMilli(1_500))
	events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "change", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(1_600))
	state, err := ReplayReviewRun(plan, events)
	if err != nil || state.Status() != ReviewRunActive || state.Revision() != uint64(len(events)) || state.HeadIdentity() != events[len(events)-1].Identity() || state.Validate() != nil {
		t.Fatalf("state=(%#v,%v)", state, err)
	}
	source, _ := state.Task("source")
	if source.Status() != TaskRuntimeSucceeded || source.Attempts() != 1 || source.OutputIdentity() != strings.Repeat("e", 64) {
		t.Fatalf("source=%#v", source)
	}
	change, _ := state.Task("change")
	if change.Status() != TaskRuntimeAvailable {
		t.Fatalf("change=%#v", change)
	}
	ready := state.ReadyTasks(time.UnixMilli(1_600))
	if len(ready) != 0 {
		t.Fatalf("ready=%#v", ready)
	}
}

func TestReplayReviewRunRejectsDependencyBypassAndStaleLease(t *testing.T) {
	plan := runPlanFixture(t)
	opened := appendRunEventFixture(t, plan, nil, RunEventOpened, "", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
	bypass := appendRunEventFixture(t, plan, opened, RunEventTaskAvailable, "change", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
	if state, err := ReplayReviewRun(plan, bypass); !errors.Is(err, ErrRunTransitionDependencyBlocked) || state.Revision() != 0 {
		t.Fatalf("bypass=(%#v,%v)", state, err)
	}
	events := appendRunEventFixture(t, plan, opened, RunEventTaskAvailable, "source", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
	events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "source", 1, strings.Repeat("d", 64), "worker-1", time.UnixMilli(2_000), "", 0, time.Time{}, time.UnixMilli(1_000))
	stale := appendRunEventFixture(t, plan, events, RunEventTaskSucceeded, "source", 1, strings.Repeat("f", 64), "", time.Time{}, strings.Repeat("e", 64), 0, time.Time{}, time.UnixMilli(1_500))
	if state, err := ReplayReviewRun(plan, stale); !errors.Is(err, ErrRunTransitionLeaseMismatch) || state.Revision() != 0 {
		t.Fatalf("stale=(%#v,%v)", state, err)
	}
}

func TestReplayReviewRunAllowsExpiredLeaseRecoveryAndBoundedRetry(t *testing.T) {
	plan := runPlanFixture(t)
	var events []RunEvent
	events = appendRunEventFixture(t, plan, events, RunEventOpened, "", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
	events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "source", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
	events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "source", 1, strings.Repeat("d", 64), "worker-1", time.UnixMilli(2_000), "", 0, time.Time{}, time.UnixMilli(1_000))
	events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "source", 2, strings.Repeat("e", 64), "worker-2", time.UnixMilli(4_000), "", 0, time.Time{}, time.UnixMilli(2_100))
	events = appendRunEventFixture(t, plan, events, RunEventTaskFailed, "source", 2, strings.Repeat("e", 64), "", time.Time{}, "", RunFailureTransient, time.UnixMilli(3_000), time.UnixMilli(2_500))
	state, err := ReplayReviewRun(plan, events)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := state.Task("source")
	if source.Status() != TaskRuntimeFailed || source.Attempts() != 2 || !source.RetryableAt(time.UnixMilli(3_000)) {
		t.Fatalf("failed source=%#v", source)
	}
	ready := state.ReadyTasks(time.UnixMilli(3_000))
	if len(ready) != 1 || ready[0].Key() != "source" {
		t.Fatalf("ready=%#v", ready)
	}
}

func TestReplayReviewRunRejectsEventsAfterTerminalRun(t *testing.T) {
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, []TaskDefinition{taskFixture(t, "source", TaskAcquireSource)})
	if err != nil {
		t.Fatal(err)
	}
	var events []RunEvent
	events = appendRunEventFixture(t, plan, events, RunEventOpened, "", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
	events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "source", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
	events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "source", 1, strings.Repeat("d", 64), "worker", time.UnixMilli(2_000), "", 0, time.Time{}, time.UnixMilli(1_000))
	events = appendRunEventFixture(t, plan, events, RunEventTaskSucceeded, "source", 1, strings.Repeat("d", 64), "", time.Time{}, strings.Repeat("e", 64), 0, time.Time{}, time.UnixMilli(1_500))
	events = appendRunEventFixture(t, plan, events, RunEventSucceeded, "", 0, "", "", time.Time{}, strings.Repeat("f", 64), 0, time.Time{}, time.UnixMilli(1_600))
	state, err := ReplayReviewRun(plan, events)
	if err != nil || state.Status() != ReviewRunSucceeded {
		t.Fatalf("terminal=(%#v,%v)", state, err)
	}
	extra := appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "source", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(1_700))
	if state, err := ReplayReviewRun(plan, extra); !errors.Is(err, ErrRunAlreadyTerminal) || state.Revision() != 0 {
		t.Fatalf("extra=(%#v,%v)", state, err)
	}
}

func TestReplayReviewRunAllowsRequiredWorkAfterOptionalTerminalFailure(t *testing.T) {
	source, _ := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 0, 1_000, true)
	change, _ := NewTaskDefinition("change", TaskBuildChange, strings.Repeat("b", 64), strings.Repeat("e", 64), []string{"source"}, 1, 0, 1_000, true)
	analysis, _ := NewTaskDefinition("analysis", TaskInspectDeterministic, strings.Repeat("c", 64), strings.Repeat("f", 64), []string{"change"}, 1, 0, 1_000, false)
	contextTask, _ := NewTaskDefinition("context", TaskAssembleContext, strings.Repeat("d", 64), strings.Repeat("a", 64), []string{"change", "analysis"}, 1, 0, 1_000, true)
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, []TaskDefinition{source, change, analysis, contextTask})
	if err != nil {
		t.Fatal(err)
	}
	var events []RunEvent
	events = appendRunEventFixture(t, plan, events, RunEventOpened, "", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
	for index, key := range []string{"source", "change"} {
		at := time.UnixMilli(int64(200 + index*300))
		token := strings.Repeat(string(rune('d'+index)), 64)
		events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, key, 0, "", "", time.Time{}, "", 0, time.Time{}, at)
		events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, key, 1, token, "worker", at.Add(time.Second), "", 0, time.Time{}, at)
		events = appendRunEventFixture(t, plan, events, RunEventTaskSucceeded, key, 1, token, "", time.Time{}, strings.Repeat(string(rune('a'+index)), 64), 0, time.Time{}, at.Add(time.Millisecond))
	}
	at := time.UnixMilli(800)
	events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "analysis", 0, "", "", time.Time{}, "", 0, time.Time{}, at)
	events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "analysis", 1, strings.Repeat("f", 64), "worker", at.Add(time.Second), "", 0, time.Time{}, at)
	events = appendRunEventFixture(t, plan, events, RunEventTaskFailed, "analysis", 1, strings.Repeat("f", 64), "", time.Time{}, "", RunFailurePolicy, time.Time{}, at.Add(time.Millisecond))
	state, err := ReplayReviewRun(plan, events)
	if err != nil {
		t.Fatal(err)
	}
	ready := state.ReadyTasks(time.UnixMilli(900))
	if len(ready) != 1 || ready[0].Key() != "context" {
		t.Fatalf("ready=%#v", ready)
	}
}
