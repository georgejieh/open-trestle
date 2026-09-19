package controlplane

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestFinalizerSettlesAbandonedFinalTaskAttempt(t *testing.T) {
	for _, attempts := range []uint8{1, 3} {
		t.Run(fmt.Sprint(attempts), func(t *testing.T) {
			task, err := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, attempts, 0, 1000, true)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, []TaskDefinition{task})
			if err != nil {
				t.Fatal(err)
			}
			journal := NewMemoryRunJournal()
			coordinator, err := NewCoordinator(journal)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if _, err = coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
				t.Fatal(err)
			}
			at := time.UnixMilli(200)
			var lease TaskLease
			for attempt := uint8(1); attempt <= attempts; attempt++ {
				var acquired bool
				lease, acquired, err = coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker-a", at)
				if err != nil || !acquired || lease.Attempt() != attempt {
					t.Fatalf("claim attempt %d: acquired=%t err=%v", attempt, acquired, err)
				}
				at = lease.ExpiresAt().Add(time.Millisecond)
			}
			finalizer, err := NewRunFinalizer(journal)
			if err != nil {
				t.Fatal(err)
			}
			before, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), lease.ExpiresAt().Add(-time.Millisecond))
			if err != nil || changed || before.Status() != ReviewRunActive {
				t.Fatalf("premature finalization: changed=%t err=%v", changed, err)
			}
			state, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), at)
			if err != nil || !changed || state.Status() != ReviewRunFailed {
				t.Fatalf("abandoned task not settled: changed=%t status=%s err=%v", changed, state.Status(), err)
			}
			runtime, _ := state.Task(task.Key())
			if runtime.Status() != TaskRuntimeFailed || runtime.Attempts() != attempts || runtime.Failure() != RunFailureResourceLimit || !runtime.RetryAt().IsZero() {
				t.Fatalf("terminal task=%#v", runtime)
			}
			completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
			if _, err = coordinator.CompleteTask(ctx, plan, lease, completion, at); err == nil {
				t.Fatal("expired worker completed failed run")
			}
			again, changed, err := finalizer.ReconcileRun(ctx, plan.Scope(), at.Add(time.Millisecond))
			if err != nil || changed || again.HeadIdentity() != state.HeadIdentity() {
				t.Fatalf("non-idempotent finalization: changed=%t err=%v", changed, err)
			}
		})
	}
}

func TestReplayAcceptsOnlyExhaustedLeaseFailureAfterExpiry(t *testing.T) {
	for _, test := range []struct {
		name    string
		limit   uint8
		token   string
		kind    RunEventKind
		failure RunFailure
		output  string
		retry   time.Time
		valid   bool
	}{
		{"exhausted", 1, strings.Repeat("d", 64), RunEventTaskFailed, RunFailureResourceLimit, "", time.Time{}, true},
		{"attempt remains", 2, strings.Repeat("d", 64), RunEventTaskFailed, RunFailureResourceLimit, "", time.Time{}, false},
		{"wrong token", 1, strings.Repeat("f", 64), RunEventTaskFailed, RunFailureResourceLimit, "", time.Time{}, false},
		{"late success", 1, strings.Repeat("d", 64), RunEventTaskSucceeded, 0, strings.Repeat("e", 64), time.Time{}, false},
		{"wrong failure", 1, strings.Repeat("d", 64), RunEventTaskFailed, RunFailurePolicy, "", time.Time{}, false},
		{"retry after exhaustion", 1, strings.Repeat("d", 64), RunEventTaskFailed, RunFailureResourceLimit, "", time.UnixMilli(3000), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			task, err := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, test.limit, 0, 1000, true)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, []TaskDefinition{task})
			if err != nil {
				t.Fatal(err)
			}
			events := appendRunEventFixture(t, plan, nil, RunEventOpened, "", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(100))
			events = appendRunEventFixture(t, plan, events, RunEventTaskAvailable, "source", 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(110))
			events = appendRunEventFixture(t, plan, events, RunEventTaskLeased, "source", 1, strings.Repeat("d", 64), "worker", time.UnixMilli(1200), "", 0, time.Time{}, time.UnixMilli(200))
			events = appendRunEventFixture(t, plan, events, test.kind, "source", 1, test.token, "", time.Time{}, test.output, test.failure, test.retry, time.UnixMilli(1201))
			_, err = ReplayReviewRun(plan, events)
			if (err == nil) != test.valid {
				t.Fatalf("valid=%t err=%v", test.valid, err)
			}
		})
	}
}
