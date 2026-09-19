package controlplane

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRenewalsReserveJournalCapacityForTermination(t *testing.T) {
	for _, finish := range []string{"cancel", "complete"} {
		t.Run(finish, func(t *testing.T) {
			task, err := NewTaskDefinition("source", TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 0, 1000, true)
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
			if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
				t.Fatal(err)
			}
			lease, acquired, err := coordinator.ClaimTask(ctx, plan, "source", task.HandlerIdentity(), "worker", time.UnixMilli(200))
			if err != nil || !acquired {
				t.Fatalf("claim=%t %v", acquired, err)
			}
			head, found, err := journal.Head(ctx, plan.Scope())
			if err != nil || !found {
				t.Fatal("missing lease event")
			}
			at := time.UnixMilli(200)
			for head.Sequence() < maxRunJournalStreamEvents-4 {
				at = at.Add(time.Millisecond)
				event, err := NewRunEvent(plan, head.Sequence()+1, head.Identity(), RunEventTaskLeaseRenewed, task, 1, lease.tokenIdentity, "worker", at.Add(time.Second), "", 0, time.Time{}, at)
				if err != nil {
					t.Fatal(err)
				}
				if err := journal.Append(ctx, head.Identity(), event); err != nil {
					t.Fatal(err)
				}
				head = event
			}
			before := head.Identity()
			at = at.Add(time.Millisecond)
			_, _, err = coordinator.RenewTaskLease(ctx, plan, lease, at)
			if err == nil {
				t.Error("renewal consumed reserved terminal capacity")
			}
			after, _, err := journal.Head(ctx, plan.Scope())
			if err != nil || after.Identity() != before {
				t.Error("refused renewal changed journal")
			}
			at = at.Add(time.Millisecond)
			if finish == "cancel" {
				state, err := coordinator.CancelRun(ctx, plan, at)
				if err != nil || state.Status() != ReviewRunCanceled {
					t.Fatalf("run no longer cancelable: %v", err)
				}
			} else {
				completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
				if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at); err != nil {
					t.Fatal(err)
				}
				state, err := coordinator.SucceedRun(ctx, plan, completion.OutputIdentity(), at.Add(time.Millisecond))
				if err != nil || state.Status() != ReviewRunSucceeded {
					t.Fatalf("run no longer finalizable: %v", err)
				}
			}
		})
	}
}
