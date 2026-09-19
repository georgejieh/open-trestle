package controlplane

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLeaseRenewalUsesCurrentTimeNotAccumulatedExpiry(t *testing.T) {
	coordinator, err := NewCoordinator(NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	ctx := context.Background()
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	lease, acquired, err := coordinator.ClaimTask(ctx, plan, "source", strings.Repeat("d", 64), "worker-a", time.UnixMilli(200))
	if err != nil || !acquired {
		t.Fatalf("claim: acquired=%t err=%v", acquired, err)
	}
	original := lease
	task, _ := plan.Task("source")
	duration := time.Duration(task.LeaseDurationMilliseconds()) * time.Millisecond
	for i := 0; i < 20; i++ {
		at := time.UnixMilli(300 + int64(i)*100)
		renewed, state, err := coordinator.RenewTaskLease(ctx, plan, lease, at)
		if err != nil || !renewed.ExpiresAt().Equal(at.Add(duration)) {
			t.Fatalf("renewal horizon: expires=%v want=%v err=%v", renewed.ExpiresAt(), at.Add(duration), err)
		}
		repeated, repeatedState, err := coordinator.RenewTaskLease(ctx, plan, original, at)
		if err != nil || repeated.Identity() != renewed.Identity() || repeatedState.HeadIdentity() != state.HeadIdentity() {
			t.Fatalf("repeated renewal advanced lease: err=%v", err)
		}
		lease = renewed
	}
	recovered, acquired, err := coordinator.ClaimTask(ctx, plan, "source", strings.Repeat("d", 64), "worker-b", lease.ExpiresAt().Add(time.Millisecond))
	if err != nil || !acquired || recovered.Attempt() != 2 {
		t.Fatalf("recovery beyond bounded horizon failed: acquired=%t err=%v", acquired, err)
	}
}
