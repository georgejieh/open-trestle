package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var refusalShortfall = TaskFailureContextShortfall{RequiredTokens: 14096, EstimatedInputTokens: 10000, MaxOutputTokens: 4096, DeclaredContextTokens: 8192}

// The lease holder settles a packet-only preparation as its recorded route
// refusal before the lease expires; replay restores it and the historical tail
// names it apart from a lease-expiry termination.
func TestRefusePreparedContextPacketWithinLease(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	tasks := runPlanTasks(t)
	// The closed cleanup suffix skips exactly the three dependents.
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, tasks[:len(tasks)-1])
	if err != nil {
		t.Fatal(err)
	}
	coordinator := inventoryOpen(t, journal, plan)
	lease := inventoryPreparedLease(t, coordinator, plan)
	packet, err := coordinator.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), lease.ExpiresAt().Add(-10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	at := lease.ExpiresAt().Add(-5 * time.Millisecond)
	for name, call := range map[string]func() error{
		"source reason": func() error {
			_, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonNoMergeBase, TaskFailureContextShortfall{}, at)
			return err
		},
		"missing counts": func() error {
			_, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonRouteContextInsufficient, TaskFailureContextShortfall{}, at)
			return err
		},
		"counts on no_eligible_route": func() error {
			_, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonNoEligibleRoute, refusalShortfall, at)
			return err
		},
		"after lease expiry": func() error {
			_, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonRouteContextInsufficient, refusalShortfall, lease.ExpiresAt().Add(time.Millisecond))
			return err
		},
		"other lease": func() error {
			other := lease
			other.tokenIdentity = strings.Repeat("f", 64)
			_, err := coordinator.RefusePreparedContextPacket(ctx, plan, other, packet, TaskFailureReasonRouteContextInsufficient, refusalShortfall, at)
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrPreparedContextPacket) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Without a reason the in-lease failure is still refused by replay.
	_, state, err := coordinator.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	contextTask, _ := plan.Task("context")
	bare, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskFailed, contextTask, lease.Attempt(), lease.tokenIdentity, "", time.Time{}, "", RunFailurePolicy, time.Time{}, at)
	if err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayReviewRun(plan, append(events, bare)); !errors.Is(err, ErrPreparedContextPacket) {
		t.Fatalf("bare in-lease failure: %v", err)
	}
	late, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskFailed, contextTask, lease.Attempt(), lease.tokenIdentity, "", time.Time{}, "", RunFailurePolicy, time.Time{}, lease.ExpiresAt().Add(time.Millisecond))
	if err == nil {
		late, err = late.withFailureReason(contextTask, TaskFailureReasonNoEligibleRoute, TaskFailureContextShortfall{})
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayReviewRun(plan, append(events, late)); err == nil {
		t.Fatal("refusal after the lease replayed")
	}
	refused, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonRouteContextInsufficient, refusalShortfall, at)
	if err != nil {
		t.Fatal(err)
	}
	again, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonRouteContextInsufficient, refusalShortfall, at.Add(time.Millisecond))
	if err != nil || again.HeadIdentity() != refused.HeadIdentity() || again.Revision() != refused.Revision() {
		t.Fatalf("repeat refusal: %v", err)
	}
	if _, err := coordinator.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonNoEligibleRoute, TaskFailureContextShortfall{}, at); !errors.Is(err, ErrPreparedContextPacket) {
		t.Fatalf("different settled reason: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	coordinator, err = NewCoordinator(reopened)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err = coordinator.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	task, _ := state.Task("context")
	if shortfall, ok := task.ContextShortfall(); task.Status() != TaskRuntimeFailed || task.Failure() != RunFailurePolicy || task.FailureReason() != TaskFailureReasonRouteContextInsufficient || !ok || shortfall != refusalShortfall || task.OutputIdentity() != "" || !task.RetryAt().IsZero() || state.HeadIdentity() != refused.HeadIdentity() {
		t.Fatal("replay lost the in-lease refusal")
	}
	if _, err := coordinator.TerminatePreparedContextPacket(ctx, plan, packet, lease.ExpiresAt()); err == nil {
		t.Fatal("refused packet terminated again")
	}
	if got := expiryTailFact(t, reopened).ExpiryTail(); got != ContextPacketExpiryTailRefusedV4PolicyTerminated {
		t.Fatalf("refusal tail=%v", got)
	}
	for _, key := range []string{"candidates", "verification", "readiness"} {
		_, state, err := coordinator.Resume(ctx, plan.Scope())
		if err != nil {
			t.Fatal(err)
		}
		dependent, _ := plan.Task(key)
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskSkipped, dependent, 0, "", "", time.Time{}, "", RunFailureDependency, time.Time{}, at)
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.Append(ctx, state.HeadIdentity(), event); err != nil {
			t.Fatal(err)
		}
		if got := expiryTailFact(t, reopened).ExpiryTail(); got != ContextPacketExpiryTailRefusedV4PolicyTerminated {
			t.Fatalf("skip %s=%v", key, got)
		}
	}
	if _, err := coordinator.FailRun(ctx, plan, RunFailurePolicy, at); err != nil {
		t.Fatal(err)
	}
	if fact := expiryTailFact(t, reopened); fact.ExpiryTail() != ContextPacketExpiryTailRefusedV4PolicyTerminated || fact.FinalRunStatus() != ReviewRunFailed {
		t.Fatal("closed refusal suffix not classified")
	}
}

// A lease-expiry termination stays reason-free and keeps its own tail.
func TestRefusalTailIsNotExpiryTail(t *testing.T) {
	j, c, plan, lease, packet := expiryTailFixture(t)
	ctx := context.Background()
	if _, err := c.TerminatePreparedContextPacket(ctx, plan, packet, lease.ExpiresAt()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RefusePreparedContextPacket(ctx, plan, lease, packet, TaskFailureReasonNoEligibleRoute, TaskFailureContextShortfall{}, lease.ExpiresAt()); !errors.Is(err, ErrPreparedContextPacket) {
		t.Fatalf("terminated packet refused: %v", err)
	}
	_, state, err := c.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	task, _ := state.Task("context")
	if task.FailureReason() != 0 || expiryTailFact(t, j).ExpiryTail() != ContextPacketExpiryTailExpiredV4PolicyTerminated {
		t.Fatal("expiry termination gained a reason")
	}
}
