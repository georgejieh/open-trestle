package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicJournalsRefuseSuccessAfterPreparedContextPacket(t *testing.T) {
	journals := []struct {
		name string
		open func(*testing.T) RunJournal
	}{
		{"memory", func(t *testing.T) RunJournal { return NewMemoryRunJournal() }},
		{"file", func(t *testing.T) RunJournal {
			journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := journal.Close(); err != nil {
					t.Error(err)
				}
			})
			return journal
		}},
	}
	for _, journalCase := range journals {
		t.Run(journalCase.name, func(t *testing.T) {
			ctx := context.Background()
			journal := journalCase.open(t)
			coordinator, plan, lease := preparedTestLease(t, journal)
			descriptor := historicalDescriptor(plan, lease)
			prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, lease.ExpiresAt().Add(-2*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			head, found, err := journal.Head(ctx, plan.Scope())
			if err != nil || !found || head.Identity() != prepared.Identity() || head.Kind() != RunEventContextPacketPrepared {
				t.Fatalf("prepared head: found=%t kind=%s identity=%s error=%v", found, head.Kind(), head.Identity(), err)
			}
			before, err := journal.Read(ctx, plan.Scope(), 0, maxRunJournalReadLimit)
			if err != nil || len(before) == 0 || len(before) != int(head.Sequence()) || before[len(before)-1].Identity() != prepared.Identity() {
				t.Fatalf("prepared stream: events=%d sequence=%d error=%v", len(before), head.Sequence(), err)
			}
			task, found := plan.Task(lease.TaskKey())
			if !found {
				t.Fatal("leased task missing from plan")
			}
			success, err := NewRunEvent(plan, head.Sequence()+1, head.Identity(), RunEventTaskSucceeded, task,
				lease.Attempt(), lease.tokenIdentity, "", time.Time{}, prepared.Descriptor().ArtifactIdentity,
				0, time.Time{}, lease.ExpiresAt().Add(-time.Millisecond))
			if err != nil {
				t.Fatalf("construct public success: %v", err)
			}
			if success.OutputIdentity() != prepared.Descriptor().ArtifactIdentity || success.PreviousIdentity() != head.Identity() {
				t.Fatal("success does not match prepared packet and current head")
			}
			encoded, err := EncodeRunEvent(success)
			if err != nil {
				t.Fatalf("encode public success: %v", err)
			}
			parsed, err := ParseRunEvent(encoded)
			if err != nil || parsed.Identity() != success.Identity() || parsed.Kind() != RunEventTaskSucceeded {
				t.Fatalf("parse public success: identity=%s kind=%s error=%v", parsed.Identity(), parsed.Kind(), err)
			}

			appendErr := journal.Append(ctx, head.Identity(), success)
			afterHead, afterFound, headErr := journal.Head(ctx, plan.Scope())
			after, readErr := journal.Read(ctx, plan.Scope(), 0, maxRunJournalReadLimit)
			restarted, err := NewCoordinator(journal)
			if err != nil {
				t.Fatal(err)
			}
			_, state, resumeErr := restarted.Resume(ctx, plan.Scope())
			if !errors.Is(appendErr, ErrPreparedContextPacket) {
				t.Errorf("public Append error=%v, want ErrPreparedContextPacket; head=%s (prepared=%s success=%s), events=%d (before=%d), replay error=%v",
					appendErr, afterHead.Identity(), prepared.Identity(), success.Identity(), len(after), len(before), resumeErr)
			}
			if headErr != nil || !afterFound || afterHead.Identity() != prepared.Identity() || afterHead.Kind() != RunEventContextPacketPrepared {
				t.Errorf("head changed after rejected success: found=%t kind=%s identity=%s error=%v", afterFound, afterHead.Kind(), afterHead.Identity(), headErr)
			}
			if readErr != nil || len(after) != len(before) || len(after) == 0 || after[len(after)-1].Identity() != prepared.Identity() {
				t.Errorf("stream changed after rejected success: events=%d (before=%d), error=%v", len(after), len(before), readErr)
			}
			runtime, runtimeFound := state.Task(lease.TaskKey())
			packet, packetFound := runtime.PreparedContextPacket()
			if resumeErr != nil || !runtimeFound || !packetFound || packet.Identity() != prepared.Identity() || state.HeadIdentity() != prepared.Identity() {
				t.Errorf("prepared replay changed after rejected success: error=%v task=%t packet=%t packet identity=%s state head=%s",
					resumeErr, runtimeFound, packetFound, packet.Identity(), state.HeadIdentity())
			}

			planless := journalCase.open(t)
			if _, saved, err := planless.LoadPlan(ctx, plan.Scope()); err != nil || saved {
				t.Fatalf("fresh journal has a saved plan: saved=%t error=%v", saved, err)
			}
			copiedHead := ""
			for _, event := range before {
				if err := planless.Append(ctx, copiedHead, event); err != nil {
					t.Fatalf("copy pre-success event %d: %v", event.Sequence(), err)
				}
				copiedHead = event.Identity()
			}
			if copiedHead != prepared.Identity() {
				t.Fatalf("copied head=%s, want prepared=%s", copiedHead, prepared.Identity())
			}
			planlessHead, found, err := planless.Head(ctx, plan.Scope())
			if err != nil || !found || planlessHead.Identity() != prepared.Identity() || planlessHead.Kind() != RunEventContextPacketPrepared {
				t.Fatalf("planless prepared head: found=%t kind=%s identity=%s error=%v", found, planlessHead.Kind(), planlessHead.Identity(), err)
			}
			if err := planless.Append(ctx, copiedHead, success); !errors.Is(err, ErrPreparedContextPacket) {
				t.Errorf("planless public Append error=%v, want ErrPreparedContextPacket", err)
			}
			planlessHead, found, err = planless.Head(ctx, plan.Scope())
			if err != nil || !found || planlessHead.Identity() != prepared.Identity() || planlessHead.Kind() != RunEventContextPacketPrepared {
				t.Errorf("planless head changed after rejected success: found=%t kind=%s identity=%s error=%v", found, planlessHead.Kind(), planlessHead.Identity(), err)
			}
			planlessEvents, err := planless.Read(ctx, plan.Scope(), 0, maxRunJournalReadLimit)
			if err != nil || len(planlessEvents) != len(before) || len(planlessEvents) == 0 || planlessEvents[len(planlessEvents)-1].Identity() != prepared.Identity() {
				t.Errorf("planless stream changed after rejected success: events=%d (before=%d), error=%v", len(planlessEvents), len(before), err)
			}
		})
	}
}
