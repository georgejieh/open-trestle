package controlplane

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func expiryTailFixture(t *testing.T, extra ...TaskDefinition) (*FileRunJournal, *Coordinator, ReviewRunPlan, TaskLease, PreparedContextPacket) {
	t.Helper()
	tasks := runPlanTasks(t)
	tasks = tasks[:len(tasks)-1] // A valid non-nine plan deliberately receives metadata.
	tasks = append(tasks, extra...)
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, tasks)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	coordinator := inventoryOpen(t, journal, plan)
	lease := inventoryPreparedLease(t, coordinator, plan)
	packet, err := coordinator.PrepareContextPacket(context.Background(), plan, lease, historicalDescriptor(plan, lease), lease.ExpiresAt().Add(-10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return journal, coordinator, plan, lease, packet
}

func expiryTailFact(t *testing.T, j *FileRunJournal) HistoricalContextPacketFact {
	t.Helper()
	facts, err := j.InspectHistoricalContextPackets(context.Background())
	if err != nil || len(facts) != 1 {
		t.Fatalf("facts=%d %v", len(facts), err)
	}
	return facts[0]
}

func TestHistoricalPacketExpiryTailCanonicalPrefixes(t *testing.T) {
	j, c, plan, lease, packet := expiryTailFixture(t)
	if plan.TaskCount() == 9 {
		t.Fatal("fixture must demonstrate no nine-task eligibility claim")
	}
	if got := expiryTailFact(t, j).ExpiryTail(); got != ContextPacketExpiryTailActiveExactV4 {
		t.Fatalf("exact head=%v", got)
	}
	ctx := context.Background()
	at := lease.ExpiresAt()
	if _, err := c.TerminatePreparedContextPacket(ctx, plan, packet, at); err != nil {
		t.Fatal(err)
	}
	if got := expiryTailFact(t, j).ExpiryTail(); got != ContextPacketExpiryTailExpiredV4PolicyTerminated {
		t.Fatalf("expiry equality=%v", got)
	}
	for _, key := range []string{"candidates", "verification", "readiness"} {
		_, state, err := c.Resume(ctx, plan.Scope())
		if err != nil {
			t.Fatal(err)
		}
		task, _ := plan.Task(key)
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskSkipped, task, 0, "", "", time.Time{}, "", RunFailureDependency, time.Time{}, at)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Append(ctx, state.HeadIdentity(), event); err != nil {
			t.Fatal(err)
		}
		if got := expiryTailFact(t, j).ExpiryTail(); got != ContextPacketExpiryTailExpiredV4PolicyTerminated {
			t.Fatalf("skip %s=%v", key, got)
		}
	}
	if _, err := c.FailRun(ctx, plan, RunFailurePolicy, at); err != nil {
		t.Fatal(err)
	}
	fact := expiryTailFact(t, j)
	if fact.ExpiryTail() != ContextPacketExpiryTailExpiredV4PolicyTerminated || fact.FinalRunStatus() != ReviewRunFailed || fact.LeaseEvent().LeaseExpiresAt() != lease.ExpiresAt() {
		t.Fatal("canonical terminal lost original lease")
	}
	if (HistoricalContextPacketFact{}).ExpiryTail() != ContextPacketExpiryTailUnknown {
		t.Fatal("zero fact classified")
	}
	// Existing accessor clones cannot alter the scalar classification.
	e := fact.PreparedEvent()
	e.packetDescriptor.Provenance[0] = "changed"
	if fact.ExpiryTail() != ContextPacketExpiryTailExpiredV4PolicyTerminated {
		t.Fatal("classification changed")
	}
}

func TestHistoricalPacketExpiryTailNoncanonicalReplayValid(t *testing.T) {
	for _, mode := range []string{"early-final", "wrong-final-failure", "cancel", "interleave", "renew-unrelated"} {
		t.Run(mode, func(t *testing.T) {
			extra := []TaskDefinition{}
			if mode == "interleave" || mode == "renew-unrelated" {
				extra = append(extra, taskFixture(t, "other", TaskAcquireSource))
			}
			j, c, plan, lease, packet := expiryTailFixture(t, extra...)
			ctx := context.Background()
			at := lease.ExpiresAt()
			if mode == "interleave" || mode == "renew-unrelated" {
				task, _ := plan.Task("other")
				other, ok, err := c.ClaimTask(ctx, plan, "other", task.HandlerIdentity(), "worker", at.Add(-time.Millisecond))
				if err != nil || !ok {
					t.Fatal(err)
				}
				if mode == "renew-unrelated" {
					if _, _, err := c.RenewTaskLease(ctx, plan, other, at); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "cancel" {
				if _, err := c.CancelRun(ctx, plan, at); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := c.TerminatePreparedContextPacket(ctx, plan, packet, at); err != nil {
					t.Fatal(err)
				}
				if mode == "early-final" || mode == "wrong-final-failure" {
					if mode == "wrong-final-failure" {
						if _, err := c.Advance(ctx, plan, at); err != nil {
							t.Fatal(err)
						}
					}
					_, state, err := c.Resume(ctx, plan.Scope())
					if err != nil {
						t.Fatal(err)
					}
					failure := RunFailurePolicy
					if mode == "wrong-final-failure" {
						failure = RunFailureTransient
					}
					event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventFailed, TaskDefinition{}, 0, "", "", time.Time{}, "", failure, time.Time{}, at)
					if err != nil {
						t.Fatal(err)
					}
					if err := j.Append(ctx, state.HeadIdentity(), event); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, _, err := c.Resume(ctx, plan.Scope()); err != nil {
				t.Fatalf("fixture not replay valid: %v", err)
			}
			if got := expiryTailFact(t, j).ExpiryTail(); got != ContextPacketExpiryTailUnknown {
				t.Fatalf("noncanonical=%v", got)
			}
		})
	}
}

func TestHistoricalPacketExpiryTailMostRecentAndOverflow(t *testing.T) {
	j, c, plan, lease, packet := expiryTailFixture(t, taskFixture(t, "context-b", TaskAssembleContext, "analysis", "memory"))
	ctx := context.Background()
	at := lease.ExpiresAt()
	if _, err := c.TerminatePreparedContextPacket(ctx, plan, packet, at); err != nil {
		t.Fatal(err)
	}
	task, _ := plan.Task("context-b")
	next, ok, err := c.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := c.PrepareContextPacket(ctx, plan, next, historicalDescriptor(plan, next), next.ExpiresAt().Add(-2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	facts, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 2 {
		t.Fatal(err)
	}
	if facts[0].ExpiryTail() != ContextPacketExpiryTailUnknown || facts[1].ExpiryTail() != ContextPacketExpiryTailActiveExactV4 {
		t.Fatal("only most recent v4 may classify")
	}
	events, err := j.Read(ctx, plan.Scope(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := c.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	facts, overflow, err := historicalFactsForStream(plan, events, state, 1)
	if err != nil || !overflow || len(facts) != 1 || facts[0].ExpiryTail() != ContextPacketExpiryTailUnknown {
		t.Fatalf("overflow=%v facts=%d err=%v", overflow, len(facts), err)
	}
	// Before a second v4, prefix facts also carry the same original lease witness.
	first := slices.IndexFunc(events, func(e RunEvent) bool { return e.Identity() == packet.Identity() })
	prefix := events[:first+1]
	prefixState, err := ReplayReviewRun(plan, prefix)
	if err != nil {
		t.Fatal(err)
	}
	facts, _, err = historicalFactsForStream(plan, prefix, prefixState, 1)
	if err != nil || facts[0].ExpiryTail() != ContextPacketExpiryTailActiveExactV4 {
		t.Fatal("historical exact prefix not captured")
	}
}

func TestHistoricalPacketExpiryTailLinkedInputUnknown(t *testing.T) {
	j, c, plan, lease, packet := expiryTailFixture(t)
	ctx := context.Background()
	d := packet.Descriptor()
	packetAt := lease.ExpiresAt().Add(-10 * time.Millisecond)
	makeObject := func(kind string, provenance []string) ContextInputArtifactDescriptor {
		slices.Sort(provenance)
		value := ContextInputArtifactDescriptor{
			PayloadDigest: strings.Repeat("2", 64), Classification: d.Classification, Protection: d.Protection,
			Provenance: provenance, CreatedAtMilliseconds: packetAt.Add(time.Millisecond).UnixMilli(),
			ExpiresAtMilliseconds: d.ExpiresAtMilliseconds,
		}
		value.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), kind, value)
		return value
	}
	authorization := strings.Repeat("8", 64)
	request := makeObject("sanitized_model_request", []string{d.ArtifactIdentity})
	receipt := makeObject("sanitized_egress_receipt", []string{d.ArtifactIdentity, request.ArtifactIdentity})
	input := makeObject("task_input", []string{d.ArtifactIdentity, request.ArtifactIdentity, receipt.ArtifactIdentity, authorization})
	id := ContextInputDescriptor{
		PacketPreparedEventIdentity: packet.Identity(), PacketArtifactIdentity: d.ArtifactIdentity,
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		Request: request, Receipt: receipt, Input: input,
		ReceiptIdentity: strings.Repeat("4", 64), ScannerLauncherDigest: strings.Repeat("5", 64),
		ScannerWorkerDigest: strings.Repeat("6", 64), GenerationInputIdentity: strings.Repeat("7", 64),
		AuthorizationIdentity: authorization, SelectionReceiptIdentity: strings.Repeat("9", 64),
		RoutingInputIdentity: strings.Repeat("a", 64), SelectedRecordIdentity: strings.Repeat("b", 64),
		PolicyIdentity: strings.Repeat("d", 64), RoutePairIdentity: strings.Repeat("e", 64),
		AuthorizerIdentity: strings.Repeat("f", 64), SanitizerIdentity: strings.Repeat("1", 64),
		RegistryRevision: 11, PerformanceRevision: 5,
	}
	if _, err := c.PrepareContextInput(ctx, plan, lease, packet, id, packetAt.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if got := expiryTailFact(t, j).ExpiryTail(); got != ContextPacketExpiryTailUnknown {
		t.Fatalf("linked v5=%v", got)
	}
}
