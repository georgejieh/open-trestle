package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHistoricalPacketLeaseEventZeroValue(t *testing.T) {
	if (HistoricalContextPacketFact{}).LeaseEvent().Identity() != "" {
		t.Fatal("zero fact has lease")
	}
}

func TestHistoricalPacketLeaseEventKeepsExactReferencedClaimOrRenewal(t *testing.T) {
	for _, renew := range []bool{false, true} {
		name := "claim"
		if renew {
			name = "renewal"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			base := inventoryPlan(t, "tenant", "repo", "run")
			tasks := append(runPlanTasks(t), taskFixture(t, "context-b", TaskAssembleContext, "analysis", "memory"))
			plan, err := NewReviewRunPlan(base.Scope(), base.RequestIdentity(), base.PolicyIdentity(), base.Mode(), tasks)
			if err != nil {
				t.Fatal(err)
			}
			c := inventoryOpen(t, j, plan)
			first := inventoryPreparedLease(t, c, plan)
			if renew {
				first, _, err = c.RenewTaskLease(ctx, plan, first, time.UnixMilli(400))
				if err != nil {
					t.Fatal(err)
				}
			}
			other, _ := plan.Task("context-b")
			second, ok, err := c.ClaimTask(ctx, plan, other.Key(), other.HandlerIdentity(), "other-worker", time.UnixMilli(500))
			if err != nil || !ok {
				t.Fatal("interleaved claim", err)
			}
			packet, err := c.PrepareContextPacket(ctx, plan, first, historicalDescriptor(plan, first), time.UnixMilli(600))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.TerminatePreparedContextPacket(ctx, plan, packet, first.ExpiresAt().Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			secondPacket, err := c.PrepareContextPacket(ctx, plan, second, historicalDescriptor(plan, second), first.ExpiresAt().Add(2*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.TerminatePreparedContextPacket(ctx, plan, secondPacket, second.ExpiresAt().Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			streamBefore, err := os.ReadFile(j.streamPath(plan.Scope()))
			if err != nil {
				t.Fatal(err)
			}
			facts, err := j.InspectHistoricalContextPackets(ctx)
			if err != nil || len(facts) != 2 {
				t.Fatal("facts", len(facts), err)
			}
			expected := map[string]TaskLease{"context": first, "context-b": second}
			events, err := j.Read(ctx, plan.Scope(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			for _, fact := range facts {
				want := expected[fact.PreparedEvent().TaskKey()]
				got := fact.LeaseEvent()
				var original RunEvent
				for _, event := range events {
					if event.Identity() == want.EventIdentity() {
						original = event
					}
				}
				if !reflect.DeepEqual(got, original) || got.Identity() != fact.PreparedEvent().PacketDescriptor().LeaseEventIdentity || got.TaskKey() != want.TaskKey() || got.WorkerIdentity() != want.WorkerIdentity() || got.Attempt() != want.Attempt() || !got.LeaseExpiresAt().Equal(want.ExpiresAt()) {
					t.Fatal("lease fact lost exact referenced event")
				}
				if fact.PreparedEvent().TaskKey() == "context" && renew && got.Kind() != RunEventTaskLeaseRenewed {
					t.Fatal("renewal replaced by original claim")
				}
				if !renew && got.Kind() != RunEventTaskLeased {
					t.Fatal("claim replaced")
				}
				wire, err := EncodeRunEvent(got)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(wire, []byte(want.token)) || strings.Contains(string(wire), `"token":`) {
					t.Fatal("lease secret escaped into read-only event")
				}
				got.workerIdentity = "changed"
				got.packetDescriptor.Provenance = []string{"changed"}
				if !reflect.DeepEqual(fact.LeaseEvent(), original) {
					t.Fatal("lease accessor aliases retained event")
				}
			}
			_, state, err := c.Resume(ctx, plan.Scope())
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := state.Task("context")
			if !runtime.LeaseExpiresAt().IsZero() || !facts[0].LeaseEvent().LeaseExpiresAt().Equal(first.ExpiresAt()) {
				t.Fatal("original expiry not retained after failure")
			}
			streamAfter, err := os.ReadFile(j.streamPath(plan.Scope()))
			if err != nil || !bytes.Equal(streamBefore, streamAfter) {
				t.Fatal("inspection changed journal wire", err)
			}
			if inventory, err := j.InspectStartupInventory(ctx); inventory != (StartupInventory{}) || !errors.Is(err, ErrPreparedContextPacketAtStartup) {
				t.Fatal("read-only accessor changed startup authority", err)
			}
			kept, overflow, err := historicalFactsForStream(plan, events, state, 1)
			if err != nil || !overflow || len(kept) != 1 || kept[0].LeaseEvent().Identity() != first.EventIdentity() {
				t.Fatal("overflow changed retained lease fact", err)
			}
			none, overflow, err := historicalFactsForStream(plan, events, state, 0)
			if err != nil || !overflow || len(none) != 0 {
				t.Fatal("zero remaining retained fact", err)
			}
		})
	}
}

func TestHistoricalPacketLeaseEventReplayRejectsChangedAncestry(t *testing.T) {
	ctx := context.Background()
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	plan := inventoryPlan(t, "tenant", "repo", "changed")
	c := inventoryOpen(t, j, plan)
	lease := inventoryPreparedLease(t, c, plan)
	if _, err := c.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), time.UnixMilli(600)); err != nil {
		t.Fatal(err)
	}
	events, err := j.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"event", "lease", "attempt", "token", "worker"} {
		t.Run(change, func(t *testing.T) {
			altered := append([]RunEvent(nil), events...)
			index := len(altered) - 1
			packet := cloneHistoricalEvent(altered[index])
			switch change {
			case "event":
				packet.packetDescriptor.LeaseEventIdentity = strings.Repeat("f", 64)
			case "lease":
				packet.packetDescriptor.LeaseIdentity = strings.Repeat("f", 64)
			case "attempt":
				packet.attempt++
			case "token":
				packet.leaseTokenIdentity = strings.Repeat("f", 64)
			case "worker":
				for i := range altered {
					if altered[i].Identity() == lease.EventIdentity() {
						altered[i].workerIdentity = "other-worker"
						altered[i].identity = deriveRunEventIdentity(altered[i])
						packet.packetDescriptor.LeaseEventIdentity = altered[i].Identity()
						packet.previousIdentity = altered[i].Identity()
					}
				}
			}
			packet.identity = deriveRunEventIdentity(packet)
			altered[index] = packet
			if _, err := ReplayReviewRun(plan, altered); err == nil {
				t.Fatal("changed lease ancestry replay accepted")
			}
		})
	}
}
