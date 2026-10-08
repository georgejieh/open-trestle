package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The packet store is deliberately not part of the coordinator transaction: this
// test interrupts at the first checkpoint, before any packet write.
func TestPacketPreparationRejectsTerminalRun(t *testing.T) {
	ctx := context.Background()
	descriptorFor := func(plan ReviewRunPlan, lease TaskLease) ContextPacketDescriptor {
		d := ContextPacketDescriptor{LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), PayloadDigest: strings.Repeat("b", 64), Classification: "internal", Protection: "process_private", Provenance: []string{strings.Repeat("c", 64), strings.Repeat("e", 64)}, SourceRootIdentity: strings.Repeat("d", 64), SnapshotIdentity: strings.Repeat("e", 64), DependencyIdentities: []string{strings.Repeat("e", 64)}, CreatedAtMilliseconds: 300, ExpiresAtMilliseconds: 3600300}
		d.ArtifactIdentity = packetArtifactIdentity(plan.Scope(), d)
		return d
	}
	for _, preparedBeforeCancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel-before-prepare", true: "cancel-before-expired-termination"}[preparedBeforeCancel], func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			journal, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			coordinator, plan, lease := preparedTestLease(t, journal)
			before := lease.ExpiresAt().Add(-2 * time.Millisecond)
			descriptor := descriptorFor(plan, lease)
			var prepared PreparedContextPacket
			if preparedBeforeCancel {
				var err error
				prepared, err = coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, before)
				if err != nil {
					t.Fatal(err)
				}
			}
			canceled, err := coordinator.CancelRun(ctx, plan, before.Add(time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			if preparedBeforeCancel {
				if _, err := coordinator.TerminatePreparedContextPacket(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond)); !errors.Is(err, ErrRunAlreadyTerminal) {
					t.Fatalf("terminal packet settlement=%v", err)
				}
			} else if _, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, lease.ExpiresAt()); !errors.Is(err, ErrRunAlreadyTerminal) {
				t.Fatalf("post-cancel packet prepare=%v", err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			restarted, _ := NewCoordinator(reopened)
			_, state, err := restarted.Resume(ctx, plan.Scope())
			if err != nil || state.Status() != ReviewRunCanceled || state.HeadIdentity() != canceled.HeadIdentity() {
				t.Fatalf("cancellation journal poisoned: %v", err)
			}
		})
	}
}

func TestPacketDescriptorFieldNeverAppearsOnLegacyEvents(t *testing.T) {
	ctx := context.Background()
	journal := NewMemoryRunJournal()
	coordinator, plan, lease := preparedTestLease(t, journal)
	artifact := preparedTestArtifact(t, plan, []byte(`{}`))
	prepared, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, lease.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.SettlePreparedContextAbstention(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(ctx, plan.Scope(), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for _, event := range events {
		version := runEventVersion(event)
		if version < 1 || version > 3 || seen[version] {
			continue
		}
		seen[version] = true
		wire, err := EncodeRunEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		var record runEventRecord
		if err := json.Unmarshal(wire, &record); err != nil {
			t.Fatal(err)
		}
		record.PacketDescriptor = &ContextPacketDescriptor{}
		mutated, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRunEvent(mutated); err == nil {
			t.Fatalf("v%d accepted extraneous canonical zero packet descriptor", version)
		}
	}
	for version := 1; version <= 3; version++ {
		if !seen[version] {
			t.Fatalf("missing fixture version %d", version)
		}
	}
}

func TestPacketPreparationFileJournalRestartAndExpiry(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, plan, lease := preparedTestLease(t, journal)
	descriptor := ContextPacketDescriptor{
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), Classification: "internal", Protection: "process_private", PayloadDigest: strings.Repeat("b", 64),
		Provenance:         []string{strings.Repeat("c", 64), strings.Repeat("e", 64)},
		SourceRootIdentity: strings.Repeat("d", 64), SnapshotIdentity: strings.Repeat("e", 64),
		DependencyIdentities:  []string{strings.Repeat("e", 64)},
		CreatedAtMilliseconds: 300, ExpiresAtMilliseconds: 3600300,
	}
	descriptor.ArtifactIdentity = packetArtifactIdentity(plan.Scope(), descriptor)
	at := lease.ExpiresAt().Add(-time.Millisecond)
	extra := clonePacketDescriptor(descriptor)
	extra.Provenance = append(extra.Provenance, strings.Repeat("f", 64))
	extra.DependencyIdentities = append(extra.DependencyIdentities, strings.Repeat("f", 64))
	extra.ArtifactIdentity = packetArtifactIdentity(plan.Scope(), extra)
	if _, err := coordinator.PrepareContextPacket(ctx, plan, lease, extra, at); err == nil {
		t.Fatal("extra nondependency identity accepted as an exact direct dependency")
	}
	prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, at)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.DependencyIdentities[0] = strings.Repeat("f", 64)
	if prepared.Descriptor().DependencyIdentities[0] != strings.Repeat("e", 64) {
		t.Fatal("mutable descriptor leaked into journal")
	}
	descriptor.DependencyIdentities[0] = strings.Repeat("e", 64)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, _ := NewCoordinator(reopened)
	_, state, err := restarted.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	recovered, ok := runtime.PreparedContextPacket()
	if !ok || recovered.Identity() != prepared.Identity() || recovered.Descriptor().ArtifactIdentity != descriptor.ArtifactIdentity {
		t.Fatal("checkpoint lost")
	}
	wire, err := EncodeRunEvent(recovered.event)
	if err != nil || len(wire) > 16<<10 || bytes.Contains(wire, []byte("prepared_artifact")) || !bytes.Contains(wire, []byte(`"schema_version":4`)) {
		t.Fatalf("packet wire: %v", err)
	}
	if _, err := ParseRunEvent(append(append([]byte(nil), wire...), bytes.Repeat([]byte(" "), 16<<10)...)); err == nil {
		t.Fatal("oversized v4 event admitted")
	}
	parsed, err := ParseRunEvent(wire)
	if err != nil || parsed.Identity() != recovered.Identity() {
		t.Fatalf("v4 readback: %v", err)
	}
	same, err := restarted.PrepareContextPacket(ctx, plan, lease, descriptor, at)
	if err != nil || same.Identity() != recovered.Identity() {
		t.Fatalf("idempotence: %v", err)
	}
	changed := descriptor
	changed.SourceRootIdentity = strings.Repeat("9", 64)
	if _, err := restarted.PrepareContextPacket(ctx, plan, lease, changed, at); !errors.Is(err, ErrPreparedContextPacket) {
		t.Fatalf("changed descriptor accepted: %v", err)
	}
	success, _ := NewTaskSuccess(strings.Repeat("1", 64))
	failure, _ := NewTaskFailure(RunFailurePolicy)
	for _, completion := range []TaskCompletion{success, failure} {
		if _, err := restarted.CompleteTask(ctx, plan, lease, completion, at); !errors.Is(err, ErrPreparedContextPacket) {
			t.Fatalf("generic completion: %v", err)
		}
	}
	if _, _, err := restarted.RenewTaskLease(ctx, plan, lease, at); err == nil {
		t.Fatal("renewed prepared lease")
	}
	expired := lease.ExpiresAt().Add(time.Millisecond)
	if _, err := restarted.Advance(ctx, plan, expired); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := restarted.ClaimTask(ctx, plan, "context", lease.HandlerIdentity(), "other", expired); err != nil || claimed {
		t.Fatalf("reclaimed: %v", err)
	}
	if _, err := restarted.TerminatePreparedContextPacket(ctx, plan, recovered, at); err == nil {
		t.Fatal("premature terminal failure")
	}
	state, err = restarted.TerminatePreparedContextPacket(ctx, plan, recovered, expired)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ = state.Task("context")
	if runtime.Status() != TaskRuntimeFailed || runtime.OutputIdentity() != "" || runtime.Failure() != RunFailurePolicy {
		t.Fatal("packet wrongly succeeded or yielded output")
	}
	sameState, err := restarted.TerminatePreparedContextPacket(ctx, plan, recovered, expired.Add(time.Millisecond))
	if err != nil || state.HeadIdentity() != sameState.HeadIdentity() {
		t.Fatalf("terminal idempotence: %v", err)
	}
	if _, err := restarted.CompleteTask(ctx, plan, lease, success, expired); err == nil {
		t.Fatal("stale worker succeeded")
	}
}
