package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestLocalHistoricalPacketLinkedInputLaterScopeMissingPrecedence(t *testing.T) {
	ctx := context.Background()
	f := newLocalPacketOwnerFixture(t)
	first, err := f.owner.PreparePacket(ctx, f.request)
	if err != nil {
		t.Fatalf("first physical owner Put: %v", err)
	}
	packet, err := f.store.Get(ctx, f.request.Plan().Scope(), first.Descriptor().ArtifactIdentity, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := artifact.Encode(packet)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Kind() != artifact.KindContextPacket || !bytes.Contains(packet.Payload(), []byte("fmt.Println")) ||
		packet.Identity() != first.Descriptor().ArtifactIdentity || packet.PayloadDigest() != first.Descriptor().PayloadDigest ||
		first.Descriptor().SourceRootIdentity != f.rootDigest || first.Descriptor().LeaseIdentity != f.request.Lease().Identity() {
		t.Fatal("first physical packet is not bound to the Git owner, descriptor, and lease")
	}
	inputDescriptor := missingLocalContextInputDescriptor(t, f, first, packet)
	input, err := f.coordinator.PrepareContextInput(ctx, f.request.Plan(), f.request.Lease(), first,
		inputDescriptor, f.clock.Now().Add(time.Millisecond))
	if err != nil || !reflect.DeepEqual(input.Descriptor(), inputDescriptor) {
		t.Fatalf("linked v5 intent: %v", err)
	}
	secondPlan, second := prepareLocalHistoricalSecondScope(t, f, "tenant-a", "repo-a")
	firstEvents := encodedLocalPacketHistory(t, f.journal, f.request.Plan().Scope())
	secondEvents := encodedLocalPacketHistory(t, f.journal, secondPlan.Scope())
	if err := f.resources.Close(); err != nil {
		t.Fatalf("close original owner resources: %v", err)
	}
	before := snapshotLocalPacketFiles(t, f.statePath)
	assertLocalHistoricalRawLinkedTwoScopes(t, f, first, input, inputDescriptor, secondPlan, second, firstBytes, firstEvents, secondEvents)

	boot := &daemon{}
	t.Cleanup(func() {
		if err := boot.Close(); err != nil {
			t.Errorf("cleanup refused boot: %v", err)
		}
	})
	active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, boot, f.statePath, f.setupPath, &f.setupPlan,
		"tenant-a", "repo-a", f.repository, f.gitRoot, f.objectStore, f.adapter, f.rootDigest, f.clock)
	if active != nil || journal != nil || owner != nil || bootErr == nil {
		t.Errorf("linked v5 and later missing v4 must refuse with nil handles: %v %v %v %v", active, journal, owner, bootErr)
	}
	if err := boot.Close(); err != nil {
		t.Fatalf("close refused boot resources: %v", err)
	}
	if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
		t.Fatal("refused boot changed runtime file names or bytes")
	}
	assertLocalHistoricalRawLinkedTwoScopes(t, f, first, input, inputDescriptor, secondPlan, second, firstBytes, firstEvents, secondEvents)
	if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
		t.Fatal("raw writer reopen changed runtime file names or bytes")
	}
	if !errors.Is(bootErr, errHistoricalPacketMissingAtStartup) ||
		errors.Is(bootErr, errHistoricalInputIntentQuarantinedAtStartup) ||
		errors.Is(bootErr, errHistoricalPacketObservedAtStartup) ||
		errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) ||
		errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) {
		t.Fatalf("later same-owner missing physical v4 must win over linked v5 quarantine: %v", bootErr)
	}
}

func assertLocalHistoricalRawLinkedTwoScopes(t *testing.T, f localPacketOwnerFixture,
	first controlplane.PreparedContextPacket, input controlplane.PreparedContextInput,
	inputDescriptor controlplane.ContextInputDescriptor, secondPlan controlplane.ReviewRunPlan,
	second controlplane.PreparedContextPacket, firstBytes []byte, firstEvents, secondEvents [][]byte) {
	t.Helper()
	ctx := context.Background()
	journal, err := controlplane.NewFileRunJournal(f.statePath)
	if err != nil {
		t.Fatalf("reopen journal writer: %v", err)
	}
	journalClosed := false
	defer func() {
		if !journalClosed {
			if err := journal.Close(); err != nil {
				t.Errorf("close raw journal: %v", err)
			}
		}
	}()
	if got := encodedLocalPacketHistory(t, journal, f.request.Plan().Scope()); !reflect.DeepEqual(got, firstEvents) {
		t.Fatal("first recorded stream changed")
	}
	if got := encodedLocalPacketHistory(t, journal, secondPlan.Scope()); !reflect.DeepEqual(got, secondEvents) {
		t.Fatal("second recorded stream changed")
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := journal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 2 {
		t.Fatalf("raw all-scope replay facts: %d %v", len(facts), err)
	}
	byScope := make(map[string]controlplane.HistoricalContextPacketFact, len(facts))
	for _, fact := range facts {
		scope := fact.Plan().Scope().Identity()
		if _, duplicate := byScope[scope]; duplicate {
			t.Fatalf("duplicate historical fact for scope %s", scope)
		}
		byScope[scope] = fact
	}
	for _, expected := range []struct {
		plan   controlplane.ReviewRunPlan
		packet controlplane.PreparedContextPacket
		head   string
		linked bool
	}{
		{f.request.Plan(), first, input.Identity(), true},
		{secondPlan, second, second.Identity(), false},
	} {
		plan, state, err := coordinator.Resume(ctx, expected.plan.Scope())
		if err != nil || plan.Identity() != expected.plan.Identity() || state.HeadIdentity() != expected.head {
			t.Fatalf("raw per-scope replay %s: %v", expected.plan.Scope().Identity(), err)
		}
		runtime, ok := state.Task("context")
		if !ok {
			t.Fatalf("missing context runtime for %s", expected.plan.Scope().Identity())
		}
		fact, ok := byScope[expected.plan.Scope().Identity()]
		if !ok || fact.Plan().Identity() != expected.plan.Identity() ||
			fact.FinalHeadIdentity() != state.HeadIdentity() || fact.FinalRevision() != state.Revision() ||
			fact.FinalRunStatus() != state.Status() {
			t.Fatalf("historical fact differs from replay for %s", expected.plan.Scope().Identity())
		}
		prepared := fact.PreparedEvent()
		if prepared.Kind() != controlplane.RunEventContextPacketPrepared || prepared.Identity() != expected.packet.Identity() ||
			!reflect.DeepEqual(prepared.PacketDescriptor(), expected.packet.Descriptor()) {
			t.Fatalf("historical v4 differs from recorded descriptor for %s", expected.plan.Scope().Identity())
		}
		events, err := journal.Read(ctx, expected.plan.Scope(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		foundPacket, foundInput := false, false
		contextTask, ok := expected.plan.Task("context")
		if !ok {
			t.Fatal("missing context task")
		}
		upstream := make([]controlplane.RunEvent, 0, len(contextTask.Dependencies()))
		for _, key := range contextTask.Dependencies() {
			found := false
			for _, event := range events {
				if event.Kind() == controlplane.RunEventTaskSucceeded && event.TaskKey() == key && event.Sequence() < prepared.Sequence() {
					upstream = append(upstream, event)
					found = true
				}
			}
			if !found {
				t.Fatalf("missing recorded upstream success for %s", key)
			}
		}
		if !reflect.DeepEqual(fact.UpstreamSuccessEvents(), upstream) {
			t.Fatalf("fact upstream events differ for %s", expected.plan.Scope().Identity())
		}
		for _, event := range events {
			if event.Kind() == controlplane.RunEventContextPacketPrepared && event.Identity() == expected.packet.Identity() &&
				reflect.DeepEqual(event.PacketDescriptor(), expected.packet.Descriptor()) {
				foundPacket = true
			}
			if expected.linked && event.Kind() == controlplane.RunEventContextInputPrepared && event.Identity() == input.Identity() &&
				reflect.DeepEqual(event.InputDescriptor(), inputDescriptor) {
				foundInput = true
			}
		}
		if !foundPacket || expected.linked && !foundInput {
			t.Fatalf("recorded v4/v5 events absent for %s", expected.plan.Scope().Identity())
		}
		linked, hasLinked := fact.LinkedInputEvent()
		if hasLinked != expected.linked {
			t.Fatalf("unexpected historical linked input for %s", expected.plan.Scope().Identity())
		}
		if expected.linked {
			current, has := runtime.PreparedContextInput()
			if !has || current.Identity() != input.Identity() || !reflect.DeepEqual(current.Descriptor(), inputDescriptor) ||
				linked.Identity() != input.Identity() || !reflect.DeepEqual(linked.InputDescriptor(), inputDescriptor) {
				t.Fatal("first replay lost linked v5 descriptor or checkpoint")
			}
		} else {
			current, has := runtime.PreparedContextPacket()
			if !has || current.Identity() != second.Identity() || !reflect.DeepEqual(current.Descriptor(), second.Descriptor()) {
				t.Fatal("second replay lost current v4 descriptor or checkpoint")
			}
		}
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journalClosed = true
	pending, err := artifact.OpenPendingFileStore(filepath.Join(f.statePath, "artifacts"))
	if err != nil {
		t.Fatalf("reopen pending writer: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	firstLeaf := filepath.Join(f.statePath, "artifacts", f.request.Plan().Scope().Identity()+"-"+first.Descriptor().ArtifactIdentity+".artifact.json")
	if got, err := os.ReadFile(firstLeaf); err != nil || !bytes.Equal(got, firstBytes) {
		t.Fatalf("first physical owner Put changed: %v", err)
	}
	secondLeaf := filepath.Join(f.statePath, "artifacts", secondPlan.Scope().Identity()+"-"+second.Descriptor().ArtifactIdentity+".artifact.json")
	if _, err := os.Lstat(secondLeaf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second physical packet appeared: %v", err)
	}
}
