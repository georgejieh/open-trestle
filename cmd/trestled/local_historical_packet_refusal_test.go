package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

// A recorded Git owner's intact v4 packet must remain refused before activation,
// but its refusal must be distinguishable from the legacy blanket refusal.
func TestLocalHistoricalPacketRefusalObservedV4Only(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalPacketOwnerFixture(t)
	scope := fixture.request.Plan().Scope()

	_, state, err := fixture.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	at := fixture.clock.Now()
	candidate, err := contexthandler.BuildPacketCandidate(ctx, localPacketFixtureReader{fixture.store}, fixture.request, state, fixture.clock, fixture.rootDigest, at, at)
	if err != nil {
		t.Fatalf("read-only candidate: %v", err)
	}
	assertLocalPacketOracle(t, fixture, state, candidate.Artifact(), candidate.Descriptor())
	candidateBytes, err := artifact.Encode(candidate.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatalf("boot-returned owner v4 preparation: %v", err)
	}
	if !reflect.DeepEqual(prepared.Descriptor(), candidate.Descriptor()) {
		t.Fatal("owner recorded a descriptor other than the read-only candidate")
	}
	stored, err := fixture.store.Get(ctx, scope, prepared.Descriptor().ArtifactIdentity, at)
	if err != nil {
		t.Fatalf("physical owner Put/readback: %v", err)
	}
	storedBytes, err := artifact.Encode(stored)
	if err != nil || !bytes.Equal(storedBytes, candidateBytes) {
		t.Fatalf("physical envelope differs from read-only candidate: %v", err)
	}
	beforeEvents := encodedLocalPacketHistory(t, fixture.journal, scope)
	if err := fixture.resources.Close(); err != nil {
		t.Fatalf("close first owner resources: %v", err)
	}

	// Raw reopening checks bytes and replay only. Both leases close before the gate.
	verifyLocalPacketReopen(t, fixture, prepared, storedBytes, beforeEvents, controlplane.PreparedContextInput{}, controlplane.ContextInputDescriptor{}, false)
	beforeFiles := snapshotLocalPacketFiles(t, fixture.statePath)
	second := &daemon{}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Errorf("close refused boot resources on cleanup: %v", err)
		}
	})
	active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, second, fixture.statePath, fixture.setupPath, &fixture.setupPlan,
		"tenant-a", "repo-a", fixture.repository, fixture.gitRoot, fixture.objectStore, fixture.adapter, fixture.rootDigest, fixture.clock)
	if active != nil || journal != nil || owner != nil || bootErr == nil {
		t.Errorf("historical v4 must refuse before activation: store=%v journal=%v owner=%v err=%v", active, journal, owner, bootErr)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close refused boot resources: %v", err)
	}
	afterFiles := snapshotLocalPacketFiles(t, fixture.statePath)
	if !reflect.DeepEqual(beforeFiles, afterFiles) {
		t.Fatal("second boot changed packet, journal, or runtime file bytes")
	}
	verifyLocalPacketReopen(t, fixture, prepared, storedBytes, beforeEvents, controlplane.PreparedContextInput{}, controlplane.ContextInputDescriptor{}, false)
	if errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) {
		t.Fatalf("intact recorded Git v4 requires typed observed refusal, got blanket ErrPreparedContextPacketAtStartup: %v", bootErr)
	}
	if !errors.Is(bootErr, errHistoricalPacketObservedAtStartup) ||
		errors.Is(bootErr, errHistoricalPacketMissingAtStartup) ||
		errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) {
		t.Fatalf("intact recorded Git v4 requires only errHistoricalPacketObservedAtStartup: %v", bootErr)
	}
}
