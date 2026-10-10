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

// This is a passing fail-closed restart control for one honest owner Put followed
// by cancellation, not recovery authorization or a cross-store crash proof.
func TestLocalSameOwnerCanceledV4RestartRefusesWithoutMutation(t *testing.T) {
	ctx := context.Background()
	f := newLocalPacketOwnerFixture(t)
	expected := ownerGateCandidate(t, f)
	scope := f.request.Plan().Scope()
	prepared, err := f.owner.PreparePacket(ctx, f.request)
	if err != nil || !reflect.DeepEqual(prepared.Descriptor(), expected.descriptor) {
		t.Fatalf("enrolled owner v4 Put: prepared=%v err=%v", prepared.Identity(), err)
	}
	stored, err := f.store.Get(ctx, scope, expected.value.Identity(), f.clock.Now())
	if err != nil {
		t.Fatalf("owner packet Get: %v", err)
	}
	want, wantErr := artifact.Encode(expected.value)
	original, encodeErr := artifact.Encode(stored)
	if wantErr != nil || encodeErr != nil || !bytes.Equal(want, original) {
		t.Fatalf("owner physical packet differs from candidate: want=%v got=%v", wantErr, encodeErr)
	}
	canceled, err := f.coordinator.CancelRun(ctx, f.request.Plan(), time.UnixMilli(240))
	if err != nil || canceled.Status() != controlplane.ReviewRunCanceled || canceled.Failure() != controlplane.RunFailureCanceled || canceled.OutputIdentity() != "" {
		t.Fatalf("cancel after physical Put: state=%v err=%v", canceled.Status(), err)
	}
	events := ownerGateHistory(t, f.journal, f, expected, controlplane.RunEventContextPacketPrepared, controlplane.RunEventCanceled)
	if prepared.Identity() != events[len(expected.history)].Identity() || canceled.HeadIdentity() != events[len(events)-1].Identity() {
		t.Fatal("owner v4 or canceled terminal head differs from durable event identity")
	}
	contextTask, ok := canceled.Task("context")
	if !ok || contextTask.OutputIdentity() != "" || contextTask.Status() == controlplane.TaskRuntimeSucceeded {
		t.Fatal("canceled context task acquired output")
	}
	packetLeaf := filepath.Join(f.statePath, "artifacts", scope.Identity()+"-"+expected.value.Identity()+".artifact.json")
	physical, err := os.ReadFile(packetLeaf)
	if err != nil || !bytes.Equal(physical, original) {
		t.Fatalf("owner physical packet leaf differs from Encode: %v", err)
	}
	originalEvents := encodedLocalPacketHistory(t, f.journal, scope)
	if err := f.resources.Close(); err != nil {
		t.Fatalf("close original owner resources: %v", err)
	}
	before := snapshotLocalPacketFiles(t, f.statePath)

	// Raw constructors classify persisted facts only. Every lease closes before
	// the next recorded-owner boot. Neither raw handle is an enrolled owner.
	verifyRaw := func() {
		t.Helper()
		journal, err := controlplane.NewFileRunJournal(f.statePath)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := artifact.OpenPendingFileStore(filepath.Join(f.statePath, "artifacts"))
		if err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
		if err := pending.Close(); err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
		store, err := artifact.NewFileStore(filepath.Join(f.statePath, "artifacts"))
		if err != nil {
			_ = journal.Close()
			t.Fatal(err)
		}
		physical, err := os.ReadFile(packetLeaf)
		if err != nil || !bytes.Equal(physical, original) {
			t.Errorf("raw physical packet leaf changed: %v", err)
		}
		reopened, err := store.Get(ctx, scope, expected.value.Identity(), f.clock.Now())
		if err != nil {
			t.Errorf("raw packet Get: %v", err)
		} else {
			encoded, encodeErr := artifact.Encode(reopened)
			if encodeErr != nil || !bytes.Equal(encoded, original) {
				t.Errorf("raw packet bytes differ: %v", encodeErr)
			}
		}
		got := encodedLocalPacketHistory(t, journal, scope)
		if !reflect.DeepEqual(got, originalEvents) {
			t.Error("raw journal changed event bytes")
		}
		rawEvents := ownerGateHistory(t, journal, f, expected, controlplane.RunEventContextPacketPrepared, controlplane.RunEventCanceled)
		if rawEvents[len(expected.history)].Identity() != prepared.Identity() || rawEvents[len(rawEvents)-1].Identity() != canceled.HeadIdentity() {
			t.Error("raw journal changed exact v4/canceled identities")
		}
		coordinator, err := controlplane.NewCoordinator(journal)
		if err != nil {
			t.Error(err)
		} else {
			plan, state, resumeErr := coordinator.Resume(ctx, scope)
			if resumeErr != nil {
				t.Errorf("raw replay failed: %v", resumeErr)
			} else {
				task, present := state.Task("context")
				if plan.Identity() != f.request.Plan().Identity() || state.Status() != controlplane.ReviewRunCanceled ||
					state.HeadIdentity() != canceled.HeadIdentity() || state.OutputIdentity() != "" || !present || task.OutputIdentity() != "" {
					t.Error("raw replay lost canceled run or produced task output")
				}
			}
		}
		if err := store.Close(); err != nil {
			t.Error(err)
		}
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}
	verifyRaw()
	if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
		t.Fatal("first raw reopen changed runtime names or bytes")
	}
	for attempt := 0; attempt < 2; attempt++ {
		boot := &daemon{}
		active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, boot, f.statePath, f.setupPath, &f.setupPlan,
			"tenant-a", "repo-a", f.repository, f.gitRoot, f.objectStore, f.adapter, f.rootDigest, f.clock)
		if active != nil || journal != nil || owner != nil || bootErr == nil {
			t.Errorf("refused boot %d activated: store=%v journal=%v owner=%v err=%v", attempt+1, active, journal, owner, bootErr)
		}
		if err := boot.Close(); err != nil {
			t.Fatalf("close refused boot %d: %v", attempt+1, err)
		}
		if !errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) ||
			errors.Is(bootErr, errHistoricalPacketObservedAtStartup) || errors.Is(bootErr, errHistoricalPacketMissingAtStartup) ||
			errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) || errors.Is(bootErr, errHistoricalInputIntentQuarantinedAtStartup) ||
			errors.Is(bootErr, errHistoricalInputArtifactMissingAtStartup) {
			t.Fatalf("boot %d did not return canceled-only conservative refusal: %v", attempt+1, bootErr)
		}
		if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
			t.Fatalf("boot %d changed runtime names or bytes", attempt+1)
		}
		verifyRaw()
		if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
			t.Fatalf("raw reopen after boot %d changed runtime names or bytes", attempt+1)
		}
	}
}
