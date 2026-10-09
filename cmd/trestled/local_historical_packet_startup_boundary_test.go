package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

func restartHistoricalPacketFixture(t *testing.T, f localPacketOwnerFixture, clock artifact.Clock) (error, func()) {
	t.Helper()
	before := snapshotLocalPacketFiles(t, f.statePath)
	if err := f.resources.Close(); err != nil {
		t.Fatalf("close first writer: %v", err)
	}
	second := &daemon{}
	active, journal, owner, bootErr := startLocalSourceOwnerGate(context.Background(), second, f.statePath, f.setupPath, &f.setupPlan, "tenant-a", "repo-a", f.repository, f.gitRoot, f.objectStore, f.adapter, f.rootDigest, clock)
	if bootErr == nil {
		if active == nil || journal == nil || owner == nil {
			t.Fatal("clean recorded boot lost active handles")
		}
	} else if active != nil || journal != nil || owner != nil {
		t.Fatalf("refused boot leaked active handles: %v", bootErr)
	}
	if !reflect.DeepEqual(before, snapshotLocalPacketFiles(t, f.statePath)) {
		t.Fatal("restart changed state bytes")
	}
	return bootErr, func() {
		if err := second.Close(); err != nil {
			t.Errorf("close second writer: %v", err)
		}
		if !reflect.DeepEqual(before, snapshotLocalPacketFiles(t, f.statePath)) {
			t.Error("close changed state bytes")
		}
	}
}

func TestLocalHistoricalPacketRecordedNoV4CleanRestart(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	err, closeSecond := restartHistoricalPacketFixture(t, f, f.clock)
	defer closeSecond()
	if err != nil {
		t.Fatalf("recorded no-v4 must remain active: %v", err)
	}
}

func TestLocalHistoricalPacketIntactCanceledAndExpiredRefusal(t *testing.T) {
	for _, variant := range []string{"canceled", "expired"} {
		t.Run(variant, func(t *testing.T) {
			f := newLocalPacketOwnerFixture(t)
			prepared, err := f.owner.PreparePacket(context.Background(), f.request)
			if err != nil {
				t.Fatal(err)
			}
			clock := artifact.Clock(f.clock)
			if variant == "canceled" {
				if _, err := f.coordinator.CancelRun(context.Background(), f.request.Plan(), f.clock.Now().Add(time.Millisecond)); err != nil {
					t.Fatalf("cancel prepared run: %v", err)
				}
			} else {
				clock = localPacketFixtureClock{time.UnixMilli(prepared.Descriptor().ExpiresAtMilliseconds + 1000)}
			}
			bootErr, closeSecond := restartHistoricalPacketFixture(t, f, clock)
			defer closeSecond()
			if variant == "canceled" {
				if !errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) {
					t.Fatalf("intact canceled packet requires conservative refusal: %v", bootErr)
				}
			} else if !errors.Is(bootErr, errHistoricalPacketObservedAtStartup) {
				t.Fatalf("intact expired packet requires observed refusal: %v", bootErr)
			}
			if errors.Is(bootErr, errHistoricalPacketMissingAtStartup) || errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) || variant == "canceled" && errors.Is(bootErr, errHistoricalPacketObservedAtStartup) {
				t.Fatalf("incorrect typed class: %v", bootErr)
			}
		})
	}
}

func TestLocalHistoricalPacketEncryptedDescriptorConservativeUncertainty(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	ctx := context.Background()
	_, state, err := f.coordinator.Resume(ctx, f.request.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := contexthandler.BuildPacketCandidate(ctx, localPacketFixtureReader{f.store}, f.request, state, f.clock, f.rootDigest, f.clock.Now(), f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	value := candidate.Artifact()
	encrypted, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), artifact.ProtectionEnvelopeEncrypted, value.Provenance(), value.Payload(), value.CreatedAt(), value.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	descriptor := candidate.Descriptor()
	descriptor.Protection = encrypted.Protection().String()
	descriptor.ArtifactIdentity = encrypted.Identity()
	if _, err := f.coordinator.PrepareContextPacket(ctx, f.request.Plan(), f.request.Lease(), descriptor, f.clock.Now()); err != nil {
		t.Fatalf("encrypted replay-valid v4 intent: %v", err)
	}
	// The artifact is deliberately absent; unsupported physical protection must
	// fail before ENOENT can become an owner-qualified typed missing class.
	leaf := filepath.Join(f.statePath, "artifacts", value.Scope().Identity()+"-"+encrypted.Identity()+".artifact.json")
	if _, err := os.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("encrypted descriptor must not have physical bytes: %v", err)
	}
	bootErr, closeSecond := restartHistoricalPacketFixture(t, f, f.clock)
	defer closeSecond()
	if !errors.Is(bootErr, errPhysicalPacketObservationUncertain) || errors.Is(bootErr, errHistoricalPacketMissingAtStartup) || errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) || errors.Is(bootErr, errHistoricalPacketObservedAtStartup) {
		t.Fatalf("unsupported encrypted descriptor must be uncertain, not typed: %v", bootErr)
	}
}
