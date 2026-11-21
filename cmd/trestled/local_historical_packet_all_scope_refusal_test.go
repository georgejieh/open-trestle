package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// The second scope is journal intent only. Its complete, replay-valid v4 has
// never passed through Put, so the first scope's intact bytes cannot mask it.
func prepareLocalHistoricalSecondScope(t *testing.T, f localPacketOwnerFixture, tenant, repository string) (controlplane.ReviewRunPlan, controlplane.PreparedContextPacket) {
	t.Helper()
	ctx := context.Background()
	first := f.request.Plan()
	var scope audit.ReviewScope
	var err error
	for n := 1; n <= 100; n++ {
		scope, err = audit.NewReviewScope(tenant, repository, "run-b-"+strconv.Itoa(n))
		if err != nil {
			t.Fatal(err)
		}
		if scope.Identity() > first.Scope().Identity() {
			break
		}
	}
	if scope.Identity() <= first.Scope().Identity() {
		t.Fatal("could not order second scope after intact first scope")
	}
	plan, err := controlplane.NewReviewRunPlan(scope, first.RequestIdentity(), first.PolicyIdentity(), first.Mode(), first.Tasks())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Identity() == first.Identity() {
		t.Fatal("second plan reused first identity")
	}
	if _, err := f.coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatalf("second plan open: %v", err)
	}
	at := time.UnixMilli(102)
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		task, ok := plan.Task(key)
		if !ok {
			t.Fatalf("missing task %s", key)
		}
		if _, err := f.coordinator.Advance(ctx, plan, at); err != nil {
			t.Fatalf("second advance %s: %v", key, err)
		}
		lease, claimed, err := f.coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !claimed {
			t.Fatalf("second claim %s: %t %v", key, claimed, err)
		}
		digest := sha256.Sum256([]byte(scope.Identity() + ":" + key + ":synthetic-upstream"))
		completion, err := controlplane.NewTaskSuccess(hex.EncodeToString(digest[:]))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatalf("second complete %s: %v", key, err)
		}
		at = at.Add(2 * time.Millisecond)
	}
	contextTask, ok := plan.Task("context")
	if !ok {
		t.Fatal("missing context task")
	}
	state, err := f.coordinator.Advance(ctx, plan, at)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, contextTask)
	if err != nil || len(dependencies) != 2 {
		t.Fatalf("second exact dependencies: %d %v", len(dependencies), err)
	}
	lease, claimed, err := f.coordinator.ClaimTask(ctx, plan, "context", contextTask.HandlerIdentity(), "worker", at)
	if err != nil || !claimed {
		t.Fatalf("second context claim: %t %v", claimed, err)
	}
	identities := []string{dependencies[0].OutputIdentity(), dependencies[1].OutputIdentity()}
	slices.Sort(identities)
	if identities[0] == identities[1] {
		t.Fatal("duplicate upstream outputs")
	}
	packetAt := f.clock.Now()
	value, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential,
		artifact.OriginHost, artifact.ProtectionProcessPrivate, identities, []byte(`{"second":"intent-only"}`), packetAt, time.UnixMilli(120000))
	if err != nil {
		t.Fatal(err)
	}
	descriptor := controlplane.ContextPacketDescriptor{
		ArtifactIdentity: value.Identity(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		PayloadDigest: value.PayloadDigest(), Classification: value.Classification().String(), Protection: value.Protection().String(),
		Provenance: value.Provenance(), SourceRootIdentity: f.rootDigest, SnapshotIdentity: strings.Repeat("9", 64),
		DependencyIdentities: identities, CreatedAtMilliseconds: value.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: value.ExpiresAt().UnixMilli(),
	}
	prepared, err := f.coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, packetAt)
	if err != nil || !reflect.DeepEqual(prepared.Descriptor(), descriptor) {
		t.Fatalf("second replay-valid v4: %v", err)
	}
	leaf := filepath.Join(f.statePath, "artifacts", scope.Identity()+"-"+value.Identity()+".artifact.json")
	if _, err := os.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second physical packet must never be Put: %v", err)
	}
	return plan, prepared
}

func assertLocalHistoricalRawTwoScopes(t *testing.T, f localPacketOwnerFixture, first, second controlplane.PreparedContextPacket, secondPlan controlplane.ReviewRunPlan, firstBytes []byte, firstEvents, secondEvents [][]byte) {
	t.Helper()
	ctx := context.Background()
	journal, err := controlplane.NewFileRunJournal(f.statePath)
	if err != nil {
		t.Fatalf("reopen journal writer: %v", err)
	}
	if got := encodedLocalPacketHistory(t, journal, f.request.Plan().Scope()); !reflect.DeepEqual(got, firstEvents) {
		t.Error("first recorded stream changed")
	}
	if got := encodedLocalPacketHistory(t, journal, secondPlan.Scope()); !reflect.DeepEqual(got, secondEvents) {
		t.Error("second recorded stream changed")
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []struct {
		plan     controlplane.ReviewRunPlan
		prepared controlplane.PreparedContextPacket
	}{
		{f.request.Plan(), first}, {secondPlan, second},
	} {
		plan, state, err := coordinator.Resume(ctx, expected.plan.Scope())
		if err != nil || plan.Identity() != expected.plan.Identity() || state.HeadIdentity() != expected.prepared.Identity() {
			t.Fatalf("raw per-scope replay %s: %v", expected.plan.Scope().Identity(), err)
		}
		runtime, ok := state.Task("context")
		current, has := runtime.PreparedContextPacket()
		if !ok || !has || current.Identity() != expected.prepared.Identity() || !reflect.DeepEqual(current.Descriptor(), expected.prepared.Descriptor()) {
			t.Fatalf("raw v4 mismatch: %s", expected.plan.Scope().Identity())
		}
	}
	facts, err := journal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 2 {
		t.Fatalf("raw all-scope replay facts: %d %v", len(facts), err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
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

func TestLocalHistoricalPacketRefusalAllScopeOwnerPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, repository string
		wantMissing              bool
	}{
		{"same owner later missing", "tenant-a", "repo-a", true},
		{"different tenant structural", "tenant-b", "repo-a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := newLocalPacketOwnerFixture(t)
			first, err := f.owner.PreparePacket(ctx, f.request)
			if err != nil {
				t.Fatalf("first physical owner Put: %v", err)
			}
			stored, err := f.store.Get(ctx, f.request.Plan().Scope(), first.Descriptor().ArtifactIdentity, f.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			firstBytes, err := artifact.Encode(stored)
			if err != nil {
				t.Fatal(err)
			}
			plan, second := prepareLocalHistoricalSecondScope(t, f, tc.tenant, tc.repository)
			firstEvents := encodedLocalPacketHistory(t, f.journal, f.request.Plan().Scope())
			secondEvents := encodedLocalPacketHistory(t, f.journal, plan.Scope())
			if err := f.resources.Close(); err != nil {
				t.Fatalf("close first owner leases: %v", err)
			}
			assertLocalHistoricalRawTwoScopes(t, f, first, second, plan, firstBytes, firstEvents, secondEvents)
			before := snapshotLocalPacketFiles(t, f.statePath)
			boot := &daemon{}
			t.Cleanup(func() {
				if err := boot.Close(); err != nil {
					t.Errorf("cleanup refused boot: %v", err)
				}
			})
			active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, boot, f.statePath, f.setupPath, &f.setupPlan,
				"tenant-a", "repo-a", f.repository, f.gitRoot, f.objectStore, f.adapter, f.rootDigest, f.clock)
			if active != nil || journal != nil || owner != nil || bootErr == nil {
				t.Errorf("historical v4 must refuse before activation with nil handles: %v %v %v %v", active, journal, owner, bootErr)
			}
			if err := boot.Close(); err != nil {
				t.Fatalf("close refused resources: %v", err)
			}
			if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
				t.Fatal("boot changed runtime bytes/names")
			}
			assertLocalHistoricalRawTwoScopes(t, f, first, second, plan, firstBytes, firstEvents, secondEvents)
			if after := snapshotLocalPacketFiles(t, f.statePath); !reflect.DeepEqual(before, after) {
				t.Fatal("writer lease reopen changed runtime bytes/names")
			}
			if tc.wantMissing {
				if !errors.Is(bootErr, errHistoricalPacketMissingAtStartup) || errors.Is(bootErr, errHistoricalPacketObservedAtStartup) || errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) || errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) {
					t.Fatalf("later same-owner missing must win globally over intact first: %v", bootErr)
				}
			} else {
				if !errors.Is(bootErr, ErrLocalSourceOwnerMismatch) || errors.Is(bootErr, errHistoricalPacketMissingAtStartup) || errors.Is(bootErr, errHistoricalPacketObservedAtStartup) || errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) || errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) || errors.Is(bootErr, artifact.ErrCorruptArtifact) {
					t.Fatalf("owner mismatch requires its exact structural refusal before activation: %v", bootErr)
				}
			}
		})
	}
}
