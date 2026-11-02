package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// Requires the adopted narrow live journal-only expiry disposition.
func TestOwnerExecuteAndSettleSanitizerLeaseExpiryNoOutput(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	ctx, scope := context.Background(), f.request.Plan().Scope()
	inventory, policy, err := localGenerationInventoryAndPolicyWithReviewPolicyForTest(ctx, t, f.request.Plan().PolicyIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if policy.ReviewPolicyIdentity() != f.request.Plan().PolicyIdentity() {
		t.Fatal("test policy is not the request policy")
	}
	pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := audit.NewFileLedger(filepath.Join(t.TempDir(), "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	planner, err := contexthandler.NewJournaledPacketOnlyHandler(f.store, f.owner.clock, f.coordinator)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(f.statePath, scope.Identity()+".scope-intent.json")
	assertNoMarkerOrGrant := func() {
		t.Helper()
		if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("scope marker: %v", err)
		}
		events, err := ledger.Read(ctx, scope, 0, 100)
		if err != nil || len(events) != 0 {
			t.Fatalf("unexpected audit effects: count=%d err=%v", len(events), err)
		}
	}
	snapshotArtifacts := func() map[string]string {
		t.Helper()
		values := map[string]string{}
		err := filepath.WalkDir(filepath.Join(f.statePath, "artifacts"), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			value, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			values[path] = string(value)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return values
	}
	assertNoMarkerOrGrant()
	callbacks := 0
	var pinnedHead, pinnedToken string
	var pinnedRevision uint64
	var packet controlplane.PreparedContextPacket
	var packetBytes []byte
	var physicalBefore map[string]string
	originalLease := f.request.Lease()
	expiredAt := originalLease.ExpiresAt()
	sanitizer := expireOwnerSanitizer{
		GenerationRequestSanitizer: testsupport.NewCleanGenerationSanitizer(),
		expire: func() {
			callbacks++
			if callbacks != 1 {
				t.Fatal("sanitizer callback repeated")
			}
			head, present, err := f.journal.Head(ctx, scope)
			if err != nil || !present || head.Kind() != controlplane.RunEventContextPacketPrepared {
				t.Fatalf("missing actual v4: %v", err)
			}
			plan, state, err := f.coordinator.Resume(ctx, scope)
			if err != nil || plan.Identity() != f.request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive {
				t.Fatalf("unexpected live plan/state: %v", err)
			}
			task, found := state.Task("context")
			var prepared bool
			packet, prepared = task.PreparedContextPacket()
			if !found || !prepared || task.Status() != controlplane.TaskRuntimeLeased || packet.Identity() != head.Identity() || state.HeadIdentity() != head.Identity() {
				t.Fatal("v4 is not the actual leased context checkpoint")
			}
			if _, linked := task.PreparedContextInput(); linked {
				t.Fatal("input already linked")
			}
			descriptor := packet.Descriptor()
			if descriptor.LeaseIdentity != originalLease.Identity() || descriptor.LeaseEventIdentity != originalLease.EventIdentity() || task.LeaseExpiresAt() != originalLease.ExpiresAt() {
				t.Fatal("original lease not bound to v4")
			}
			value, err := f.store.Get(ctx, scope, descriptor.ArtifactIdentity, f.owner.clock.Now())
			if err != nil || value.Validate() != nil || value.Kind() != artifact.KindContextPacket || value.Protection() != artifact.ProtectionProcessPrivate {
				t.Fatalf("invalid physical packet: %v", err)
			}
			assertLocalPacketOracle(t, f, state, value, descriptor)
			packetBytes, err = artifact.Encode(value)
			if err != nil {
				t.Fatal(err)
			}
			if ctx.Err() != nil || !f.owner.clock.Now().Before(expiredAt) || !expiredAt.Before(value.ExpiresAt()) {
				t.Fatal("expiry is not isolated to the task lease")
			}
			assertNoMarkerOrGrant()
			pinnedHead, pinnedRevision = state.HeadIdentity(), state.Revision()
			pinnedToken = task.LeaseTokenIdentity()
			physicalBefore = snapshotArtifacts()
			f.owner.clock = localPacketFixtureClock{expiredAt}
		},
	}
	handler := &localContextOwnerTask{owner: f.owner, ledger: ledger, sanitizer: sanitizer, configuration: policy, inventory: inventory, pair: pair, abstentionPlanner: planner}
	err = handler.ExecuteAndSettle(ctx, f.request)
	if callbacks != 1 {
		t.Fatalf("ordinary sanitizer boundary not reached: callbacks=%d err=%v", callbacks, err)
	}
	if err != nil {
		t.Fatalf("proven pre-input expiry was not terminalized: %v", err)
	}
	if ctx.Err() != nil || !f.owner.clock.Now().Equal(expiredAt) || f.request.Lease().Identity() != originalLease.Identity() {
		t.Fatal("context or original lease changed")
	}
	assertFailedTask := func(state controlplane.ReviewRunState) {
		t.Helper()
		task, found := state.Task("context")
		if !found || state.Plan().Identity() != f.request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive || state.OutputIdentity() != "" || state.Revision() != pinnedRevision+1 {
			t.Fatal("run not at the exact task-failure checkpoint")
		}
		if task.Status() != controlplane.TaskRuntimeFailed || task.Failure() != controlplane.RunFailurePolicy || task.OutputIdentity() != "" || !task.RetryAt().IsZero() || task.LeaseTokenIdentity() != pinnedToken || task.Attempts() != originalLease.Attempt() {
			t.Fatal("context lacks exact failed/no-output/no-retry disposition")
		}
		if _, linked := task.PreparedContextInput(); linked {
			t.Fatal("input unexpectedly linked")
		}
		head, present, err := f.journal.Head(ctx, scope)
		if err != nil || !present || head.Identity() != state.HeadIdentity() || head.Kind() != controlplane.RunEventTaskFailed || head.PreviousIdentity() != pinnedHead || head.Sequence() != pinnedRevision+1 || head.TaskKey() != f.request.Task().Key() || head.TaskIdentity() != f.request.Task().Identity() || head.Attempt() != originalLease.Attempt() || head.LeaseTokenIdentity() != pinnedToken || head.Failure() != controlplane.RunFailurePolicy || head.OutputIdentity() != "" || !head.RetryAt().IsZero() || !head.OccurredAt().Equal(expiredAt) {
			t.Fatalf("unexpected task failure event: %v", err)
		}
	}
	_, state, err := f.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	assertFailedTask(state)
	events, err := f.journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, event := range events {
		if event.Kind() == controlplane.RunEventContextInputPrepared || event.Kind() == controlplane.RunEventContextInputSettled || event.Kind() == controlplane.RunEventFailed {
			t.Fatalf("unexpected input or run terminal event: %v", event.Kind())
		}
		if event.Kind() == controlplane.RunEventTaskFailed {
			failures++
		}
	}
	if failures != 1 {
		t.Fatalf("task failures=%d", failures)
	}
	value, err := f.store.Get(ctx, scope, packet.Descriptor().ArtifactIdentity, expiredAt)
	if err != nil {
		t.Fatal(err)
	}
	afterPacket, err := artifact.Encode(value)
	if err != nil || string(afterPacket) != string(packetBytes) {
		t.Fatal("still-live packet bytes changed")
	}
	assertNoMarkerOrGrant()
	if !reflect.DeepEqual(snapshotArtifacts(), physicalBefore) {
		t.Fatal("physical artifacts changed after sanitizer boundary")
	}
	state, err = f.coordinator.Advance(ctx, f.request.Plan(), expiredAt)
	if err != nil {
		t.Fatal(err)
	}
	assertFailedTask(state)
	finalizer, err := controlplane.NewRunFinalizer(f.journal)
	if err != nil {
		t.Fatal(err)
	}
	state, changed, err := finalizer.ReconcileRun(ctx, scope, expiredAt)
	if err != nil || !changed || state.Status() != controlplane.ReviewRunFailed || state.Failure() != controlplane.RunFailurePolicy || state.OutputIdentity() != "" || state.Revision() != pinnedRevision+2 {
		t.Fatalf("expected failed/no-output run: changed=%v err=%v", changed, err)
	}
	finalHead, present, err := f.journal.Head(ctx, scope)
	if err != nil || !present || finalHead.Kind() != controlplane.RunEventFailed || finalHead.OutputIdentity() != "" || finalHead.Failure() != controlplane.RunFailurePolicy {
		t.Fatalf("missing exact run failure: %v", err)
	}
	assertNoMarkerOrGrant()
	if !reflect.DeepEqual(snapshotArtifacts(), physicalBefore) {
		t.Fatal("recovery probe changed physical artifacts")
	}
}
