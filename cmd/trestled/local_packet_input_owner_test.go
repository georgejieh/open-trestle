package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

func TestOwnerPreparedInputPersistsExactPhysicalEffects(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	ctx, scope := context.Background(), fixture.request.Plan().Scope()
	packet, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.owner.clock = localPacketFixtureClock{time.UnixMilli(231)}
	inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
	if err != nil {
		t.Fatal(err)
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
	preparedArtifacts, err := fixture.owner.PrepareInput(ctx, fixture.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
	if err != nil {
		t.Fatal(err)
	}
	prepared, input := preparedArtifacts.Prepared, preparedArtifacts.Input
	if input.Kind() != artifact.KindTaskInput || prepared.Descriptor().Input.ArtifactIdentity != input.Identity() {
		t.Fatal("v5 input is not the stored task_input")
	}
	physicalArtifacts := make([]artifact.Artifact, 0, 4)
	for _, item := range []struct {
		id   string
		kind artifact.Kind
	}{
		{packet.Descriptor().ArtifactIdentity, artifact.KindContextPacket},
		{prepared.Descriptor().Request.ArtifactIdentity, artifact.KindSanitizedModelRequest},
		{prepared.Descriptor().Receipt.ArtifactIdentity, artifact.KindSanitizedEgressReceipt},
		{prepared.Descriptor().Input.ArtifactIdentity, artifact.KindTaskInput},
	} {
		physical, err := fixture.store.Get(ctx, scope, item.id, fixture.owner.clock.Now())
		if err != nil || physical.Kind() != item.kind {
			t.Fatalf("physical %s kind=%s err=%v", item.id, physical.Kind(), err)
		}
		want := []artifact.Artifact{preparedArtifacts.Packet, preparedArtifacts.Request, preparedArtifacts.Receipt, preparedArtifacts.Input}[len(physicalArtifacts)]
		if !localInputBytesEqual(want, physical) {
			t.Fatal("physical owner envelope changed")
		}
		physicalArtifacts = append(physicalArtifacts, physical)
	}
	marker := filepath.Join(fixture.statePath, scope.Identity()+".scope-intent.json")
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified input marker remains: %v", err)
	}
	auditEvents, err := ledger.Read(ctx, scope, 0, 10)
	if err != nil || len(auditEvents) != 1 || auditEvents[0].Kind() != audit.EventRouteSelected || auditEvents[0].SubjectIdentity() != prepared.Descriptor().SelectionReceiptIdentity {
		t.Fatalf("route selection evidence: %v (%d)", err, len(auditEvents))
	}
	_, state, err := fixture.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	current, okay := runtime.PreparedContextInput()
	if !okay || current.Identity() != prepared.Identity() || state.HeadIdentity() != prepared.Identity() {
		t.Fatal("v5 not the authoritative head")
	}
	completion, _ := controlplane.NewTaskSuccess(input.Identity())
	if _, err := fixture.coordinator.CompleteTask(ctx, fixture.request.Plan(), fixture.request.Lease(), completion, fixture.owner.clock.Now()); !errors.Is(err, controlplane.ErrPreparedContextInput) {
		t.Fatalf("generic success after physical v5: %v", err)
	}
	expiredProof := controlplane.OwnerContextInputSettlement{Plan: fixture.request.Plan(), Lease: fixture.request.Lease(), Prepared: prepared,
		Packet: physicalArtifacts[0], Request: physicalArtifacts[1], Receipt: physicalArtifacts[2], Input: input,
		Clock: localPacketFixtureClock{fixture.request.Lease().ExpiresAt().Add(time.Millisecond)}}
	if _, err := fixture.journal.SettleOwnerContextInput(ctx, fixture.store, ledger, expiredProof); !errors.Is(err, controlplane.ErrPreparedContextInput) {
		t.Fatalf("expired settlement accepted: %v", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired preflight poisoned scope: %v", err)
	}
	wrongProof := expiredProof
	wrongProof.Clock = fixture.owner.clock
	wrongProof.Input = physicalArtifacts[1]
	if _, err := fixture.journal.SettleOwnerContextInput(ctx, fixture.store, ledger, wrongProof); !errors.Is(err, controlplane.ErrPreparedContextInput) {
		t.Fatalf("mismatched physical task_input accepted: %v", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong preflight poisoned scope: %v", err)
	}
	settled, err := fixture.journal.SettleOwnerContextInput(ctx, fixture.store, ledger, controlplane.OwnerContextInputSettlement{
		Plan: fixture.request.Plan(), Lease: fixture.request.Lease(), Prepared: prepared,
		Packet: physicalArtifacts[0], Request: physicalArtifacts[1], Receipt: physicalArtifacts[2], Input: input,
		Clock: fixture.owner.clock,
	})
	if err != nil {
		t.Fatalf("owner physical settlement: %v", err)
	}
	output, _ := settled.Task("context")
	if output.Status() != controlplane.TaskRuntimeSucceeded || output.OutputIdentity() != input.Identity() {
		t.Fatal("v6 settlement did not set exact v5 output")
	}
	head, present, err := fixture.journal.Head(ctx, scope)
	if err != nil || !present || head.Kind() != controlplane.RunEventContextInputSettled || head.OutputIdentity() != input.Identity() {
		t.Fatal("v6 did not persist as head")
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("settlement intent remains: %v", err)
	}
}

func TestOwnerPreparedInputCancellationLeavesUncertainEffectsQuarantined(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := fixture.request.Plan().Scope()
	packet, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.owner.clock = localPacketFixtureClock{time.UnixMilli(231)}
	inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
	if err != nil {
		t.Fatal(err)
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
	fixture.owner.beforeInputPut = cancel
	if _, err := fixture.owner.PrepareInput(ctx, fixture.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity()); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("canceled effect did not quarantine: %v", err)
	}
	marker := filepath.Join(fixture.statePath, scope.Identity()+".scope-intent.json")
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("uncertain intent missing: %v", err)
	}
	_, state, err := fixture.coordinator.Resume(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	task, _ := state.Task("context")
	prepared, found := task.PreparedContextInput()
	if !found || state.HeadIdentity() != prepared.Identity() {
		t.Fatal("v5 append not durable before canceled Put")
	}
	if _, err := fixture.store.Get(context.Background(), scope, prepared.Descriptor().Input.ArtifactIdentity, fixture.owner.clock.Now()); err == nil {
		t.Fatal("task_input unexpectedly persisted after cancel")
	}
	if _, err := fixture.coordinator.CancelRun(context.Background(), fixture.request.Plan(), fixture.owner.clock.Now()); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("canceled effect left journal writable: %v", err)
	}
	if err := fixture.resources.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlplane.NewFileRunJournal(fixture.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.InspectStartupInventory(context.Background()); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("restart admitted uncertain v5 effects: %v", err)
	}
}

type cancelAtOwnerSettlementVerifyClock struct {
	at     time.Time
	calls  int
	cancel context.CancelFunc
}

func (c *cancelAtOwnerSettlementVerifyClock) Now() time.Time {
	c.calls++
	if c.calls == 4 {
		c.cancel()
	}
	return c.at
}

func TestOwnerSettlementMarkerReconcilesOnlyVerifiedCommittedV6(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	ctx, scope := context.Background(), fixture.request.Plan().Scope()
	packet, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	fixture.owner.clock = localPacketFixtureClock{time.UnixMilli(231)}
	inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(t.TempDir(), "audit")
	ledger, err := audit.NewFileLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	preparedArtifacts, err := fixture.owner.PrepareInput(ctx, fixture.request, packet, testsupport.NewCleanGenerationSanitizer(), policy, inventory, pair, ledger, policy.ReviewPolicyIdentity())
	if err != nil {
		t.Fatal(err)
	}
	prepared, input := preparedArtifacts.Prepared, preparedArtifacts.Input
	values := [4]artifact.Artifact{}
	for i, id := range []string{packet.Descriptor().ArtifactIdentity, prepared.Descriptor().Request.ArtifactIdentity, prepared.Descriptor().Receipt.ArtifactIdentity, input.Identity()} {
		values[i], err = fixture.store.Get(ctx, scope, id, fixture.owner.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	settleCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req := controlplane.OwnerContextInputSettlement{
		Plan: fixture.request.Plan(), Lease: fixture.request.Lease(), Prepared: prepared,
		Packet: values[0], Request: values[1], Receipt: values[2], Input: input,
		Clock: &cancelAtOwnerSettlementVerifyClock{at: fixture.owner.clock.Now(), cancel: cancel},
	}
	if _, err := fixture.journal.SettleOwnerContextInput(settleCtx, fixture.store, ledger, req); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("canceled post-append v6 must retain marker: %v", err)
	}
	marker := filepath.Join(fixture.statePath, scope.Identity()+".scope-intent.json")
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("post-append settlement marker missing: %v", err)
	}
	head, present, err := fixture.journal.Head(ctx, scope)
	if err != nil || !present || head.Kind() != controlplane.RunEventContextInputSettled {
		t.Fatal("v6 not durable before canceled verify")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixture.resources.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlplane.NewFileRunJournal(fixture.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	store, err := artifact.NewFileStore(filepath.Join(fixture.statePath, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reopenedLedger, err := audit.NewFileLedger(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedLedger.Close()
	if _, err := reopened.InspectStartupInventory(ctx); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("restart admitted marker: %v", err)
	}
	wrong := req
	wrong.Input = values[1]
	wrong.Clock = fixture.owner.clock
	if err := reopened.ReconcileOwnerContextSettlement(ctx, store, reopenedLedger, wrong); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("wrong input cleared marker: %v", err)
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("marker lost after wrong proof: %v", err)
	}
	req.Clock = fixture.owner.clock
	if err := reopened.ReconcileOwnerContextSettlement(ctx, store, reopenedLedger, req); err != nil {
		t.Fatalf("verified v6 restart recovery: %v", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("verified marker survived: %v", err)
	}
}
