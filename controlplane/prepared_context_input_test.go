package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPreparedContextInputAdvancesOnlyExactActivePacket(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	journal, err := NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	coordinator, plan, lease := preparedTestLease(t, journal)
	packet := ContextPacketDescriptor{LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), PayloadDigest: strings.Repeat("b", 64), Classification: "internal", Protection: "process_private", Provenance: []string{strings.Repeat("c", 64), strings.Repeat("e", 64)}, SourceRootIdentity: strings.Repeat("d", 64), SnapshotIdentity: strings.Repeat("e", 64), DependencyIdentities: []string{strings.Repeat("e", 64)}, CreatedAtMilliseconds: 300, ExpiresAtMilliseconds: 3600300}
	packet.ArtifactIdentity = packetArtifactIdentity(plan.Scope(), packet)
	at := lease.ExpiresAt().Add(-2 * time.Millisecond)
	preparedPacket, err := coordinator.PrepareContextPacket(ctx, plan, lease, packet, at)
	if err != nil {
		t.Fatal(err)
	}
	artifactFor := func(kind string, parents []string, payload string) ContextInputArtifactDescriptor {
		value := ContextInputArtifactDescriptor{PayloadDigest: payload, Classification: "internal", Protection: "process_private", Provenance: parents, CreatedAtMilliseconds: at.UnixMilli(), ExpiresAtMilliseconds: 3600300}
		slices.Sort(value.Provenance)
		value.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), kind, value)
		return value
	}
	request := artifactFor("sanitized_model_request", []string{packet.ArtifactIdentity}, strings.Repeat("1", 64))
	receipt := artifactFor("sanitized_egress_receipt", []string{packet.ArtifactIdentity, request.ArtifactIdentity}, strings.Repeat("2", 64))
	input := artifactFor("task_input", []string{packet.ArtifactIdentity, request.ArtifactIdentity, receipt.ArtifactIdentity, strings.Repeat("8", 64)}, strings.Repeat("3", 64))
	descriptor := ContextInputDescriptor{PacketPreparedEventIdentity: preparedPacket.Identity(), PacketArtifactIdentity: packet.ArtifactIdentity, LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), Request: request, Receipt: receipt, Input: input, ReceiptIdentity: strings.Repeat("4", 64), ScannerHelperDigest: strings.Repeat("5", 64), GenerationInputIdentity: strings.Repeat("7", 64), AuthorizationIdentity: strings.Repeat("8", 64), SelectionReceiptIdentity: strings.Repeat("9", 64), RoutingInputIdentity: strings.Repeat("a", 64), SelectedRecordIdentity: strings.Repeat("b", 64), PolicyIdentity: strings.Repeat("d", 64), RoutePairIdentity: strings.Repeat("e", 64), AuthorizerIdentity: strings.Repeat("f", 64), SanitizerIdentity: strings.Repeat("1", 64), RegistryRevision: uint64(11), PerformanceRevision: uint64(5)}
	// The public descriptor may claim identities, but cannot describe egress
	// produced before the v4 event or impossible constructor time ordering.
	for _, tc := range []struct {
		name                    string
		request, receipt, input int64
	}{
		{"request and receipt differ", at.UnixMilli(), at.UnixMilli() - 1, at.UnixMilli()},
		{"input predates receipt", at.UnixMilli(), at.UnixMilli(), at.UnixMilli() - 1},
		{"request predates packet event", at.UnixMilli() - 1, at.UnixMilli() - 1, at.UnixMilli()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := cloneContextInputDescriptor(descriptor)
			invalid.Request.CreatedAtMilliseconds = tc.request
			invalid.Request.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "sanitized_model_request", invalid.Request)
			invalid.Receipt.CreatedAtMilliseconds = tc.receipt
			invalid.Receipt.Provenance = sortedContextInputParents(packet.ArtifactIdentity, invalid.Request.ArtifactIdentity)
			invalid.Receipt.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "sanitized_egress_receipt", invalid.Receipt)
			invalid.Input.CreatedAtMilliseconds = tc.input
			invalid.Input.Provenance = sortedContextInputParents(packet.ArtifactIdentity, invalid.Request.ArtifactIdentity, invalid.Receipt.ArtifactIdentity, invalid.AuthorizationIdentity)
			invalid.Input.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "task_input", invalid.Input)
			if !invalid.Request.valid(plan.Scope(), "sanitized_model_request") || !invalid.Receipt.valid(plan.Scope(), "sanitized_egress_receipt") || !invalid.Input.valid(plan.Scope(), "task_input") {
				t.Fatal("invalid test artifact envelope")
			}
			events, err := journal.Read(ctx, plan.Scope(), 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			isolated := NewMemoryRunJournal()
			if err := isolated.SavePlan(ctx, plan); err != nil {
				t.Fatal(err)
			}
			for _, prior := range events {
				if err := isolated.Append(ctx, prior.PreviousIdentity(), prior); err != nil {
					t.Fatal(err)
				}
			}
			testCoordinator, err := NewCoordinator(isolated)
			if err != nil {
				t.Fatal(err)
			}
			_, prepareErr := testCoordinator.PrepareContextInput(ctx, plan, lease, preparedPacket, invalid, at.Add(time.Millisecond))
			forged := preparedPacket.event
			forged.sequence++
			forged.previousIdentity = preparedPacket.Identity()
			forged.kind = RunEventContextInputPrepared
			forged.packetDescriptor = ContextPacketDescriptor{}
			forged.inputDescriptor = invalid
			forged.outputIdentity = invalid.Input.ArtifactIdentity
			forged.occurredAtMillis = at.Add(time.Millisecond).UnixMilli()
			forged.identity = deriveRunEventIdentity(forged)
			_, replayErr := ReplayReviewRun(plan, append(events, forged))
			if !errors.Is(prepareErr, ErrPreparedContextInput) || replayErr == nil {
				t.Errorf("impossible preparation=%v forged replay=%v", prepareErr, replayErr)
			}
		})
	}
	prepared, err := coordinator.PrepareContextInput(ctx, plan, lease, preparedPacket, descriptor, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(filepath.Join(root, "journal"))
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
	active, ok := runtime.PreparedContextInput()
	if !ok || active.Identity() != prepared.Identity() || active.Descriptor().PacketPreparedEventIdentity != preparedPacket.Identity() || runtime.Attempts() != lease.Attempt() {
		t.Fatal("not same predecessor, attempt and lease")
	}
	wire, err := EncodeRunEvent(active.event)
	if err != nil || len(wire) > 16<<10 || !bytes.Contains(wire, []byte(`"schema_version":5`)) || bytes.Contains(wire, []byte(`"prepared_artifact"`)) || bytes.Contains(wire, []byte(`"output_kind"`)) {
		t.Fatalf("v5 wire: %v", err)
	}
	assertSchemaRecordShape(t, filepath.Join("..", "schemas", "controlplane", "review-run-event-v5.schema.json"), wire)
	if decoded, err := ParseRunEvent(wire); err != nil || decoded.Identity() != prepared.Identity() || !bytes.Equal(mustEncodeRunEvent(t, decoded), wire) {
		t.Fatalf("v5 canonical roundtrip: %v", err)
	}
	wide := active.event
	wide.inputDescriptor = cloneContextInputDescriptor(wide.inputDescriptor)
	for i := 1; len(wide.inputDescriptor.Input.Provenance) < 32; i++ {
		wide.inputDescriptor.Input.Provenance = append(wide.inputDescriptor.Input.Provenance, fmt.Sprintf("%064x", i))
	}
	slices.Sort(wide.inputDescriptor.Input.Provenance)
	wide.inputDescriptor.Input.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "task_input", wide.inputDescriptor.Input)
	wide.outputIdentity = wide.inputDescriptor.Input.ArtifactIdentity
	wide.identity = deriveRunEventIdentity(wide)
	maxParentsWire, err := EncodeRunEvent(wide)
	if err != nil || len(maxParentsWire) > maxEncodedRunEventBytes {
		t.Fatalf("32-parent v5 envelope: %d bytes, %v", len(maxParentsWire), err)
	}
	for name, candidate := range map[string][]byte{
		"noncanonical whitespace": append([]byte(" "), wire...),
		"oversize":                append(append([]byte(nil), wire...), bytes.Repeat([]byte(" "), maxEncodedRunEventBytes)...),
	} {
		if decoded, err := ParseRunEvent(candidate); !errors.Is(err, ErrInvalidRunEventEncoding) || decoded.Identity() != "" {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	same, err := restarted.PrepareContextInput(ctx, plan, lease, preparedPacket, descriptor, lease.ExpiresAt().Add(time.Millisecond))
	if err != nil || same.Identity() != prepared.Identity() {
		t.Fatalf("idempotence after expiry: %v", err)
	}
	changes := []func(*ContextInputDescriptor){func(d *ContextInputDescriptor) {
		d.Request.PayloadDigest = strings.Repeat("a", 64)
		d.Request.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "sanitized_model_request", d.Request)
	}, func(d *ContextInputDescriptor) { d.ReceiptIdentity = strings.Repeat("a", 64) }, func(d *ContextInputDescriptor) {
		d.Receipt.PayloadDigest = strings.Repeat("a", 64)
		d.Receipt.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "sanitized_egress_receipt", d.Receipt)
	}, func(d *ContextInputDescriptor) { d.SelectedRecordIdentity = strings.Repeat("a", 64) }, func(d *ContextInputDescriptor) { d.RegistryRevision++ }, func(d *ContextInputDescriptor) { d.PerformanceRevision++ }, func(d *ContextInputDescriptor) { d.AuthorizationIdentity = strings.Repeat("a", 64) }, func(d *ContextInputDescriptor) {
		d.Input.PayloadDigest = strings.Repeat("a", 64)
		d.Input.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), "task_input", d.Input)
	}}
	for _, zeroRevision := range []func(*ContextInputDescriptor){func(d *ContextInputDescriptor) { d.RegistryRevision = 0 }, func(d *ContextInputDescriptor) { d.PerformanceRevision = 0 }} {
		invalid := cloneContextInputDescriptor(descriptor)
		zeroRevision(&invalid)
		if _, err := restarted.PrepareContextInput(ctx, plan, lease, preparedPacket, invalid, at.Add(time.Millisecond)); !errors.Is(err, ErrPreparedContextInput) {
			t.Fatalf("zero revision accepted: %v", err)
		}
	}
	for i, change := range changes {
		changed := cloneContextInputDescriptor(descriptor)
		change(&changed)
		if _, err := restarted.PrepareContextInput(ctx, plan, lease, preparedPacket, changed, at.Add(time.Millisecond)); !errors.Is(err, ErrPreparedContextInput) {
			t.Fatalf("change %d accepted: %v", i, err)
		}
	}
	success, _ := NewTaskSuccess(input.ArtifactIdentity)
	failure, _ := NewTaskFailure(RunFailurePolicy)
	for _, completion := range []TaskCompletion{success, failure} {
		if _, err := restarted.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); !errors.Is(err, ErrPreparedContextInput) {
			t.Fatalf("generic completion: %v", err)
		}
	}
	if _, _, err := restarted.RenewTaskLease(ctx, plan, lease, at.Add(time.Millisecond)); err == nil {
		t.Fatal("renewed")
	}
	if _, err := restarted.TerminatePreparedContextPacket(ctx, plan, preparedPacket, lease.ExpiresAt().Add(time.Millisecond)); err == nil {
		t.Fatal("stale packet terminal")
	}
	expired := lease.ExpiresAt().Add(time.Millisecond)
	if _, err := restarted.Advance(ctx, plan, expired); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := restarted.ClaimTask(ctx, plan, "context", lease.HandlerIdentity(), "other", expired); err != nil || claimed {
		t.Fatalf("reclaim %v %v", claimed, err)
	}
	// No exact object exists in the reopened store, so only trusted no-output failure can follow.
	terminal, err := restarted.TerminatePreparedContextInput(ctx, plan, active, expired)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ = terminal.Task("context")
	if runtime.Status() != TaskRuntimeFailed || runtime.OutputIdentity() != "" || runtime.Failure() != RunFailurePolicy {
		t.Fatal("missing bytes became success")
	}
	repeated, err := restarted.TerminatePreparedContextInput(ctx, plan, active, expired.Add(time.Millisecond))
	if err != nil || repeated.HeadIdentity() != terminal.HeadIdentity() {
		t.Fatalf("terminal duplicate: %v", err)
	}
	for _, completion := range []TaskCompletion{success, failure} {
		if _, err := restarted.CompleteTask(ctx, plan, lease, completion, expired); !errors.Is(err, ErrPreparedContextInput) {
			t.Fatalf("stale completion accepted: %v", err)
		}
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	final, _ := NewCoordinator(again)
	_, state, err = final.Resume(ctx, plan.Scope())
	if err != nil || state.HeadIdentity() != terminal.HeadIdentity() {
		t.Fatalf("restart failed: %v", err)
	}
}
