package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestContextInputSettlementIsDistinctFromPublicCompletion(t *testing.T) {
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
	prepared, err := coordinator.PrepareContextInput(ctx, plan, lease, preparedPacket, descriptor, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	prior, err := journal.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	settled := prepared.event
	settled.kind = RunEventContextInputSettled
	settled.inputDescriptor = ContextInputDescriptor{}
	settled.sequence++
	settled.previousIdentity = prepared.Identity()
	settled.occurredAtMillis++
	settled.identity = deriveRunEventIdentity(settled)
	if _, err := NewRunEvent(plan, settled.sequence, settled.previousIdentity, RunEventContextInputSettled, func() TaskDefinition { task, _ := plan.Task("context"); return task }(), lease.Attempt(), lease.tokenIdentity, "", time.Time{}, settled.OutputIdentity(), 0, time.Time{}, time.UnixMilli(settled.occurredAtMillis)); !errors.Is(err, ErrPreparedContextInput) {
		t.Fatalf("public constructor accepted owner settlement: %v", err)
	}
	wire, err := EncodeRunEvent(settled)
	if err != nil {
		t.Fatal(err)
	}
	assertSchemaRecordShape(t, filepath.Join("..", "schemas", "controlplane", "review-run-event-v6.schema.json"), wire)
	if decoded, err := ParseRunEvent(wire); err != nil || decoded.Identity() != settled.Identity() {
		t.Fatalf("v6 wire roundtrip: %v", err)
	}
	if err := journal.Append(ctx, prepared.Identity(), settled); !errors.Is(err, ErrPreparedContextInput) {
		t.Fatalf("public journal accepted owner settlement: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*RunEvent)
		valid  bool
	}{
		{"exact", func(*RunEvent) {}, true},
		{"wrong output", func(e *RunEvent) { e.outputIdentity = strings.Repeat("a", 64) }, false},
		{"wrong predecessor", func(e *RunEvent) { e.previousIdentity = preparedPacket.Identity() }, false},
		{"expired lease", func(e *RunEvent) { e.occurredAtMillis = lease.ExpiresAt().Add(time.Millisecond).UnixMilli() }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := settled
			tc.mutate(&candidate)
			candidate.identity = deriveRunEventIdentity(candidate)
			state, err := ReplayReviewRun(plan, append(slices.Clone(prior), candidate))
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				runtime, _ := state.Task("context")
				if runtime.Status() != TaskRuntimeSucceeded || runtime.OutputIdentity() != descriptor.Input.ArtifactIdentity {
					t.Fatalf("invalid settlement: %v %s", runtime.Status(), runtime.OutputIdentity())
				}
			} else if err == nil {
				t.Fatal("forged settlement accepted")
			}
		})
	}
	canceled, err := NewRunEvent(plan, settled.sequence, prepared.Identity(), RunEventCanceled, TaskDefinition{}, 0, "", "", time.Time{}, "", RunFailureCanceled, time.Time{}, at.Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	late := settled
	late.sequence++
	late.previousIdentity = canceled.Identity()
	late.occurredAtMillis++
	late.identity = deriveRunEventIdentity(late)
	if _, err := ReplayReviewRun(plan, append(append(slices.Clone(prior), canceled), late)); err == nil {
		t.Fatal("settlement after cancellation accepted")
	}
	if _, err := ReplayReviewRun(plan, append(append(slices.Clone(prior), settled), settled)); err == nil {
		t.Fatal("duplicate settlement accepted")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
}
