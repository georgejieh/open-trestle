package controlplane_test

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPreparedContextInputFileObjectsAbsentAfterCheckpoint(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant", "repository", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	journal, err := controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewFileStore(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	tasks := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
	}{
		{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}}, {"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"verification"}}, {"publication", controlplane.TaskPublishResult, []string{"readiness"}},
	}
	definitions := make([]controlplane.TaskDefinition, 0, len(tasks))
	for _, task := range tasks {
		maxAttempts := uint8(3)
		if task.key == "publication" {
			maxAttempts = 1
		}
		definition, err := controlplane.NewTaskDefinition(task.key, task.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), task.dependencies, maxAttempts, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		definitions = append(definitions, definition)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunRequired, definitions)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := int64(200)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+1)); err != nil {
			t.Fatal(err)
		}
		at += 20
	}
	task, _ := plan.Task("context")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !ok {
		t.Fatalf("context lease: %v", err)
	}
	packet, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationInternal, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, []byte(`{"packet":"immutable fixture"}`), time.UnixMilli(280), time.UnixMilli(3600280))
	if err != nil {
		t.Fatal(err)
	}
	descriptor := controlplane.ContextPacketDescriptor{
		ArtifactIdentity: packet.Identity(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), PayloadDigest: packet.PayloadDigest(), Classification: packet.Classification().String(), Protection: packet.Protection().String(),
		Provenance: packet.Provenance(), SourceRootIdentity: strings.Repeat("a", 64), SnapshotIdentity: strings.Repeat("b", 64), DependencyIdentities: []string{strings.Repeat("e", 64)},
		CreatedAtMilliseconds: packet.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: packet.ExpiresAt().UnixMilli(),
	}

	preparedPacket, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, time.UnixMilli(at+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(ctx, packet, time.UnixMilli(at+2)); err != nil {
		t.Fatal(err)
	}
	ledger, err := audit.NewFileLedger(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	authorization := strings.Repeat("8", 64)
	newObject := func(kind artifact.Kind, parents []string) artifact.Artifact {
		sort.Strings(parents)
		object, err := artifact.New(scope, kind, "application/json", artifact.ClassificationInternal, artifact.OriginHost, artifact.ProtectionProcessPrivate, parents, []byte(`{"sanitized":"fixture only"}`), time.UnixMilli(at+3), packet.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		return object
	}
	request := newObject(artifact.KindSanitizedModelRequest, []string{packet.Identity()})
	receipt := newObject(artifact.KindSanitizedEgressReceipt, []string{packet.Identity(), request.Identity()})
	input := newObject(artifact.KindTaskInput, []string{packet.Identity(), request.Identity(), receipt.Identity(), authorization})
	fromObject := func(value artifact.Artifact) controlplane.ContextInputArtifactDescriptor {
		return controlplane.ContextInputArtifactDescriptor{ArtifactIdentity: value.Identity(), PayloadDigest: value.PayloadDigest(), Classification: value.Classification().String(), Protection: value.Protection().String(), Provenance: value.Provenance(), CreatedAtMilliseconds: value.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: value.ExpiresAt().UnixMilli()}
	}
	d := controlplane.ContextInputDescriptor{PacketPreparedEventIdentity: preparedPacket.Identity(), PacketArtifactIdentity: packet.Identity(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), Request: fromObject(request), Receipt: fromObject(receipt), Input: fromObject(input), ReceiptIdentity: strings.Repeat("4", 64), ScannerHelperDigest: strings.Repeat("5", 64), GenerationInputIdentity: strings.Repeat("7", 64), AuthorizationIdentity: authorization, SelectionReceiptIdentity: strings.Repeat("9", 64), RoutingInputIdentity: strings.Repeat("a", 64), SelectedRecordIdentity: strings.Repeat("b", 64), PolicyIdentity: strings.Repeat("d", 64), RoutePairIdentity: strings.Repeat("e", 64), AuthorizerIdentity: strings.Repeat("f", 64), SanitizerIdentity: strings.Repeat("1", 64), RegistryRevision: uint64(11), PerformanceRevision: uint64(5)}
	checkpoint, err := coordinator.PrepareContextInput(ctx, plan, lease, preparedPacket, d, time.UnixMilli(at+4))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	store, err = artifact.NewFileStore(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ledger, err = audit.NewFileLedger(filepath.Join(root, "audit"))
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	restarted, _ := controlplane.NewCoordinator(journal)
	_, state, err := restarted.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	active, ok := runtime.PreparedContextInput()
	if !ok || active.Identity() != checkpoint.Identity() {
		t.Fatal("v5 checkpoint lost")
	}
	for _, value := range []artifact.Artifact{request, receipt, input} {
		if _, err := store.Get(ctx, scope, value.Identity(), time.UnixMilli(at+5)); !errors.Is(err, artifact.ErrArtifactNotFound) {
			t.Fatalf("missing %s accepted: %v", value.Kind(), err)
		}
	}
	events, err := ledger.Read(ctx, scope, 0, 100)
	if err != nil || len(events) != 0 {
		t.Fatalf("audit effects: %d %v", len(events), err)
	}
	success, _ := controlplane.NewTaskSuccess(input.Identity())
	if _, err := restarted.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+5)); !errors.Is(err, controlplane.ErrPreparedContextInput) {
		t.Fatalf("missing objects became success: %v", err)
	}
	expired := lease.ExpiresAt().Add(time.Millisecond)
	state, err = restarted.TerminatePreparedContextInput(ctx, plan, active, expired)
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ = state.Task("context")
	if runtime.Status() != controlplane.TaskRuntimeFailed || runtime.OutputIdentity() != "" || runtime.Failure() != controlplane.RunFailurePolicy {
		t.Fatal("no-output terminal violated")
	}
}
