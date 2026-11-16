package controlplane_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestPacketCheckpointWithFileStoreCrashPrefixes(t *testing.T) {
	for _, put := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[put], func(t *testing.T) {
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
			prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, time.UnixMilli(at+1))
			if err != nil {
				t.Fatal(err)
			}
			if put {
				if _, err := store.Put(ctx, packet, time.UnixMilli(at+2)); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			reopenedJournal, err := controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
			if err != nil {
				t.Fatal(err)
			}
			defer reopenedJournal.Close()
			reopenedStore, err := artifact.NewFileStore(filepath.Join(root, "artifacts"))
			if err != nil {
				t.Fatal(err)
			}
			defer reopenedStore.Close()
			recoverer, _ := controlplane.NewCoordinator(reopenedJournal)
			_, state, err := recoverer.Resume(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := state.Task("context")
			recovered, ok := runtime.PreparedContextPacket()
			if !ok || recovered.Identity() != prepared.Identity() || recovered.Descriptor().ArtifactIdentity != packet.Identity() {
				t.Fatal("journal intent lost")
			}
			stored, getErr := reopenedStore.Get(ctx, scope, recovered.Descriptor().ArtifactIdentity, time.UnixMilli(at+2))
			if put {
				if getErr != nil || stored.Identity() != packet.Identity() || !bytes.Equal(stored.Payload(), packet.Payload()) || stored.PayloadDigest() != descriptor.PayloadDigest {
					t.Fatalf("stored packet mismatch: %v", getErr)
				}
			} else if !errors.Is(getErr, artifact.ErrArtifactNotFound) {
				t.Fatalf("missing packet admitted: %v", getErr)
			}
			state, err = recoverer.TerminatePreparedContextPacket(ctx, plan, recovered, lease.ExpiresAt().Add(time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ = state.Task("context")
			if runtime.Status() != controlplane.TaskRuntimeFailed || runtime.OutputIdentity() != "" {
				t.Fatal("preparatory packet dispatched")
			}
		})
	}
}
