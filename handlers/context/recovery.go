package context

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
)

var ErrContextAbstentionRecovery = errors.New("context abstention recovery blocked")

// RecoverPreparedContextAbstention resolves a durable journal intent before
// any expired-lease settlement or supervisor can advance its review run.
func RecoverPreparedContextAbstention(ctx context.Context, coordinator *controlplane.Coordinator, store artifact.Store, plan controlplane.ReviewRunPlan, at time.Time) error {
	return recoverPreparedContextAbstention(ctx, coordinator, store, plan, at, journaledPacketOnlyHandlerIdentity())
}

// RecoverOwnerPreparedContextAbstention is called only after the daemon's
// Git-qualified owner gate has admitted this versioned handler.
func RecoverOwnerPreparedContextAbstention(ctx context.Context, coordinator *controlplane.Coordinator, store artifact.Store, plan controlplane.ReviewRunPlan, at time.Time) error {
	return recoverPreparedContextAbstention(ctx, coordinator, store, plan, at, PacketAuthorityHandlerIdentity())
}

func recoverPreparedContextAbstention(ctx context.Context, coordinator *controlplane.Coordinator, store artifact.Store, plan controlplane.ReviewRunPlan, at time.Time, handlerIdentity string) error {
	if ctx == nil || coordinator == nil || nilInterface(store) || plan.Validate() != nil || at.IsZero() {
		return ErrContextAbstentionRecovery
	}
	saved, state, err := coordinator.Resume(ctx, plan.Scope())
	if err != nil || saved.Identity() != plan.Identity() {
		return ErrContextAbstentionRecovery
	}
	if state.Status() != controlplane.ReviewRunActive {
		return nil
	}
	task, found := plan.Task("context")
	if !found || task.Kind() != controlplane.TaskAssembleContext || task.HandlerIdentity() != handlerIdentity {
		return nil
	}
	runtime, found := state.Task(task.Key())
	if !found {
		return ErrContextAbstentionRecovery
	}
	prepared, exists := runtime.PreparedContextAbstention()
	if !exists {
		if runtime.Status() == controlplane.TaskRuntimeFailed && runtime.OutputIdentity() != "" {
			_, err := coordinator.FailRun(ctx, plan, runtime.Failure(), at)
			if err != nil {
				return ErrContextAbstentionRecovery
			}
		}
		return nil
	}
	if runtime.Status() != controlplane.TaskRuntimeLeased || prepared.PlanIdentity() != plan.Identity() || prepared.TaskIdentity() != task.Identity() || prepared.TaskKey() != task.Key() || prepared.Attempt() != runtime.Attempts() || prepared.LeaseTokenIdentity() != runtime.LeaseTokenIdentity() {
		return ErrContextAbstentionRecovery
	}
	encoded := prepared.EncodedArtifact()
	value, err := artifact.Parse(encoded)
	if err != nil || value.Identity() != prepared.ArtifactIdentity() || validateContextAbstentionForTask(value, plan, task) != nil {
		return ErrContextAbstentionRecovery
	}
	if err := validatePreparedAbstentionLineage(ctx, store, plan, state, value, prepared.Failure(), at); err != nil {
		return ErrContextAbstentionRecovery
	}
	stored, err := store.Get(ctx, plan.Scope(), value.Identity(), at)
	if errors.Is(err, artifact.ErrArtifactNotFound) {
		if _, err = store.Put(ctx, value, at); err != nil {
			return ErrContextAbstentionRecovery
		}
		stored, err = store.Get(ctx, plan.Scope(), value.Identity(), at)
	}
	if err != nil || stored.Identity() != value.Identity() || !reflect.DeepEqual(stored.Provenance(), value.Provenance()) || validateContextAbstentionForTask(stored, plan, task) != nil {
		return ErrContextAbstentionRecovery
	}
	if _, err = coordinator.SettlePreparedContextAbstention(ctx, plan, prepared, at); err != nil {
		return ErrContextAbstentionRecovery
	}
	if _, err = coordinator.FailRun(ctx, plan, prepared.Failure(), at); err != nil {
		return ErrContextAbstentionRecovery
	}
	return nil
}

func validatePreparedAbstentionLineage(ctx context.Context, store artifact.Store, plan controlplane.ReviewRunPlan, state controlplane.ReviewRunState, value artifact.Artifact, failure controlplane.RunFailure, at time.Time) error {
	var wire contextAbstentionWire
	if json.Unmarshal(value.Payload(), &wire) != nil || wire.Failure != failure.String() {
		return ErrContextAbstentionRecovery
	}
	analysisTask, ok := state.Task("analysis")
	if !ok || analysisTask.Status() != controlplane.TaskRuntimeSucceeded {
		return ErrContextAbstentionRecovery
	}
	memoryTask, ok := state.Task("memory")
	if !ok || memoryTask.Status() != controlplane.TaskRuntimeSucceeded {
		return ErrContextAbstentionRecovery
	}
	scope := plan.Scope()
	analysis, err := store.Get(ctx, scope, analysisTask.OutputIdentity(), at)
	if err != nil {
		return err
	}
	memory, err := store.Get(ctx, scope, memoryTask.OutputIdentity(), at)
	if err != nil {
		return err
	}
	changeID, err := analysisChangeArtifactIdentity(analysis)
	if err != nil {
		return err
	}
	change, err := store.Get(ctx, scope, changeID, at)
	if err != nil {
		return err
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(change)
	if err != nil {
		return err
	}
	base, err := store.Get(ctx, scope, baseID, at)
	if err != nil {
		return err
	}
	head, err := store.Get(ctx, scope, headID, at)
	if err != nil {
		return err
	}
	if _, err = changehandler.ParseResultArtifact(change, base, head); err != nil {
		return err
	}
	parsedAnalysis, err := analysishandler.ParseResultArtifact(analysis, change, base, head)
	if err != nil {
		return err
	}
	parsedMemory, err := memoryhandler.ParseResultArtifact(memory, change, base, head)
	if err != nil || parsedMemory.ChangeArtifactIdentity() != parsedAnalysis.ChangeArtifactIdentity() || parsedMemory.PolicyIdentity() != plan.PolicyIdentity() {
		return ErrContextAbstentionRecovery
	}
	snapshot, err := sourcehandler.ParseSnapshotArtifact(head)
	if err != nil || snapshot.Identity() != wire.HeadSnapshotIdentity || parsedAnalysis.HeadSnapshotIdentity() != wire.HeadSnapshotIdentity {
		return ErrContextAbstentionRecovery
	}
	expected := []string{analysis.Identity(), memory.Identity(), change.Identity(), head.Identity()}
	sort.Strings(expected)
	if !reflect.DeepEqual(expected, value.Provenance()) || value.Classification() != analysis.Classification() || value.Protection() != analysis.Protection() {
		return ErrContextAbstentionRecovery
	}
	return nil
}
