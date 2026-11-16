package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

// PrepareAbstention records a linked deterministic abstention under the same
// boot-owned journal gate; it never authorizes a model input or v6 settlement.
func (o *localPacketOwner) PrepareAbstention(ctx context.Context, request controlplane.TaskExecutionRequest, planner *contexthandler.Handler, candidate artifact.Artifact, failure controlplane.RunFailure) error {
	if o == nil || o.store == nil || o.journal == nil || o.clock == nil || planner == nil || ctx == nil || request.Validate() != nil || candidate.Validate() != nil || failure == 0 {
		return contexthandler.ErrPacketAuthority
	}
	coordinator, err := controlplane.NewCoordinator(o.journal)
	if err != nil {
		return err
	}
	scope := request.Plan().Scope()
	var prepared controlplane.PreparedContextAbstention
	preflight := func(inner context.Context) (string, error) {
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) || !now.Before(candidate.ExpiresAt()) {
			return "", contexthandler.ErrPacketAuthority
		}
		plan, state, err := coordinator.Resume(inner, scope)
		if err != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive {
			return "", errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		runtime, found := state.Task(request.Task().Key())
		if !found || runtime.Status() != controlplane.TaskRuntimeLeased || runtime.WorkerIdentity() != request.Lease().WorkerIdentity() || runtime.Attempts() != request.Lease().Attempt() || runtime.LastEventIdentity() != request.Lease().EventIdentity() {
			return "", contexthandler.ErrPacketAuthority
		}
		current, result, err := planner.InspectAbstention(inner, request, candidate.CreatedAt())
		if err != nil || result != failure || !localInputBytesEqual(current, candidate) {
			return "", errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		encoded, err := json.Marshal(struct{ Version, Plan, Lease, Artifact string }{"local-abstention-prepare-v1", plan.Identity(), request.Lease().Identity(), candidate.Identity()})
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(encoded)
		return hex.EncodeToString(digest[:]), nil
	}
	return o.journal.WithScopeIntentPrepared(ctx, scope, "abstention-prepare-v1", preflight, func(inner context.Context) error {
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) {
			return contexthandler.ErrPacketAuthority
		}
		current, result, err := planner.InspectAbstention(inner, request, candidate.CreatedAt())
		if err != nil || result != failure || !localInputBytesEqual(current, candidate) {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		encoded, err := artifact.Encode(candidate)
		if err != nil {
			return err
		}
		prepared, err = coordinator.PrepareContextAbstention(inner, request.Plan(), request.Lease(), encoded, failure, now)
		if err != nil {
			return err
		}
		now = o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) {
			return contexthandler.ErrPacketAuthority
		}
		if _, err := o.store.Put(inner, candidate, now); err != nil {
			return err
		}
		completion, err := controlplane.NewContextTaskFailureWithOutput(failure, request.Plan(), request.Task(), candidate.Identity())
		if err != nil {
			return err
		}
		now = o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) {
			return contexthandler.ErrPacketAuthority
		}
		_, err = coordinator.CompleteTask(inner, request.Plan(), request.Lease(), completion, now)
		return err
	}, func(inner context.Context) error {
		now := o.clock.Now().UTC()
		if now.UnixMilli() <= 0 {
			return contexthandler.ErrPacketAuthority
		}
		stored, err := o.store.Get(inner, scope, candidate.Identity(), now)
		if err != nil || !localInputBytesEqual(stored, candidate) {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		plan, state, err := coordinator.Resume(inner, scope)
		if err != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		runtime, found := state.Task(request.Task().Key())
		if !found || runtime.Status() != controlplane.TaskRuntimeFailed || runtime.OutputIdentity() != candidate.Identity() || runtime.Failure() != failure {
			return contexthandler.ErrPacketAuthority
		}
		if state.Revision() < 2 {
			return contexthandler.ErrPacketAuthority
		}
		events, err := o.journal.Read(inner, scope, state.Revision()-2, 2)
		if err != nil || len(events) != 2 || events[0].Identity() != prepared.Identity() || events[1].Kind() != controlplane.RunEventTaskFailed || events[1].OutputIdentity() != candidate.Identity() {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		return nil
	})
}
