package main

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

// localPacketRecheckExpiry exists only on the pre-input second-load time branch.
type localPacketRecheckExpiry struct {
	packet    contexthandler.PacketCandidate
	sampledAt time.Time
}

// terminatePacketRecheckExpiry changes only the exact expired task's journal disposition.
func (o *localPacketOwner) terminatePacketRecheckExpiry(ctx context.Context, request controlplane.TaskExecutionRequest, prepared controlplane.PreparedContextPacket, expiry localPacketRecheckExpiry) error {
	if o == nil || o.journal == nil || o.clock == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || prepared.Identity() == "" || expiry.sampledAt.IsZero() || expiry.sampledAt.UnixMilli() <= 0 || expiry.sampledAt.Before(request.Lease().ExpiresAt()) || !expiry.sampledAt.Before(expiry.packet.Artifact().ExpiresAt()) || !reflect.DeepEqual(expiry.packet.Descriptor(), prepared.Descriptor()) {
		return contexthandler.ErrPacketAuthority
	}
	coordinator, err := controlplane.NewCoordinator(o.journal)
	if err != nil {
		return errors.Join(contexthandler.ErrPacketAuthority, err)
	}
	err = o.journal.WithScopeGate(ctx, request.Plan().Scope(), func(inner context.Context) error {
		plan, state, err := coordinator.Resume(inner, request.Plan().Scope())
		if err != nil {
			return err
		}
		head, present, err := o.journal.Head(inner, request.Plan().Scope())
		if err != nil {
			return err
		}
		task, found := state.Task(request.Task().Key())
		current, hasPacket := task.PreparedContextPacket()
		descriptor := prepared.Descriptor()
		if inner.Err() != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive || !present || head.Kind() != controlplane.RunEventContextPacketPrepared || head.Identity() != prepared.Identity() || state.HeadIdentity() != head.Identity() || state.Revision() != head.Sequence() || !reflect.DeepEqual(head.PacketDescriptor(), descriptor) || !found || !hasPacket || current.Identity() != prepared.Identity() || !reflect.DeepEqual(current.Descriptor(), descriptor) || task.Status() != controlplane.TaskRuntimeLeased || task.Definition().Identity() != request.Task().Identity() || task.Definition().HandlerIdentity() != request.Lease().HandlerIdentity() || task.Attempts() != request.Lease().Attempt() || task.WorkerIdentity() != request.Lease().WorkerIdentity() || task.LeaseExpiresAt() != request.Lease().ExpiresAt() || task.LeaseTokenIdentity() != head.LeaseTokenIdentity() || head.Attempt() != request.Lease().Attempt() || head.TaskIdentity() != request.Task().Identity() || descriptor.LeaseIdentity != request.Lease().Identity() || descriptor.LeaseEventIdentity != request.Lease().EventIdentity() {
			return contexthandler.ErrPacketAuthority
		}
		now := o.clock.Now().UTC()
		if inner.Err() != nil || now.UnixMilli() <= 0 || now.Before(expiry.sampledAt) || now.Before(request.Lease().ExpiresAt()) || now.UnixMilli() < state.LastOccurredAt().UnixMilli() || !now.Before(expiry.packet.Artifact().ExpiresAt()) {
			return contexthandler.ErrPacketAuthority
		}
		expected, err := controlplane.NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), controlplane.RunEventTaskFailed, task.Definition(), task.Attempts(), task.LeaseTokenIdentity(), "", time.Time{}, "", controlplane.RunFailurePolicy, time.Time{}, now)
		if err != nil {
			return err
		}
		_, appendErr := coordinator.TerminatePreparedContextPacket(inner, plan, prepared, now)
		// Visible bytes after an append error do not establish journal durability.
		actual, present, readErr := o.journal.Head(inner, plan.Scope())
		if readErr != nil || !present || actual.Identity() != expected.Identity() {
			return errors.Join(contexthandler.ErrPacketAuthority, appendErr, readErr)
		}
		_, after, readErr := coordinator.Resume(inner, plan.Scope())
		failed, found := after.Task(task.Key())
		if readErr != nil || inner.Err() != nil || after.Status() != controlplane.ReviewRunActive || after.HeadIdentity() != expected.Identity() || after.Revision() != expected.Sequence() || !found || failed.Status() != controlplane.TaskRuntimeFailed || failed.Failure() != controlplane.RunFailurePolicy || failed.OutputIdentity() != "" || !failed.RetryAt().IsZero() || failed.LastEventIdentity() != expected.Identity() {
			return errors.Join(contexthandler.ErrPacketAuthority, appendErr, readErr)
		}
		if appendErr != nil {
			return errors.Join(contexthandler.ErrPacketAuthority, appendErr)
		}
		return nil
	})
	if err != nil {
		return errors.Join(contexthandler.ErrPacketAuthority, err)
	}
	return nil
}
