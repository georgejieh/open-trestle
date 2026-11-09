package main

import (
	"context"
	"errors"
	"reflect"

	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/gateway"
)

// localPacketRouteRefusal maps a planning refusal to its closed recorded reason.
// It reports false for anything that is not a route refusal.
func localPacketRouteRefusal(err error) (controlplane.TaskFailureReason, controlplane.TaskFailureContextShortfall, bool) {
	if !errors.Is(err, gateway.ErrNoEligibleRoute) {
		return 0, controlplane.TaskFailureContextShortfall{}, false
	}
	if shortfall, ok := gateway.RouteContextShortfallOf(err); ok {
		return controlplane.TaskFailureReasonRouteContextInsufficient, controlplane.TaskFailureContextShortfall{RequiredTokens: shortfall.RequiredTokens, EstimatedInputTokens: shortfall.EstimatedInputTokens, MaxOutputTokens: shortfall.MaxOutputTokens, DeclaredContextTokens: shortfall.DeclaredContextTokens}, true
	}
	return controlplane.TaskFailureReasonNoEligibleRoute, controlplane.TaskFailureContextShortfall{}, true
}

// refusePacketRoute settles the exact leased packet-only preparation as the
// lease holder's recorded route refusal. It changes only that task's journal
// disposition; the packet artifact is retained.
func (o *localPacketOwner) refusePacketRoute(ctx context.Context, request controlplane.TaskExecutionRequest, prepared controlplane.PreparedContextPacket, refusal error) error {
	reason, shortfall, ok := localPacketRouteRefusal(refusal)
	if o == nil || o.journal == nil || o.clock == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil || prepared.Identity() == "" || !ok {
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
		if inner.Err() != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive || !present || head.Kind() != controlplane.RunEventContextPacketPrepared || head.Identity() != prepared.Identity() || state.HeadIdentity() != head.Identity() || state.Revision() != head.Sequence() || !reflect.DeepEqual(head.PacketDescriptor(), descriptor) || !found || !hasPacket || current.Identity() != prepared.Identity() || task.Status() != controlplane.TaskRuntimeLeased || task.Definition().Identity() != request.Task().Identity() || task.Attempts() != request.Lease().Attempt() || task.WorkerIdentity() != request.Lease().WorkerIdentity() || task.LeaseExpiresAt() != request.Lease().ExpiresAt() || task.LeaseTokenIdentity() != head.LeaseTokenIdentity() || descriptor.LeaseIdentity != request.Lease().Identity() || descriptor.LeaseEventIdentity != request.Lease().EventIdentity() {
			return contexthandler.ErrPacketAuthority
		}
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) || now.UnixMilli() < state.LastOccurredAt().UnixMilli() {
			return contexthandler.ErrPacketAuthority
		}
		_, appendErr := coordinator.RefusePreparedContextPacket(inner, plan, request.Lease(), prepared, reason, shortfall, now)
		// Visible bytes after an append error do not establish journal durability.
		actual, present, readErr := o.journal.Head(inner, plan.Scope())
		if readErr != nil || !present || actual.Kind() != controlplane.RunEventTaskFailed || actual.PreviousIdentity() != prepared.Identity() || actual.Sequence() != head.Sequence()+1 {
			return errors.Join(contexthandler.ErrPacketAuthority, appendErr, readErr)
		}
		_, after, readErr := coordinator.Resume(inner, plan.Scope())
		refused, found := after.Task(task.Key())
		recorded, counted := refused.ContextShortfall()
		if readErr != nil || inner.Err() != nil || after.HeadIdentity() != actual.Identity() || !found || refused.Status() != controlplane.TaskRuntimeFailed || refused.Failure() != controlplane.RunFailurePolicy || refused.FailureReason() != reason || counted != shortfall.Present() || recorded != shortfall || refused.OutputIdentity() != "" || !refused.RetryAt().IsZero() || refused.LastEventIdentity() != actual.Identity() {
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
