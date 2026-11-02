package main

import (
	"context"
	"fmt"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// localContextOwnerTask is a daemon-only, versioned context handler. Generic
// Execute never writes; the worker's owner branch invokes ExecuteAndSettle.
type localContextOwnerTask struct {
	owner             *localPacketOwner
	ledger            *audit.FileLedger
	sanitizer         review.GenerationRequestSanitizer
	configuration     runtimeconfig.RuntimePolicy
	inventory         runtimeconfig.RouteInventory
	pair              runtimecatalog.LocalGenerationRoutePair
	abstentionPlanner *contexthandler.Handler
}

func (h *localContextOwnerTask) Kind() controlplane.TaskKind { return controlplane.TaskAssembleContext }
func (h *localContextOwnerTask) HandlerIdentity() string {
	return contexthandler.PacketAuthorityHandlerIdentity()
}
func (h *localContextOwnerTask) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	completion, _ := controlplane.NewTaskFailure(controlplane.RunFailurePolicy)
	return completion
}

func (h *localContextOwnerTask) ExecuteAndSettle(ctx context.Context, request controlplane.TaskExecutionRequest) (resultErr error) {
	if h == nil || h.owner == nil || h.owner.store == nil || h.owner.journal == nil || h.ledger == nil || h.sanitizer == nil || ctx == nil || request.Validate() != nil || request.Task().HandlerIdentity() != h.HandlerIdentity() || request.Task().Kind() != h.Kind() || request.Plan().PolicyIdentity() != h.configuration.ReviewPolicyIdentity() || h.configuration.Validate() != nil || h.inventory.Validate() != nil || h.pair.Validate() != nil || h.abstentionPlanner == nil {
		return contexthandler.ErrPacketAuthority
	}
	defer func() {
		if resultErr == nil || ctx.Err() != nil || h.owner.clock.Now().UTC().Before(request.Lease().ExpiresAt()) {
			return
		}
		_, err := h.owner.journal.TerminateExpiredOwnerContextInput(ctx, h.owner.store, h.ledger, request.Plan().Scope(), h.owner.clock)
		if err == nil {
			resultErr = nil
		}
	}()
	abstention, failureCode, err := h.abstentionPlanner.InspectAbstention(ctx, request, h.owner.clock.Now().UTC())
	if err != nil {
		return fmt.Errorf("owner abstention inspection: %w", err)
	}
	if abstention.Identity() != "" {
		return h.owner.PrepareAbstention(ctx, request, h.abstentionPlanner, abstention, failureCode)
	}
	packet, err := h.owner.PreparePacket(ctx, request)
	if err != nil {
		return fmt.Errorf("owner packet preparation: %w", err)
	}
	authorizerIdentity := daemonComponentIdentity("local-context-route-authorizer-v1:" + h.configuration.Identity() + ":" + h.pair.Identity())
	_, err = h.owner.prepareAndSettleInputAfterPacket(ctx, request, packet, h.sanitizer, h.configuration, h.inventory, h.pair, h.ledger, authorizerIdentity)
	if err != nil {
		return fmt.Errorf("owner input preparation and settlement: %w", err)
	}
	return nil
}

var _ controlplane.TaskHandler = (*localContextOwnerTask)(nil)
