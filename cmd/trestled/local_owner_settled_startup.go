package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

// verifyOwnerSettledStartup proves provisional owner history against replay,
// current bytes, route audit, and Git ownership before admission. Only after
// every scope passes may it reconcile an exact marker and settle a v5 head.
func verifyOwnerSettledStartup(ctx context.Context, owner *localPacketOwner, ledger *audit.FileLedger, gitRoot *os.Root) error {
	if owner == nil || !owner.pendingSettlementAudit || owner.store == nil || owner.journal == nil || owner.clock == nil || ledger == nil || gitRoot == nil || ctx == nil {
		return errHistoricalInputIntentQuarantinedAtStartup
	}
	checkGit := func() error {
		location, err := filepath.Abs(gitRoot.Name())
		if err != nil {
			return err
		}
		observed, err := observeLocalSourceDirectory(location, gitRoot)
		if err != nil || observed != owner.gitIdentity {
			return errors.Join(ErrLocalSourceOwnerMismatch, err)
		}
		return nil
	}
	if err := checkGit(); err != nil {
		return err
	}
	facts, rejected, rejectionWindows, err := observeOwnerGenerationRejections(ctx, owner, checkGit)
	if err != nil || len(facts) == 0 {
		return errors.Join(errHistoricalInputIntentQuarantinedAtStartup, err)
	}
	checkRejectionsLive := func() error {
		for _, window := range rejectionWindows {
			if !window.live(owner.clock.Now().UTC()) {
				return errHistoricalInputIntentQuarantinedAtStartup
			}
		}
		return nil
	}
	coordinator, err := controlplane.NewCoordinator(owner.journal)
	if err != nil {
		return err
	}
	verifiedScopes := make(map[string]audit.ReviewScope, len(facts))
	preparedScopes := make(map[string]bool)
	expiredScopes := make(map[string]bool)
	retiredScopes := make(map[string]bool)
	for _, fact := range facts {
		if _, linked := fact.LinkedInputEvent(); !linked && slices.Contains(owner.pendingExpiredPackets, expiredPacketCheckpoint(fact)) {
			continue
		}
		plan, packet := fact.Plan(), fact.PreparedEvent()
		scope := plan.Scope()
		verifiedScopes[scope.Identity()] = scope
		linked, hasInput := fact.LinkedInputEvent()
		settled, hasSettlement := fact.TaskSettlementEvent()
		terminal, hasTerminal := fact.TerminalEvent()
		task, hasTask := plan.Task(packet.TaskKey())
		preparedHead := !hasSettlement && !hasTerminal && fact.FinalHeadIdentity() == linked.Identity()
		settledOwner := hasSettlement && settled.Kind() == controlplane.RunEventContextInputSettled && settled.PreviousIdentity() == linked.Identity() && settled.OutputIdentity() == linked.InputDescriptor().Input.ArtifactIdentity && (!hasTerminal || terminal.Kind() == controlplane.RunEventSucceeded || terminal.Kind() == controlplane.RunEventCanceled)
		expiredTerminal := hasSettlement && settled.Kind() == controlplane.RunEventTaskFailed && settled.Failure() == controlplane.RunFailurePolicy && settled.OutputIdentity() == "" && settled.PreviousIdentity() == linked.Identity() && (!hasTerminal || terminal.Kind() == controlplane.RunEventFailed)
		rejectedGeneration := rejected[scope.Identity()] == fact.FinalHeadIdentity()
		settledOwner = settledOwner || expiredTerminal || rejectedGeneration
		if !hasInput || !hasTask || task.HandlerIdentity() != contexthandler.PacketAuthorityHandlerIdentity() || packet.PacketDescriptor().SourceRootIdentity != owner.sourceRootDigest || linked.Kind() != controlplane.RunEventContextInputPrepared || !(preparedHead || settledOwner) {
			return errHistoricalInputIntentQuarantinedAtStartup
		}
		if preparedHead {
			preparedScopes[scope.Identity()] = true
		}
		saved, state, err := coordinator.Resume(ctx, scope)
		if err != nil || saved.Identity() != plan.Identity() || state.HeadIdentity() != fact.FinalHeadIdentity() || state.Revision() != fact.FinalRevision() {
			return errors.Join(errHistoricalInputIntentQuarantinedAtStartup, err)
		}
		runtime, exists := state.Task(task.Key())
		if !exists || preparedHead && (runtime.Status() != controlplane.TaskRuntimeLeased || runtime.LeaseTokenIdentity() != linked.LeaseTokenIdentity() || runtime.Attempts() != linked.Attempt()) || !preparedHead && !expiredTerminal && (runtime.Status() != controlplane.TaskRuntimeSucceeded || runtime.OutputIdentity() != linked.InputDescriptor().Input.ArtifactIdentity) || expiredTerminal && (runtime.Status() != controlplane.TaskRuntimeFailed || runtime.OutputIdentity() != "" || runtime.Failure() != controlplane.RunFailurePolicy) {
			return errHistoricalInputIntentQuarantinedAtStartup
		}
		canceledBeforeGeneration := hasTerminal && terminal.Kind() == controlplane.RunEventCanceled
		if canceledBeforeGeneration {
			if state.Status() != controlplane.ReviewRunCanceled || !hasSettlement || settled.Kind() != controlplane.RunEventContextInputSettled {
				return errHistoricalInputIntentQuarantinedAtStartup
			}
			for _, key := range []string{"candidates", "verification", "readiness"} {
				downstream, found := state.Task(key)
				if !found || downstream.Attempts() != 0 || downstream.OutputIdentity() != "" || (downstream.Status() != controlplane.TaskRuntimePending && downstream.Status() != controlplane.TaskRuntimeAvailable) {
					return errHistoricalInputIntentQuarantinedAtStartup
				}
			}
		}
		if preparedHead && !owner.clock.Now().UTC().Before(runtime.LeaseExpiresAt()) {
			expiredScopes[scope.Identity()] = true
		}
		if expiredTerminal {
			expiredScopes[scope.Identity()] = true
		}
		if rejectedGeneration {
			continue
		}
		d := linked.InputDescriptor()
		// Past retention a settled input is proved by its journal and the
		// route audit below; its expired envelopes are not read.
		retired := retiredSettledLinked(fact, owner.clock.Now().UTC())
		if retired {
			retiredScopes[scope.Identity()] = true
		}
		expectations := [4]physicalPacketExpectation{
			{scope: scope, descriptor: packet.PacketDescriptor()},
			{scope: scope, role: physicalRoleRequest, input: d.Request},
			{scope: scope, role: physicalRoleReceipt, input: d.Receipt},
			{scope: scope, role: physicalRoleInput, input: d.Input},
		}
		for _, e := range expectations {
			if retired {
				break
			}
			identity := e.descriptor.ArtifactIdentity
			if e.role != physicalRolePacket {
				identity = e.input.ArtifactIdentity
			}
			value, err := owner.store.Get(ctx, scope, identity, owner.clock.Now().UTC())
			if err != nil || !physicalExpectationMatches(value, e) {
				return errors.Join(errHistoricalInputIntentQuarantinedAtStartup, err)
			}
			if _, err := artifact.Encode(value); err != nil {
				return errors.Join(errHistoricalInputIntentQuarantinedAtStartup, err)
			}
		}
		found := 0
		var after uint64
		for {
			events, err := ledger.Read(ctx, scope, after, 64)
			if err != nil {
				return errors.Join(errHistoricalInputIntentQuarantinedAtStartup, err)
			}
			for _, event := range events {
				if canceledBeforeGeneration && (event.Kind() == audit.EventRouteAttemptClaimed || event.Kind() == audit.EventRouteDispatchCompleted || event.Kind() == audit.EventRouteCostReconciled || event.Kind() == audit.EventRouteContinuationPlanned || event.Kind() == audit.EventPublicationClaimed || event.Kind() == audit.EventPublicationCompleted) {
					return errHistoricalInputIntentQuarantinedAtStartup
				}
				if event.Kind() == audit.EventRouteSelected && event.SubjectIdentity() == d.SelectionReceiptIdentity {
					parents := event.CausalParentIdentities()
					if event.OccurredAtUnixMilliseconds() > linked.OccurredAt().UnixMilli() || len(parents) != 3 || !slices.Contains(parents, d.RoutingInputIdentity) || !slices.Contains(parents, d.SelectedRecordIdentity) {
						return errHistoricalInputIntentQuarantinedAtStartup
					}
					found++
				}
			}
			if len(events) < 64 {
				break
			}
			after = events[len(events)-1].Sequence()
		}
		if found != 1 {
			return errHistoricalInputIntentQuarantinedAtStartup
		}
	}
	markerScopes := make(map[string]bool, len(owner.startupScopeIntents))
	for _, markerScope := range owner.startupScopeIntents {
		if _, exists := rejected[markerScope]; exists {
			return controlplane.ErrScopeIntentUnresolved
		}
		markerScopes[markerScope] = true
		if retiredScopes[markerScope] {
			return controlplane.ErrScopeIntentUnresolved
		}
		if _, okay := verifiedScopes[markerScope]; !okay {
			return controlplane.ErrScopeIntentUnresolved
		}
	}
	for scopeID := range preparedScopes {
		if !markerScopes[scopeID] && !expiredScopes[scopeID] {
			return errHistoricalInputIntentQuarantinedAtStartup
		}
	}
	if err := checkGit(); err != nil {
		return err
	}
	if err := checkRejectionsLive(); err != nil {
		return err
	}
	for scopeID := range preparedScopes {
		if expiredScopes[scopeID] {
			if err := checkRejectionsLive(); err != nil {
				return err
			}
			if _, err := owner.journal.TerminateExpiredOwnerContextInput(ctx, owner.store, ledger, verifiedScopes[scopeID], owner.clock); err != nil {
				return err
			}
		}
	}
	for _, markerScope := range owner.startupScopeIntents {
		if expiredScopes[markerScope] {
			if !preparedScopes[markerScope] {
				if err := checkRejectionsLive(); err != nil {
					return err
				}
				if _, err := owner.journal.TerminateExpiredOwnerContextInput(ctx, owner.store, ledger, verifiedScopes[markerScope], owner.clock); err != nil {
					return err
				}
			}
			continue
		}
		scope := verifiedScopes[markerScope]
		if preparedScopes[markerScope] {
			if err := checkRejectionsLive(); err != nil {
				return err
			}
			if err := owner.journal.ReconcilePersistedOwnerContextInputPreparation(ctx, owner.store, ledger, scope, owner.clock); err != nil {
				return err
			}
			continue
		}
		// A v6 head may carry either its own interrupted settlement marker or
		// an older input-preparation marker left after recovery appended v6.
		if err := checkRejectionsLive(); err != nil {
			return err
		}
		if err := owner.journal.ReconcilePersistedOwnerContextInputPreparation(ctx, owner.store, ledger, scope, owner.clock); err != nil {
			if ctx.Err() != nil {
				return err
			}
			if err := checkRejectionsLive(); err != nil {
				return err
			}
			if settledErr := owner.journal.ReconcilePersistedOwnerContextSettlement(ctx, owner.store, ledger, scope, owner.clock); settledErr != nil {
				return errors.Join(err, settledErr)
			}
		}
	}
	if err := checkGit(); err != nil {
		return err
	}
	if err := checkRejectionsLive(); err != nil {
		return err
	}
	owner.settlementAuditVerified = true
	return nil
}
