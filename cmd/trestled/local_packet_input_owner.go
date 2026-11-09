package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const localInputPrepareIntentKind = "input-prepare-v1"

type localPreparedContextInput struct {
	Prepared                        controlplane.PreparedContextInput
	Packet, Request, Receipt, Input artifact.Artifact
}

// PrepareInput records the v5 checkpoint and its exact physical envelopes.
// It does not settle the task or grant a model dispatch.
func (o *localPacketOwner) PrepareInput(ctx context.Context, request controlplane.TaskExecutionRequest, packet controlplane.PreparedContextPacket, sanitizer review.GenerationRequestSanitizer, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, pair runtimecatalog.LocalGenerationRoutePair, ledger *audit.FileLedger, authorizerIdentity string) (localPreparedContextInput, error) {
	return o.prepareInput(ctx, request, packet, sanitizer, policy, inventory, pair, ledger, authorizerIdentity, false, false)
}

func (o *localPacketOwner) PrepareAndSettleInput(ctx context.Context, request controlplane.TaskExecutionRequest, packet controlplane.PreparedContextPacket, sanitizer review.GenerationRequestSanitizer, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, pair runtimecatalog.LocalGenerationRoutePair, ledger *audit.FileLedger, authorizerIdentity string) (localPreparedContextInput, error) {
	return o.prepareInput(ctx, request, packet, sanitizer, policy, inventory, pair, ledger, authorizerIdentity, true, false)
}

func (o *localPacketOwner) prepareAndSettleInputAfterPacket(ctx context.Context, request controlplane.TaskExecutionRequest, packet controlplane.PreparedContextPacket, sanitizer review.GenerationRequestSanitizer, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, pair runtimecatalog.LocalGenerationRoutePair, ledger *audit.FileLedger, authorizerIdentity string) (localPreparedContextInput, error) {
	return o.prepareInput(ctx, request, packet, sanitizer, policy, inventory, pair, ledger, authorizerIdentity, true, true)
}

func (o *localPacketOwner) prepareInput(ctx context.Context, request controlplane.TaskExecutionRequest, packet controlplane.PreparedContextPacket, sanitizer review.GenerationRequestSanitizer, policy runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, pair runtimecatalog.LocalGenerationRoutePair, ledger *audit.FileLedger, authorizerIdentity string, settle, afterPacket bool) (localPreparedContextInput, error) {
	fail := func(err error) (localPreparedContextInput, error) {
		return localPreparedContextInput{}, errors.Join(contexthandler.ErrPacketAuthority, err)
	}
	if o == nil || o.store == nil || o.journal == nil || o.clock == nil || ctx == nil || request.Validate() != nil || packet.Identity() == "" || ledger == nil || policy.Validate() != nil || inventory.Validate() != nil || pair.Validate() != nil {
		return fail(nil)
	}
	coordinator, err := controlplane.NewCoordinator(o.journal)
	if err != nil {
		return fail(err)
	}
	// This method takes its two gated reads outside the new effect section:
	// WithScopeGate is intentionally not reentrant.
	candidate, expiry, err := o.sanitizePreparedPacket(ctx, request, packet, sanitizer)
	if err != nil {
		if settle && afterPacket && !expiry.sampledAt.IsZero() {
			if terminateErr := o.terminatePacketRecheckExpiry(ctx, request, packet, expiry); terminateErr == nil {
				return localPreparedContextInput{}, nil
			} else {
				return fail(errors.Join(err, terminateErr))
			}
		}
		return fail(err)
	}
	modelRequest, err := candidate.Request()
	if err != nil {
		return fail(err)
	}
	scope := request.Plan().Scope()
	var route runtimecatalog.LocalGenerationRoutePlan
	var prepared controlplane.PreparedContextInput
	var input artifact.Artifact
	var expected [4]artifact.Artifact
	putsCompleted := 0
	var refusal error
	preflight := func(inner context.Context) (string, error) {
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) || !now.Before(candidate.Packet().Artifact().ExpiresAt()) {
			return "", fmt.Errorf("input preflight time: %w", contexthandler.ErrPacketAuthority)
		}
		if err := o.packetFence(inner, coordinator, request, packet, candidate.Packet().Artifact()); err != nil {
			return "", fmt.Errorf("input preflight packet fence: %w", err)
		}
		stored, err := o.store.Get(inner, scope, packet.Descriptor().ArtifactIdentity, now)
		if err != nil || !localInputBytesEqual(stored, candidate.Packet().Artifact()) {
			return "", errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		route, err = runtimecatalog.PlanLocalGenerationRoute(inner, scope, modelRequest, policy, inventory, pair)
		if err != nil {
			if _, _, ok := localPacketRouteRefusal(err); ok {
				refusal = err
			}
			return "", err
		}
		preimage, err := json.Marshal(struct {
			Version, Plan, Lease, Packet, Root, Request, Receipt, Selection, Policy, Pair, Authorizer string
		}{"local-input-prepare-v1", request.Plan().Identity(), request.Lease().Identity(), packet.Identity(), o.sourceRootDigest, candidate.RequestArtifact().Identity(), candidate.ReceiptArtifact().Identity(), route.SelectionIdentity(), policy.Identity(), pair.Identity(), authorizerIdentity})
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256(preimage)
		return hex.EncodeToString(digest[:]), nil
	}
	err = o.journal.WithScopeIntentPrepared(ctx, scope, localInputPrepareIntentKind, preflight, func(inner context.Context) error {
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) {
			return fmt.Errorf("input effect time: %w", contexthandler.ErrPacketAuthority)
		}
		if err := o.packetFence(inner, coordinator, request, packet, candidate.Packet().Artifact()); err != nil {
			return fmt.Errorf("input effect packet fence: %w", err)
		}
		grant, err := runtimecatalog.GrantLocalGenerationRoute(inner, scope, modelRequest, policy, inventory, pair, route, ledger, now)
		if err != nil {
			return err
		}
		now = o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) {
			return contexthandler.ErrPacketAuthority
		}
		input, err = contexthandler.BuildAuthorizedPacketInput(inner, candidate, grant, request, authorizerIdentity, now)
		if err != nil {
			return fmt.Errorf("build authorized input: %w", err)
		}
		descriptor, err := buildLocalContextInputDescriptor(packet, request.Lease(), candidate, input, grant, route, authorizerIdentity)
		if err != nil {
			return fmt.Errorf("build input descriptor: %w", err)
		}
		prepared, err = coordinator.PrepareContextInput(inner, request.Plan(), request.Lease(), packet, descriptor, now)
		if err != nil {
			return err
		}
		expected = [4]artifact.Artifact{candidate.Packet().Artifact(), candidate.RequestArtifact(), candidate.ReceiptArtifact(), input}
		if o.beforeInputPut != nil {
			o.beforeInputPut()
		}
		abortExpired := func() error {
			if inner.Err() != nil || o.clock.Now().UTC().Before(request.Lease().ExpiresAt()) {
				return contexthandler.ErrPacketAuthority
			}
			for i, value := range expected {
				stored, err := o.store.Get(inner, scope, value.Identity(), o.clock.Now().UTC())
				if i == 0 || i <= putsCompleted {
					if err != nil || !localInputBytesEqual(stored, value) {
						return errors.Join(contexthandler.ErrPacketAuthority, err)
					}
				} else if !errors.Is(err, artifact.ErrArtifactNotFound) {
					return errors.Join(contexthandler.ErrPacketAuthority, err)
				}
			}
			if putsCompleted == 3 {
				return contexthandler.ErrPacketAuthority
			}
			if _, err := coordinator.TerminatePreparedContextInput(inner, request.Plan(), prepared, o.clock.Now().UTC()); err != nil {
				return err
			}
			return contexthandler.ErrPacketAuthority
		}
		for _, value := range expected[1:] {
			now = o.clock.Now().UTC()
			if !ownerPacketTimeValid(inner, request, now) || !now.Before(value.ExpiresAt()) {
				return abortExpired()
			}
			if _, err := o.store.Put(inner, value, now); err != nil {
				return err
			}
			putsCompleted++
		}
		if !o.clock.Now().UTC().Before(request.Lease().ExpiresAt()) {
			return abortExpired()
		}
		if settle {
			_, err := o.journal.SettlePreparedOwnerContextInput(inner, o.store, ledger, controlplane.OwnerContextInputSettlement{
				Plan: request.Plan(), Lease: request.Lease(), Prepared: prepared,
				Packet: expected[0], Request: expected[1], Receipt: expected[2], Input: expected[3], Clock: o.clock,
			})
			return err
		}
		return nil
	}, func(inner context.Context) error {
		if settle {
			_, state, err := coordinator.Resume(inner, scope)
			task, found := state.Task(request.Task().Key())
			if err != nil || !found || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() != input.Identity() {
				return errors.Join(contexthandler.ErrPacketAuthority, err)
			}
			return nil
		}
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(inner, request, now) {
			return contexthandler.ErrPacketAuthority
		}
		head, present, err := o.journal.Head(inner, scope)
		if err != nil || !present || head.Identity() != prepared.Identity() || head.Kind() != controlplane.RunEventContextInputPrepared || !reflect.DeepEqual(head.InputDescriptor(), prepared.Descriptor()) {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		plan, state, err := coordinator.Resume(inner, scope)
		if err != nil || plan.Identity() != request.Plan().Identity() || state.HeadIdentity() != prepared.Identity() {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		task, exists := state.Task(request.Task().Key())
		current, hasPrepared := task.PreparedContextInput()
		if !exists || !hasPrepared || current.Identity() != prepared.Identity() {
			return contexthandler.ErrPacketAuthority
		}
		for _, value := range expected {
			stored, err := o.store.Get(inner, scope, value.Identity(), now)
			if err != nil || !localInputBytesEqual(stored, value) {
				return errors.Join(contexthandler.ErrPacketAuthority, err)
			}
		}
		found := 0
		var after uint64
		for {
			events, err := ledger.Read(inner, scope, after, 64)
			if err != nil {
				return err
			}
			for _, event := range events {
				if event.Kind() == audit.EventRouteSelected && event.SubjectIdentity() == prepared.Descriptor().SelectionReceiptIdentity {
					found++
				}
			}
			if len(events) < 64 {
				break
			}
			after = events[len(events)-1].Sequence()
		}
		if found != 1 {
			return contexthandler.ErrPacketAuthority
		}
		return nil
	})
	if err != nil && refusal != nil && settle && afterPacket {
		// No intent marker was written: the refusal came from the preflight.
		if refuseErr := o.refusePacketRoute(ctx, request, packet, refusal); refuseErr != nil {
			return fail(errors.Join(err, refuseErr))
		}
		return localPreparedContextInput{}, nil
	}
	if err != nil {
		return fail(err)
	}
	return localPreparedContextInput{Prepared: prepared, Packet: expected[0], Request: expected[1], Receipt: expected[2], Input: input}, nil
}

func localInputBytesEqual(left, right artifact.Artifact) bool {
	a, errA := artifact.Encode(left)
	b, errB := artifact.Encode(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}
