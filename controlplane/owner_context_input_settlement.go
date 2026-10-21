package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

const ownerContextInputSettlementKind = "input-settle-v1"

// OwnerContextInputSettlement contains the exact owner-prepared v5 envelopes.
// It grants no authority when supplied to public Append or CompleteTask.
type OwnerContextInputSettlement struct {
	Plan     ReviewRunPlan
	Lease    TaskLease
	Prepared PreparedContextInput
	Packet   artifact.Artifact
	Request  artifact.Artifact
	Receipt  artifact.Artifact
	Input    artifact.Artifact
	Clock    artifact.Clock
}

// SettleOwnerContextInput is the only journal append path for v6. A successful
// return requires four physical envelopes, route audit and replayed settlement.
func (j *FileRunJournal) SettleOwnerContextInput(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, req OwnerContextInputSettlement) (ReviewRunState, error) {
	if j == nil || store == nil || ledger == nil || req.Clock == nil || ctx == nil || req.Plan.Validate() != nil || req.Lease.Validate() != nil || req.Prepared.event.Validate() != nil || req.Prepared.event.Kind() != RunEventContextInputPrepared {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	scope := req.Plan.Scope()
	var settlement RunEvent
	var result ReviewRunState
	proof := func(inner context.Context, committed bool) (ReviewRunState, error) {
		return j.verifyOwnerContextInputSettlement(inner, store, ledger, req, committed, settlement.Identity())
	}
	err := j.WithScopeIntentPrepared(ctx, scope, ownerContextInputSettlementKind, func(inner context.Context) (string, error) {
		if _, err := proof(inner, false); err != nil {
			return "", err
		}
		return ownerSettlementExpected(req.Plan, req.Prepared), nil
	}, func(inner context.Context) error {
		if _, err := proof(inner, false); err != nil {
			return err
		}
		now := req.Clock.Now().UTC()
		if now.UnixMilli() <= 0 || !now.Before(req.Lease.ExpiresAt()) || !now.Before(req.Input.ExpiresAt()) {
			return ErrPreparedContextInput
		}
		prior := req.Prepared.event
		settlement = prior
		settlement.kind = RunEventContextInputSettled
		settlement.inputDescriptor = ContextInputDescriptor{}
		settlement.sequence++
		settlement.previousIdentity = prior.Identity()
		settlement.occurredAtMillis = now.UnixMilli()
		settlement.identity = deriveRunEventIdentity(settlement)
		if _, err := EncodeRunEvent(settlement); err != nil {
			return err
		}
		stream, plan, err := j.ownerSettlementStream(inner, scope)
		if err != nil || len(stream) == 0 || stream[len(stream)-1].Identity() != prior.Identity() {
			return errors.Join(ErrPreparedContextInput, err)
		}
		if _, err := ReplayReviewRun(plan, append(stream, settlement)); err != nil {
			return err
		}
		if err := j.appendValidated(inner, prior.Identity(), settlement); err != nil {
			return err
		}
		return nil
	}, func(inner context.Context) error {
		var err error
		result, err = proof(inner, true)
		return err
	})
	if err != nil {
		return ReviewRunState{}, err
	}
	return result, nil
}

// SettlePreparedOwnerContextInput settles only inside the existing preparation
// effect gate, so its marker spans both physical preparation and settlement.
func (j *FileRunJournal) SettlePreparedOwnerContextInput(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, req OwnerContextInputSettlement) (ReviewRunState, error) {
	if j == nil || ctx == nil || store == nil || ledger == nil || req.Clock == nil || req.Plan.Validate() != nil || req.Lease.Validate() != nil || req.Prepared.event.Validate() != nil || req.Prepared.event.Kind() != RunEventContextInputPrepared {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	grant, ok := ctx.Value(scopeGateContextKey{}).(*scopeGateGrant)
	if !ok || grant.journal != j || grant.scope != req.Plan.Scope().Identity() || !grant.live.Load() {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	stream, plan, err := j.ownerSettlementStream(ctx, req.Plan.Scope())
	if err != nil || len(stream) < 2 || stream[len(stream)-1].Identity() != req.Prepared.Identity() {
		return ReviewRunState{}, errors.Join(ErrPreparedContextInput, err)
	}
	path := j.scopeIntentPath(req.Plan.Scope())
	marker, info, err := readOwnerInputPreparationMarker(path)
	canonical, _ := json.Marshal(scopeIntentRecord{Version: 1, Scope: req.Plan.Scope().Identity(), Kind: ownerInputPreparationKind, Expected: ownerInputPreparationExpected(plan, stream[len(stream)-2], req.Prepared)})
	if err != nil || !bytes.Equal(marker, append(canonical, '\n')) {
		return ReviewRunState{}, errors.Join(ErrScopeIntentUnresolved, err)
	}
	if _, err := j.verifyOwnerContextInputSettlement(ctx, store, ledger, req, false, ""); err != nil {
		return ReviewRunState{}, err
	}
	now := req.Clock.Now().UTC()
	if ctx.Err() != nil || now.UnixMilli() <= 0 || !now.Before(req.Lease.ExpiresAt()) || !now.Before(req.Input.ExpiresAt()) {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	event := req.Prepared.event
	event.kind = RunEventContextInputSettled
	event.inputDescriptor = ContextInputDescriptor{}
	event.sequence++
	event.previousIdentity = req.Prepared.Identity()
	event.occurredAtMillis = now.UnixMilli()
	event.identity = deriveRunEventIdentity(event)
	stream, plan, err = j.ownerSettlementStream(ctx, req.Plan.Scope())
	if err != nil || len(stream) == 0 || stream[len(stream)-1].Identity() != req.Prepared.Identity() {
		return ReviewRunState{}, errors.Join(ErrPreparedContextInput, err)
	}
	if _, err := ReplayReviewRun(plan, append(stream, event)); err != nil {
		return ReviewRunState{}, err
	}
	appendAt := req.Clock.Now().UTC()
	if ctx.Err() != nil || appendAt.UnixMilli() <= 0 || !appendAt.Before(req.Lease.ExpiresAt()) || !appendAt.Before(req.Input.ExpiresAt()) {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	if err := j.appendValidated(ctx, req.Prepared.Identity(), event); err != nil {
		return ReviewRunState{}, err
	}
	result, err := j.verifyOwnerContextInputSettlement(ctx, store, ledger, req, true, event.Identity())
	if err != nil {
		return ReviewRunState{}, err
	}
	if err := matchOwnerInputPreparationMarker(path, marker, info); err != nil {
		return ReviewRunState{}, err
	}
	return result, nil
}

func (j *FileRunJournal) verifyOwnerContextInputSettlement(inner context.Context, store *artifact.FileStore, ledger *audit.FileLedger, req OwnerContextInputSettlement, committed bool, settlementIdentity string) (ReviewRunState, error) {
	return j.verifyOwnerContextInputSettlementMode(inner, store, ledger, req, committed, settlementIdentity, false)
}

func (j *FileRunJournal) verifyOwnerContextInputSettlementMode(inner context.Context, store *artifact.FileStore, ledger *audit.FileLedger, req OwnerContextInputSettlement, committed bool, settlementIdentity string, persisted bool) (ReviewRunState, error) {
	scope := req.Plan.Scope()
	stream, plan, err := j.ownerSettlementStream(inner, scope)
	if err != nil || plan.Identity() != req.Plan.Identity() {
		return ReviewRunState{}, errors.Join(ErrPreparedContextInput, err)
	}
	expectedLen := 1
	if committed {
		expectedLen = 2
	}
	if len(stream) < expectedLen || stream[len(stream)-expectedLen].Identity() != req.Prepared.Identity() {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	if committed && (stream[len(stream)-1].Kind() != RunEventContextInputSettled || (settlementIdentity != "" && stream[len(stream)-1].Identity() != settlementIdentity)) {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	state, err := ReplayReviewRun(plan, stream)
	if err != nil {
		return ReviewRunState{}, err
	}
	runtime, ok := state.Task(req.Prepared.event.TaskKey())
	if !ok || req.Prepared.event.TaskIdentity() != runtime.Definition().Identity() {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	if !persisted && req.Lease.Identity() != "" && (req.Lease.Validate() != nil || req.Lease.PlanIdentity() != plan.Identity() || req.Prepared.event.TaskKey() != req.Lease.TaskKey() || req.Prepared.event.Attempt() != req.Lease.Attempt() || req.Prepared.event.LeaseTokenIdentity() != req.Lease.tokenIdentity) {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	if !committed && !persisted && req.Lease.Validate() != nil {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	if committed {
		if runtime.Status() != TaskRuntimeSucceeded || runtime.OutputIdentity() != req.Input.Identity() || (persisted && (state.Status() != ReviewRunActive || state.HeadIdentity() != stream[len(stream)-1].Identity() || runtime.Definition().Kind() != TaskAssembleContext || runtime.preparedEventIdentity != req.Prepared.Identity() || runtime.Attempts() != req.Prepared.event.Attempt() || runtime.LeaseTokenIdentity() != req.Prepared.event.LeaseTokenIdentity())) {
			return ReviewRunState{}, ErrPreparedContextInput
		}
	} else if state.Status() != ReviewRunActive || runtime.Status() != TaskRuntimeLeased || state.HeadIdentity() != req.Prepared.Identity() || (!persisted && !runtimeMatchesLease(runtime, req.Lease)) || (persisted && (runtime.Definition().Kind() != TaskAssembleContext || runtime.Attempts() != req.Prepared.event.Attempt() || runtime.LeaseTokenIdentity() != req.Prepared.event.LeaseTokenIdentity() || runtime.preparedEventIdentity != req.Prepared.Identity())) {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	d := req.Prepared.Descriptor()
	if !d.valid(scope) || d.Input.ArtifactIdentity != req.Input.Identity() || d.PacketArtifactIdentity != req.Packet.Identity() || !ownerSettlementDescriptorMatches(d.Request, req.Request) || !ownerSettlementDescriptorMatches(d.Receipt, req.Receipt) || !ownerSettlementDescriptorMatches(d.Input, req.Input) || req.Prepared.event.PlanIdentity() != plan.Identity() || req.Prepared.event.Scope().Identity() != scope.Identity() || req.Packet.Kind() != artifact.KindContextPacket || req.Request.Kind() != artifact.KindSanitizedModelRequest || req.Receipt.Kind() != artifact.KindSanitizedEgressReceipt || req.Input.Kind() != artifact.KindTaskInput {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	packetEventFound := false
	for _, event := range stream {
		if event.Identity() == d.PacketPreparedEventIdentity && event.Kind() == RunEventContextPacketPrepared && event.PacketDescriptor().ArtifactIdentity == req.Packet.Identity() && event.PacketDescriptor().PayloadDigest == req.Packet.PayloadDigest() && event.PacketDescriptor().LeaseIdentity == d.LeaseIdentity && (persisted || req.Lease.Identity() == "" || event.PacketDescriptor().LeaseIdentity == req.Lease.Identity()) {
			packetEventFound = true
			break
		}
	}
	if !packetEventFound {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	if persisted {
		packet := stream[len(stream)-expectedLen-1].PacketDescriptor()
		if req.Packet.Classification().String() != packet.Classification || req.Packet.Protection().String() != packet.Protection ||
			!slices.Equal(req.Packet.Provenance(), packet.Provenance) || req.Packet.CreatedAt().UnixMilli() != packet.CreatedAtMilliseconds ||
			req.Packet.ExpiresAt().UnixMilli() != packet.ExpiresAtMilliseconds || packet.LeaseEventIdentity != d.LeaseEventIdentity {
			return ReviewRunState{}, fmt.Errorf("persisted packet envelope: %w", ErrPreparedContextInput)
		}
	}
	at := req.Clock.Now().UTC()
	if inner.Err() != nil || at.IsZero() || (!committed && (!at.Before(req.Input.ExpiresAt()) || (persisted && !at.Before(runtime.LeaseExpiresAt())) || (!persisted && !at.Before(req.Lease.ExpiresAt())))) {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	for _, value := range []artifact.Artifact{req.Packet, req.Request, req.Receipt, req.Input} {
		if value.Validate() != nil || value.Scope().Identity() != scope.Identity() {
			return ReviewRunState{}, ErrPreparedContextInput
		}
		stored, getErr := store.Get(inner, scope, value.Identity(), at)
		if getErr != nil || !ownerSettlementBytesEqual(stored, value) {
			return ReviewRunState{}, errors.Join(ErrPreparedContextInput, getErr)
		}
	}
	found := 0
	var after uint64
	for {
		events, readErr := ledger.Read(inner, scope, after, 64)
		if readErr != nil {
			return ReviewRunState{}, readErr
		}
		for _, event := range events {
			if event.Kind() == audit.EventRouteSelected && event.SubjectIdentity() == d.SelectionReceiptIdentity {
				if event.OccurredAtUnixMilliseconds() > req.Prepared.event.occurredAtMillis || !slices.Contains(event.CausalParentIdentities(), d.RoutingInputIdentity) || !slices.Contains(event.CausalParentIdentities(), d.SelectedRecordIdentity) || (persisted && len(event.CausalParentIdentities()) != 3) {
					return ReviewRunState{}, ErrPreparedContextInput
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
		return ReviewRunState{}, ErrPreparedContextInput
	}
	return state, nil
}

// ReconcileOwnerContextSettlement clears only a marker whose v6 head, v5
// ancestry, physical envelopes and route selection still verify after restart.
// A surviving v5 head is uncertain and is never advanced or redispatched here.
func (j *FileRunJournal) ReconcileOwnerContextSettlement(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, req OwnerContextInputSettlement) error {
	if j == nil || store == nil || ledger == nil || req.Clock == nil || ctx == nil || req.Plan.Validate() != nil || req.Lease.Validate() != nil || req.Prepared.event.Validate() != nil || req.Prepared.event.Kind() != RunEventContextInputPrepared {
		return ErrPreparedContextInput
	}
	return j.ReconcileScopeIntent(ctx, req.Plan.Scope(), ownerContextInputSettlementKind, ownerSettlementExpected(req.Plan, req.Prepared), func(inner context.Context) error {
		_, err := j.verifyOwnerContextInputSettlement(inner, store, ledger, req, true, "")
		return err
	})
}

// ReconcilePersistedOwnerContextSettlement re-proves a committed v6 after
// restart without a plaintext lease token or a caller-supplied verifier.
// It cannot advance a v5 head or repair missing artifacts.
func (j *FileRunJournal) ReconcilePersistedOwnerContextSettlement(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, scope audit.ReviewScope, clock artifact.Clock) error {
	if j == nil || store == nil || ledger == nil || clock == nil || ctx == nil || scope.Validate() != nil {
		return ErrPreparedContextInput
	}
	stream, plan, err := j.ownerSettlementStream(ctx, scope)
	if err != nil || len(stream) < 3 || stream[len(stream)-1].Kind() != RunEventContextInputSettled || stream[len(stream)-2].Kind() != RunEventContextInputPrepared {
		return fmt.Errorf("persisted settlement head: %w", errors.Join(ErrPreparedContextInput, err))
	}
	prepared := PreparedContextInput{event: stream[len(stream)-2]}
	d := prepared.Descriptor()
	if !d.valid(scope) {
		return fmt.Errorf("persisted v5 descriptor: %w", ErrPreparedContextInput)
	}
	at := clock.Now().UTC()
	var packetID string
	for _, event := range stream {
		if event.Identity() == d.PacketPreparedEventIdentity && event.Kind() == RunEventContextPacketPrepared {
			packetID = event.PacketDescriptor().ArtifactIdentity
			break
		}
	}
	if packetID != d.PacketArtifactIdentity {
		return fmt.Errorf("persisted packet link: %w", ErrPreparedContextInput)
	}
	values := [4]artifact.Artifact{}
	for i, id := range [4]string{packetID, d.Request.ArtifactIdentity, d.Receipt.ArtifactIdentity, d.Input.ArtifactIdentity} {
		values[i], err = store.Get(ctx, scope, id, at)
		if err != nil {
			return errors.Join(ErrPreparedContextInput, err)
		}
	}
	req := OwnerContextInputSettlement{Plan: plan, Prepared: prepared, Packet: values[0], Request: values[1], Receipt: values[2], Input: values[3], Clock: clock}
	return j.ReconcileScopeIntent(ctx, scope, ownerContextInputSettlementKind, ownerSettlementExpected(plan, prepared), func(inner context.Context) error {
		_, err := j.verifyOwnerContextInputSettlement(inner, store, ledger, req, true, "")
		return err
	})
}

func (j *FileRunJournal) ownerSettlementStream(ctx context.Context, scope audit.ReviewScope) ([]RunEvent, ReviewRunPlan, error) {
	if err := fileRunContextDone(ctx); err != nil {
		return nil, ReviewRunPlan{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil, ReviewRunPlan{}, ErrRunJournalClosed
	}
	plan, ok, err := j.loadPlan(scope)
	if err != nil || !ok {
		return nil, ReviewRunPlan{}, errors.Join(ErrPreparedContextInput, err)
	}
	stream, err := j.loadStream(scope)
	return stream, plan, err
}

const ownerInputPreparationKind = "input-prepare-v1"

// ReconcilePersistedOwnerContextInputPreparation is a closed restart-only recovery
// for the original input-prepare marker. It creates no artifacts or route audit.
func (j *FileRunJournal) ReconcilePersistedOwnerContextInputPreparation(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, scope audit.ReviewScope, clock artifact.Clock) error {
	if j == nil || store == nil || ledger == nil || clock == nil || ctx == nil || scope.Validate() != nil {
		return ErrPreparedContextInput
	}
	if err := validateFileRunContext(ctx); err != nil {
		return err
	}
	return j.withOwnerInputPreparationTransition(ctx, scope, func(inner context.Context) error {
		path := j.scopeIntentPath(scope)
		encoded, markerInfo, err := readOwnerInputPreparationMarker(path)
		if err != nil {
			return err
		}
		stream, plan, err := j.ownerSettlementStream(inner, scope)
		if err != nil || len(stream) < 2 {
			return errors.Join(ErrScopeIntentUnresolved, ErrPreparedContextInput, err)
		}
		committed := stream[len(stream)-1].Kind() == RunEventContextInputSettled
		index := len(stream) - 1
		if committed {
			index--
		}
		if index < 1 || stream[index].Kind() != RunEventContextInputPrepared ||
			(committed && stream[index+1].PreviousIdentity() != stream[index].Identity()) {
			return errors.Join(ErrScopeIntentUnresolved, ErrPreparedContextInput)
		}
		prepared := PreparedContextInput{event: stream[index]}
		d := prepared.Descriptor()
		packet := stream[index-1]
		if !d.valid(scope) || packet.Identity() != d.PacketPreparedEventIdentity || packet.Kind() != RunEventContextPacketPrepared ||
			packet.PacketDescriptor().ArtifactIdentity != d.PacketArtifactIdentity || packet.PacketDescriptor().LeaseIdentity != d.LeaseIdentity ||
			packet.PacketDescriptor().LeaseEventIdentity != d.LeaseEventIdentity || packet.PlanIdentity() != plan.Identity() ||
			packet.TaskKey() != prepared.event.TaskKey() || packet.TaskIdentity() != prepared.event.TaskIdentity() ||
			packet.Attempt() != prepared.event.Attempt() || packet.LeaseTokenIdentity() != prepared.event.LeaseTokenIdentity() ||
			prepared.event.PlanIdentity() != plan.Identity() || prepared.event.Scope().Identity() != scope.Identity() {
			return errors.Join(ErrScopeIntentUnresolved, ErrPreparedContextInput)
		}
		expected := ownerInputPreparationExpected(plan, packet, prepared)
		canonical, _ := json.Marshal(scopeIntentRecord{Version: 1, Scope: scope.Identity(), Kind: ownerInputPreparationKind, Expected: expected})
		canonical = append(canonical, '\n')
		if !bytes.Equal(encoded, canonical) {
			return ErrScopeIntentUnresolved
		}
		prove := func(done bool, settlementIdentity string) (ReviewRunState, error) {
			current, currentPlan, readErr := j.ownerSettlementStream(inner, scope)
			expectedLength := index + 1
			if done {
				expectedLength++
			}
			if readErr != nil || currentPlan.Identity() != plan.Identity() || len(current) != expectedLength ||
				current[index].Identity() != prepared.Identity() || current[index-1].Identity() != packet.Identity() {
				return ReviewRunState{}, errors.Join(ErrPreparedContextInput, readErr)
			}
			if done {
				actual := current[index+1]
				derived := prepared.event
				derived.kind = RunEventContextInputSettled
				derived.inputDescriptor = ContextInputDescriptor{}
				derived.sequence++
				derived.previousIdentity = prepared.Identity()
				derived.occurredAtMillis = actual.occurredAtMillis
				derived.identity = deriveRunEventIdentity(derived)
				if actual.Kind() != RunEventContextInputSettled || actual.Identity() != derived.Identity() ||
					(settlementIdentity != "" && actual.Identity() != settlementIdentity) {
					return ReviewRunState{}, ErrPreparedContextInput
				}
			}
			at := clock.Now().UTC()
			if inner.Err() != nil || at.UnixMilli() <= 0 {
				return ReviewRunState{}, ErrPreparedContextInput
			}
			values := [4]artifact.Artifact{}
			for i, id := range [4]string{d.PacketArtifactIdentity, d.Request.ArtifactIdentity, d.Receipt.ArtifactIdentity, d.Input.ArtifactIdentity} {
				values[i], readErr = store.Get(inner, scope, id, at)
				if readErr != nil {
					return ReviewRunState{}, errors.Join(ErrPreparedContextInput, readErr)
				}
			}
			req := OwnerContextInputSettlement{Plan: plan, Prepared: prepared, Packet: values[0], Request: values[1], Receipt: values[2], Input: values[3], Clock: clock}
			return j.verifyOwnerContextInputSettlementMode(inner, store, ledger, req, done, settlementIdentity, true)
		}
		if _, err := prove(committed, ""); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if !committed {
			if err := matchOwnerInputPreparationMarker(path, encoded, markerInfo); err != nil {
				return err
			}
			state, err := ReplayReviewRun(plan, stream)
			if err != nil {
				return errors.Join(ErrScopeIntentUnresolved, err)
			}
			runtime, ok := state.Task(prepared.event.TaskKey())
			now := clock.Now().UTC()
			if !ok || state.Status() != ReviewRunActive || runtime.Status() != TaskRuntimeLeased ||
				runtime.preparedEventIdentity != prepared.Identity() || runtime.Attempts() != prepared.event.Attempt() ||
				runtime.LeaseTokenIdentity() != prepared.event.LeaseTokenIdentity() || !now.Before(runtime.LeaseExpiresAt()) ||
				!now.Before(runMillisToTime(d.Input.ExpiresAtMilliseconds)) || now.UnixMilli() <= 0 || inner.Err() != nil {
				return errors.Join(ErrScopeIntentUnresolved, ErrPreparedContextInput)
			}
			settlement := prepared.event
			settlement.kind = RunEventContextInputSettled
			settlement.inputDescriptor = ContextInputDescriptor{}
			settlement.sequence++
			settlement.previousIdentity = prepared.Identity()
			settlement.occurredAtMillis = now.UnixMilli()
			settlement.identity = deriveRunEventIdentity(settlement)
			if _, err := EncodeRunEvent(settlement); err != nil {
				return errors.Join(ErrScopeIntentUnresolved, err)
			}
			proposed := append(append([]RunEvent(nil), stream...), settlement)
			proposedState, err := ReplayReviewRun(plan, proposed)
			settled, found := proposedState.Task(prepared.event.TaskKey())
			if err != nil || !found || proposedState.HeadIdentity() != settlement.Identity() || settled.Status() != TaskRuntimeSucceeded ||
				settled.OutputIdentity() != d.Input.ArtifactIdentity || settled.Attempts() != runtime.Attempts() ||
				settled.LeaseTokenIdentity() != runtime.LeaseTokenIdentity() || settled.preparedEventIdentity != prepared.Identity() {
				return errors.Join(ErrScopeIntentUnresolved, ErrPreparedContextInput, err)
			}
			if err := j.appendValidated(inner, prepared.Identity(), settlement); err != nil {
				return errors.Join(ErrScopeIntentUnresolved, err)
			}
			if err := matchOwnerInputPreparationMarker(path, encoded, markerInfo); err != nil {
				return err
			}
			if _, err := prove(true, settlement.Identity()); err != nil {
				return errors.Join(ErrScopeIntentUnresolved, err)
			}
		}
		if err := fileRunContextDone(inner); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		if err := matchOwnerInputPreparationMarker(path, encoded, markerInfo); err != nil {
			return err
		}
		// No fallible filesystem operation follows the original marker removal.
		if err := os.Remove(path); err != nil {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		return nil
	})
}

func ownerInputPreparationExpected(plan ReviewRunPlan, packet RunEvent, prepared PreparedContextInput) string {
	d := prepared.Descriptor()
	value, _ := json.Marshal(struct {
		Version, Plan, Lease, Packet, Root, Request, Receipt, Selection, Policy, Pair, Authorizer string
	}{"local-input-prepare-v1", plan.Identity(), d.LeaseIdentity, packet.Identity(), packet.PacketDescriptor().SourceRootIdentity, d.Request.ArtifactIdentity, d.Receipt.ArtifactIdentity, d.SelectionReceiptIdentity, d.PolicyIdentity, d.RoutePairIdentity, d.AuthorizerIdentity})
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func ownerInputPreparationMarkerInfo(info os.FileInfo) bool {
	return info != nil && info.Mode() == 0o600 && info.Size() > 0 && info.Size() <= 1024 && rootedSingleLink(info) && fileauthority.TrustedOwner(info)
}

func readOwnerInputPreparationMarker(path string) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !ownerInputPreparationMarkerInfo(before) {
		return nil, nil, errors.Join(ErrScopeIntentUnresolved, err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.Join(ErrScopeIntentUnresolved, err)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !rootedSame(before, opened) {
		_ = file.Close()
		return nil, nil, errors.Join(ErrScopeIntentUnresolved, statErr)
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, 1025))
	post, statErr := file.Stat()
	closeErr := file.Close()
	after, lstatErr := os.Lstat(path)
	if int64(len(encoded)) != before.Size() || readErr != nil || statErr != nil || closeErr != nil || lstatErr != nil ||
		!rootedSame(before, post) || !rootedSame(before, after) {
		return nil, nil, errors.Join(ErrScopeIntentUnresolved, readErr, statErr, closeErr, lstatErr)
	}
	return encoded, before, nil
}

func matchOwnerInputPreparationMarker(path string, expected []byte, before os.FileInfo) error {
	current, info, err := readOwnerInputPreparationMarker(path)
	if err != nil || !rootedSame(before, info) || !bytes.Equal(current, expected) {
		return errors.Join(ErrScopeIntentUnresolved, err)
	}
	return nil
}

func ownerSettlementDescriptorMatches(d ContextInputArtifactDescriptor, value artifact.Artifact) bool {
	return value.Validate() == nil && d.ArtifactIdentity == value.Identity() && d.PayloadDigest == value.PayloadDigest() && d.Classification == value.Classification().String() && d.Protection == value.Protection().String() && slices.Equal(d.Provenance, value.Provenance()) && d.CreatedAtMilliseconds == value.CreatedAt().UnixMilli() && d.ExpiresAtMilliseconds == value.ExpiresAt().UnixMilli()
}

func ownerSettlementBytesEqual(left, right artifact.Artifact) bool {
	a, errA := artifact.Encode(left)
	b, errB := artifact.Encode(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// A restart can derive this digest from the durable v5 descriptor; no caller
// supplied marker bytes are trusted as physical evidence.
func ownerSettlementExpected(plan ReviewRunPlan, prepared PreparedContextInput) string {
	d := prepared.Descriptor()
	value, _ := json.Marshal(struct {
		Version, Plan, Prepared, Lease, Packet, Request, Receipt, Input string
	}{"local-input-settle-v1", plan.Identity(), prepared.Identity(), d.LeaseIdentity, d.PacketArtifactIdentity, d.Request.ArtifactIdentity, d.Receipt.ArtifactIdentity, d.Input.ArtifactIdentity})
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
