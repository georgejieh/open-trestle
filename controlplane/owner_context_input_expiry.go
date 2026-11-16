package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

// TerminateExpiredOwnerContextInput is a no-output recovery for a complete v5.
// It preserves all four envelopes and route evidence, never revives a lease,
// and clears only an exact preparation or settlement marker after proof.
func (j *FileRunJournal) TerminateExpiredOwnerContextInput(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, scope audit.ReviewScope, clock artifact.Clock) (ReviewRunState, error) {
	if j == nil || store == nil || ledger == nil || clock == nil || ctx == nil || scope.Validate() != nil {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	var result ReviewRunState
	err := j.withOwnerContextExpiryTransition(ctx, scope, func(inner context.Context) error {
		stream, plan, err := j.ownerSettlementStream(inner, scope)
		if err != nil || len(stream) < 2 {
			return errors.Join(ErrPreparedContextInput, err)
		}
		index := -1
		for i := len(stream) - 1; i >= 1; i-- {
			if stream[i].Kind() == RunEventContextInputPrepared {
				index = i
				break
			}
		}
		if index < 1 || stream[index-1].Kind() != RunEventContextPacketPrepared {
			return ErrPreparedContextInput
		}
		terminated := len(stream) > index+1
		if terminated {
			for _, event := range stream[index+2:] {
				if event.Kind() != RunEventTaskSkipped && event.Kind() != RunEventFailed {
					return ErrPreparedContextInput
				}
			}
		}
		prepared := PreparedContextInput{event: stream[index]}
		packet := stream[index-1]
		state, err := ReplayReviewRun(plan, stream)
		if err != nil {
			return err
		}
		before, err := ReplayReviewRun(plan, stream[:index+1])
		if err != nil {
			return err
		}
		runtime, ok := before.Task(prepared.event.TaskKey())
		now := clock.Now().UTC()
		if !ok || before.Status() != ReviewRunActive || runtime.Status() != TaskRuntimeLeased || runtime.preparedEventIdentity != prepared.Identity() || now.UnixMilli() <= 0 || now.Before(runtime.LeaseExpiresAt()) || !transitionTimeAllowed(state, now) {
			return ErrPreparedContextInput
		}
		expected, err := NewRunEvent(plan, prepared.event.Sequence()+1, prepared.Identity(), RunEventTaskFailed, runtime.Definition(), runtime.Attempts(), runtime.LeaseTokenIdentity(), "", time.Time{}, "", RunFailurePolicy, time.Time{}, now)
		if err != nil {
			return err
		}
		if terminated {
			actual := stream[index+1]
			expected.occurredAtMillis = actual.occurredAtMillis
			expected.identity = deriveRunEventIdentity(expected)
			if actual.Identity() != expected.Identity() {
				return ErrPreparedContextInput
			}
		}
		path := j.scopeIntentPath(scope)
		var marker []byte
		var info os.FileInfo
		if _, err := os.Lstat(path); err == nil {
			marker, info, err = readOwnerInputPreparationMarker(path)
			if err != nil {
				return err
			}
			valid := false
			for kind, digest := range map[string]string{ownerInputPreparationKind: ownerInputPreparationExpected(plan, packet, prepared), ownerContextInputSettlementKind: ownerSettlementExpected(plan, prepared)} {
				canonical, _ := json.Marshal(scopeIntentRecord{Version: 1, Scope: scope.Identity(), Kind: kind, Expected: digest})
				if bytes.Equal(marker, append(canonical, '\n')) {
					valid = true
				}
			}
			if !valid {
				return ErrScopeIntentUnresolved
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.Join(ErrScopeIntentUnresolved, err)
		}
		values, err := verifyExpiredOwnerInputBytes(inner, store, ledger, plan, packet, prepared, now)
		if err != nil {
			return err
		}
		if !terminated {
			if _, err := ReplayReviewRun(plan, append(stream, expected)); err != nil {
				return err
			}
			if marker != nil {
				if err := matchOwnerInputPreparationMarker(path, marker, info); err != nil {
					return err
				}
			}
			if err := j.appendValidated(inner, prepared.Identity(), expected); err != nil {
				return err
			}
		}
		current, currentPlan, err := j.ownerSettlementStream(inner, scope)
		expectedLength := len(stream)
		if !terminated {
			expectedLength++
		}
		if err != nil || currentPlan.Identity() != plan.Identity() || len(current) != expectedLength || current[index+1].Identity() != expected.Identity() {
			return errors.Join(ErrPreparedContextInput, err)
		}
		result, err = ReplayReviewRun(plan, current)
		if err != nil {
			return err
		}
		after, err := verifyExpiredOwnerInputBytes(inner, store, ledger, plan, packet, prepared, clock.Now().UTC())
		if err != nil {
			return err
		}
		for i := range values {
			if !ownerSettlementBytesEqual(values[i], after[i]) {
				return ErrPreparedContextInput
			}
		}
		if err := fileRunContextDone(inner); err != nil {
			return err
		}
		if marker != nil {
			if err := matchOwnerInputPreparationMarker(path, marker, info); err != nil {
				return err
			}
			if err := os.Remove(path); err != nil {
				return errors.Join(ErrScopeIntentUnresolved, err)
			}
		}
		return nil
	})
	return result, err
}

func verifyExpiredOwnerInputBytes(ctx context.Context, store *artifact.FileStore, ledger *audit.FileLedger, plan ReviewRunPlan, packet RunEvent, prepared PreparedContextInput, at time.Time) ([4]artifact.Artifact, error) {
	var values [4]artifact.Artifact
	d := prepared.Descriptor()
	p := packet.PacketDescriptor()
	if ctx.Err() != nil || !d.valid(plan.Scope()) || packet.Identity() != d.PacketPreparedEventIdentity || p.ArtifactIdentity != d.PacketArtifactIdentity || p.LeaseIdentity != d.LeaseIdentity || p.LeaseEventIdentity != d.LeaseEventIdentity {
		return values, ErrPreparedContextInput
	}
	for i, id := range [4]string{d.PacketArtifactIdentity, d.Request.ArtifactIdentity, d.Receipt.ArtifactIdentity, d.Input.ArtifactIdentity} {
		value, err := store.Get(ctx, plan.Scope(), id, at)
		if err != nil {
			return values, errors.Join(ErrPreparedContextInput, err)
		}
		values[i] = value
	}
	value := values[0]
	if value.Kind() != artifact.KindContextPacket || value.PayloadDigest() != p.PayloadDigest || value.Classification().String() != p.Classification || value.Protection().String() != p.Protection || !slices.Equal(value.Provenance(), p.Provenance) || value.CreatedAt().UnixMilli() != p.CreatedAtMilliseconds || value.ExpiresAt().UnixMilli() != p.ExpiresAtMilliseconds {
		return values, ErrPreparedContextInput
	}
	for i, desc := range []ContextInputArtifactDescriptor{d.Request, d.Receipt, d.Input} {
		if !ownerSettlementDescriptorMatches(desc, values[i+1]) {
			return values, ErrPreparedContextInput
		}
	}
	if values[1].Kind() != artifact.KindSanitizedModelRequest || values[2].Kind() != artifact.KindSanitizedEgressReceipt || values[3].Kind() != artifact.KindTaskInput {
		return values, ErrPreparedContextInput
	}
	found := 0
	var after uint64
	for {
		events, err := ledger.Read(ctx, plan.Scope(), after, 64)
		if err != nil {
			return values, err
		}
		for _, event := range events {
			if event.Kind() == audit.EventRouteSelected && event.SubjectIdentity() == d.SelectionReceiptIdentity {
				parents := event.CausalParentIdentities()
				if event.OccurredAtUnixMilliseconds() > prepared.event.occurredAtMillis || len(parents) != 3 || !slices.Contains(parents, d.RoutingInputIdentity) || !slices.Contains(parents, d.SelectedRecordIdentity) {
					return values, ErrPreparedContextInput
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
		return values, ErrPreparedContextInput
	}
	return values, nil
}
