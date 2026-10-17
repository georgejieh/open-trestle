package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

// localPacketOwner is minted only by the Git-qualified local startup gate.
// Its journal's effect section excludes a durable cancellation until Put returns.
type localPacketOwner struct {
	store            *artifact.FileStore
	journal          *controlplane.FileRunJournal
	sourceRootDigest string
	clock            artifact.Clock
	beforeRawPut     func() // test-only, installed before concurrent use
}

func (o *localPacketOwner) PreparePacket(ctx context.Context, request controlplane.TaskExecutionRequest) (controlplane.PreparedContextPacket, error) {
	if o == nil || o.store == nil || o.journal == nil || o.clock == nil || ctx == nil || request.Validate() != nil {
		return controlplane.PreparedContextPacket{}, contexthandler.ErrPacketAuthority
	}
	coordinator, err := controlplane.NewCoordinator(o.journal)
	if err != nil {
		return controlplane.PreparedContextPacket{}, errors.Join(contexthandler.ErrPacketAuthority, err)
	}
	var prepared controlplane.PreparedContextPacket
	err = o.journal.WithEffectSection(ctx, func() error {
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(ctx, request, now) {
			return contexthandler.ErrPacketAuthority
		}
		plan, state, resumeErr := coordinator.Resume(ctx, request.Plan().Scope())
		if resumeErr != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive {
			return errors.Join(contexthandler.ErrPacketAuthority, resumeErr)
		}
		// Candidate construction performs the source full-chain proof using only
		// Get on the actual boot store, while cancellation remains outside the gate.
		candidate, buildErr := contexthandler.BuildPacketCandidate(ctx, o.store, request, state, o.clock, o.sourceRootDigest, now, now)
		if buildErr != nil {
			return errors.Join(contexthandler.ErrPacketAuthority, buildErr)
		}
		value, descriptor := candidate.Artifact(), candidate.Descriptor()
		now = o.clock.Now().UTC()
		if !ownerPacketTimeValid(ctx, request, now) || !now.Before(value.ExpiresAt()) {
			return contexthandler.ErrPacketAuthority
		}
		prepared, err = coordinator.PrepareContextPacket(ctx, request.Plan(), request.Lease(), descriptor, now)
		if err != nil {
			return errors.Join(contexthandler.ErrPacketAuthority, err)
		}
		if err := o.packetFence(ctx, coordinator, request, prepared, value); err != nil {
			return err
		}
		if o.beforeRawPut != nil {
			o.beforeRawPut()
		}
		now = o.clock.Now().UTC()
		if !ownerPacketTimeValid(ctx, request, now) || !now.Before(value.ExpiresAt()) {
			return contexthandler.ErrPacketAuthority
		}
		// Keep the section through the *actual* Put return, including errors.
		if _, putErr := o.store.Put(ctx, value, now); putErr != nil {
			return errors.Join(contexthandler.ErrPacketAuthority, putErr)
		}
		now = o.clock.Now().UTC()
		if !ownerPacketTimeValid(ctx, request, now) || !now.Before(value.ExpiresAt()) {
			return contexthandler.ErrPacketAuthority
		}
		stored, getErr := o.store.Get(ctx, request.Plan().Scope(), value.Identity(), now)
		if getErr != nil {
			return errors.Join(contexthandler.ErrPacketAuthority, getErr)
		}
		want, wantErr := artifact.Encode(value)
		got, gotErr := artifact.Encode(stored)
		if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
			return errors.Join(contexthandler.ErrPacketAuthority, wantErr, gotErr)
		}
		return o.packetFence(ctx, coordinator, request, prepared, value)
	})
	return prepared, err
}

// LoadPreparedPacket returns the exact stored packet only while its enrolled
// owner, lease, and journal checkpoint remain live. It grants no model authority.
func (o *localPacketOwner) LoadPreparedPacket(ctx context.Context, request controlplane.TaskExecutionRequest, prepared controlplane.PreparedContextPacket) (artifact.Artifact, error) {
	if o == nil || o.store == nil || o.journal == nil || o.clock == nil || ctx == nil || request.Validate() != nil || prepared.Identity() == "" {
		return artifact.Artifact{}, contexthandler.ErrPacketAuthority
	}
	coordinator, err := controlplane.NewCoordinator(o.journal)
	if err != nil {
		return artifact.Artifact{}, errors.Join(contexthandler.ErrPacketAuthority, err)
	}
	var stored artifact.Artifact
	err = o.journal.WithEffectSection(ctx, func() error {
		now := o.clock.Now().UTC()
		if !ownerPacketTimeValid(ctx, request, now) || !now.Before(time.UnixMilli(prepared.Descriptor().ExpiresAtMilliseconds)) {
			return contexthandler.ErrPacketAuthority
		}
		value, getErr := o.store.Get(ctx, request.Plan().Scope(), prepared.Descriptor().ArtifactIdentity, now)
		if getErr != nil {
			return errors.Join(contexthandler.ErrPacketAuthority, getErr)
		}
		if value.Kind() != artifact.KindContextPacket || value.Protection() != artifact.ProtectionProcessPrivate || value.ExpiresAt().UnixMilli() != prepared.Descriptor().ExpiresAtMilliseconds {
			return contexthandler.ErrPacketAuthority
		}
		if err := o.packetFence(ctx, coordinator, request, prepared, value); err != nil {
			return err
		}
		stored = value
		return nil
	})
	if err != nil {
		return artifact.Artifact{}, err
	}
	return stored, nil
}

func ownerPacketTimeValid(ctx context.Context, request controlplane.TaskExecutionRequest, now time.Time) bool {
	return ctx.Err() == nil && now.UnixMilli() > 0 && now.Before(request.Lease().ExpiresAt())
}

func (o *localPacketOwner) packetFence(ctx context.Context, coordinator *controlplane.Coordinator, request controlplane.TaskExecutionRequest, prepared controlplane.PreparedContextPacket, expected artifact.Artifact) error {
	now := o.clock.Now().UTC()
	if !ownerPacketTimeValid(ctx, request, now) || !now.Before(expected.ExpiresAt()) {
		return contexthandler.ErrPacketAuthority
	}
	plan, state, err := coordinator.Resume(ctx, request.Plan().Scope())
	if err != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive || state.HeadIdentity() != prepared.Identity() {
		return errors.Join(contexthandler.ErrPacketAuthority, err)
	}
	head, present, headErr := o.journal.Head(ctx, request.Plan().Scope())
	if headErr != nil || !present || head.Identity() != prepared.Identity() || !reflect.DeepEqual(head.PacketDescriptor(), prepared.Descriptor()) {
		return errors.Join(contexthandler.ErrPacketAuthority, headErr)
	}
	runtime, found := state.Task(request.Task().Key())
	current, hasPrepared := runtime.PreparedContextPacket()
	if !found || !hasPrepared || current.Identity() != prepared.Identity() || !reflect.DeepEqual(current.Descriptor(), prepared.Descriptor()) {
		return contexthandler.ErrPacketAuthority
	}
	candidate, buildErr := contexthandler.BuildPacketCandidate(ctx, o.store, request, state, o.clock, o.sourceRootDigest, now, expected.CreatedAt())
	if buildErr != nil || !reflect.DeepEqual(candidate.Descriptor(), prepared.Descriptor()) {
		return errors.Join(contexthandler.ErrPacketAuthority, buildErr)
	}
	want, wantErr := artifact.Encode(expected)
	got, gotErr := artifact.Encode(candidate.Artifact())
	if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		return errors.Join(contexthandler.ErrPacketAuthority, wantErr, gotErr)
	}
	return nil
}
