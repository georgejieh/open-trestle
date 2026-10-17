package context

import (
	"context"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/review"
)

// ArtifactReader exposes only the read operation needed to build a packet candidate.
type ArtifactReader interface {
	Get(context.Context, audit.ReviewScope, string, time.Time) (artifact.Artifact, error)
}

// PacketCandidate is assembled evidence, not authority to prepare or persist it.
type PacketCandidate struct {
	value      artifact.Artifact
	descriptor controlplane.ContextPacketDescriptor
	packet     review.ContextPacket
	snapshot   review.ReviewSnapshot
}

func (c PacketCandidate) Artifact() artifact.Artifact     { return c.value }
func (c PacketCandidate) Packet() review.ContextPacket    { return c.packet }
func (c PacketCandidate) Snapshot() review.ReviewSnapshot { return c.snapshot }
func (c PacketCandidate) Descriptor() controlplane.ContextPacketDescriptor {
	descriptor := c.descriptor
	descriptor.Provenance = slices.Clone(descriptor.Provenance)
	descriptor.DependencyIdentities = slices.Clone(descriptor.DependencyIdentities)
	return descriptor
}

// readOnlyPacketStore adapts assembly's Store dependency without granting it writes.
type readOnlyPacketStore struct{ reader ArtifactReader }

func (s readOnlyPacketStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	return s.reader.Get(ctx, scope, id, at)
}
func (readOnlyPacketStore) Put(context.Context, artifact.Artifact, time.Time) (bool, error) {
	return false, ErrPacketAuthority
}

// BuildPacketCandidate proves the complete source chain without appending or writing artifacts.
// Caller-provided reads may have effects; state and expectedSourceRoot are not owner credentials.
func BuildPacketCandidate(ctx context.Context, reader ArtifactReader, request controlplane.TaskExecutionRequest, state controlplane.ReviewRunState, clock artifact.Clock, expectedSourceRoot string, readAt, createdAt time.Time) (PacketCandidate, error) {
	if nilInterface(ctx) || nilInterface(reader) || nilInterface(clock) || !validDigest(expectedSourceRoot) ||
		request.Validate() != nil || request.Task().Kind() != controlplane.TaskAssembleContext ||
		request.Task().HandlerIdentity() != PacketAuthorityHandlerIdentity() || request.Task().MaxAttempts() != 1 ||
		!equalStrings(request.Task().Dependencies(), []string{"analysis", "memory"}) ||
		state.Validate() != nil || state.Status() != controlplane.ReviewRunActive || state.Plan().Identity() != request.Plan().Identity() ||
		state.Plan().Scope().Identity() != request.Plan().Scope().Identity() || ctx.Err() != nil {
		return PacketCandidate{}, ErrPacketAuthority
	}
	now := clock.Now().UTC()
	if now.UnixMilli() <= 0 || readAt.UnixMilli() <= 0 || createdAt.UnixMilli() <= 0 ||
		!now.Before(request.Lease().ExpiresAt()) || !readAt.Before(request.Lease().ExpiresAt()) ||
		createdAt.After(readAt) || ctx.Err() != nil {
		return PacketCandidate{}, ErrPacketAuthority
	}
	assembler := packetAssembler{store: readOnlyPacketStore{reader: reader}, clock: clock, ownerRoot: expectedSourceRoot}
	built, err := assembler.rebuild(ctx, request, state, readAt, createdAt)
	if err != nil {
		return PacketCandidate{}, err
	}
	value := built.value
	if value.Protection() != artifact.ProtectionProcessPrivate || !value.ExpiresAt().After(request.Lease().ExpiresAt()) ||
		!clock.Now().UTC().Before(request.Lease().ExpiresAt()) || ctx.Err() != nil {
		return PacketCandidate{}, ErrPacketAuthority
	}
	dependencies := []string{}
	for _, output := range request.DependencyOutputs() {
		if !output.Available() {
			return PacketCandidate{}, ErrPacketAuthority
		}
		dependencies = append(dependencies, output.OutputIdentity())
	}
	slices.Sort(dependencies)
	descriptor := controlplane.ContextPacketDescriptor{
		ArtifactIdentity: value.Identity(), LeaseIdentity: request.Lease().Identity(), LeaseEventIdentity: request.Lease().EventIdentity(),
		PayloadDigest: value.PayloadDigest(), Classification: value.Classification().String(), Protection: value.Protection().String(),
		Provenance: value.Provenance(), SourceRootIdentity: built.root, SnapshotIdentity: built.snapshot,
		DependencyIdentities: dependencies, CreatedAtMilliseconds: value.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: value.ExpiresAt().UnixMilli(),
	}
	if !validDigest(descriptor.SnapshotIdentity) {
		return PacketCandidate{}, ErrPacketAuthority
	}
	return PacketCandidate{value: value, descriptor: descriptor, packet: built.packet, snapshot: built.snapshotValue}, nil
}
