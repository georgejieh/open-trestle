package context

import (
	"bytes"
	"context"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
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

// SanitizedPacketCandidate is a read-only packet projection. Neither the scanner
// result nor these unpersisted artifacts authorize route selection or dispatch.
type SanitizedPacketCandidate struct {
	packet                           PacketCandidate
	request                          review.SanitizedModelRequest
	receipt                          review.SanitizedEgressReceipt
	requestArtifact, receiptArtifact artifact.Artifact
	scanner                          review.ScannerBinaryDigests
	sanitizerIdentity                string
}

func (c SanitizedPacketCandidate) Packet() PacketCandidate                { return c.packet }
func (c SanitizedPacketCandidate) RequestArtifact() artifact.Artifact     { return c.requestArtifact }
func (c SanitizedPacketCandidate) ReceiptArtifact() artifact.Artifact     { return c.receiptArtifact }
func (c SanitizedPacketCandidate) Receipt() review.SanitizedEgressReceipt { return c.receipt }
func (c SanitizedPacketCandidate) RawRequestIdentity() string             { return c.request.RawRequestIdentity() }
func (c SanitizedPacketCandidate) Scanner() review.ScannerBinaryDigests   { return c.scanner }
func (c SanitizedPacketCandidate) SanitizerIdentity() string              { return c.sanitizerIdentity }
func (c SanitizedPacketCandidate) Request() (provider.Request, error) {
	return c.request.ProviderRequest()
}

// BuildSanitizedPacketCandidate scans only a source-bound candidate. No artifact
// Put or audit append occurs here; the owner must re-fence before any effects.
func BuildSanitizedPacketCandidate(ctx context.Context, candidate PacketCandidate, sanitizer review.GenerationRequestSanitizer, at time.Time) (SanitizedPacketCandidate, error) {
	if nilInterface(ctx) || nilInterface(sanitizer) || ctx.Err() != nil {
		return SanitizedPacketCandidate{}, ErrPacketAuthority
	}
	sanitizerIdentity, scanner := sanitizer.Identity(), sanitizer.ExpectedBinaryDigests()
	if !validDigest(sanitizerIdentity) ||
		candidate.value.Validate() != nil || candidate.value.Kind() != artifact.KindContextPacket ||
		candidate.packet.Validate() != nil || candidate.snapshot.Validate() != nil ||
		candidate.descriptor.ArtifactIdentity != candidate.value.Identity() || candidate.descriptor.SnapshotIdentity != candidate.snapshot.Identity() ||
		candidate.packet.SnapshotIdentity() != candidate.snapshot.Identity() || !at.Before(candidate.value.ExpiresAt()) || at.Before(candidate.value.CreatedAt()) {
		return SanitizedPacketCandidate{}, ErrPacketAuthority
	}
	raw, err := candidate.packet.ProviderRequest()
	if err != nil || !bytes.Equal(raw.Payload(), candidate.value.Payload()) {
		return SanitizedPacketCandidate{}, ErrPacketAuthority
	}
	request, receipt, err := sanitizer.SanitizeGeneration(ctx, raw, candidate.value.Scope().Identity())
	if err != nil || ctx.Err() != nil {
		return SanitizedPacketCandidate{}, ErrPacketAuthority
	}
	requestArtifact, receiptArtifact, err := review.NewSanitizedEgressArtifacts(candidate.value, request, receipt, scanner, at)
	if err != nil || sanitizer.Identity() != sanitizerIdentity || sanitizer.ExpectedBinaryDigests() != scanner || ctx.Err() != nil {
		return SanitizedPacketCandidate{}, ErrPacketAuthority
	}
	return SanitizedPacketCandidate{packet: candidate, request: request, receipt: receipt, requestArtifact: requestArtifact, receiptArtifact: receiptArtifact, scanner: scanner, sanitizerIdentity: sanitizerIdentity}, nil
}

// BuildAuthorizedPacketInput assembles an unpersisted input from a real grant.
// Its caller must prove the grant was audited and recheck the owner before v5.
func BuildAuthorizedPacketInput(ctx context.Context, candidate SanitizedPacketCandidate, authorization gateway.RouteAttemptAuthorization, execution controlplane.TaskExecutionRequest, authorizerIdentity string, at time.Time) (artifact.Artifact, error) {
	packet := candidate.Packet()
	analysis, hasAnalysis := execution.DependencyOutput("analysis")
	memory, hasMemory := execution.DependencyOutput("memory")
	if nilInterface(ctx) || ctx.Err() != nil || execution.Validate() != nil || !hasAnalysis || !hasMemory || !analysis.Available() || !memory.Available() ||
		execution.Task().Kind() != controlplane.TaskAssembleContext || execution.Plan().Scope().Identity() != packet.value.Scope().Identity() || !validDigest(authorizerIdentity) ||
		packet.descriptor.ArtifactIdentity != packet.value.Identity() || packet.descriptor.LeaseIdentity != execution.Lease().Identity() ||
		packet.descriptor.LeaseEventIdentity != execution.Lease().EventIdentity() || packet.descriptor.SnapshotIdentity != packet.snapshot.Identity() ||
		!slices.Equal(packet.descriptor.Provenance, packet.value.Provenance()) ||
		!slices.Contains(packet.value.Provenance(), analysis.OutputIdentity()) || !slices.Contains(packet.value.Provenance(), memory.OutputIdentity()) ||
		authorization.Validate() != nil || candidate.request.Validate() != nil || candidate.receipt.Validate() != nil ||
		packet.value.Validate() != nil || packet.packet.Validate() != nil || packet.snapshot.Validate() != nil ||
		!at.Before(packet.value.ExpiresAt()) || at.Before(candidate.requestArtifact.CreatedAt()) ||
		review.ValidateSanitizedEgressArtifacts(packet.value, candidate.requestArtifact, candidate.receiptArtifact, candidate.scanner) != nil {
		return artifact.Artifact{}, ErrPacketAuthority
	}
	request, err := candidate.Request()
	if err != nil || authorization.RequestIdentity() != request.Identity() || authorization.ReviewScopeIdentity() != packet.value.Scope().Identity() {
		return artifact.Artifact{}, ErrPacketAuthority
	}
	input, err := modelhandler.NewSanitizedGenerationInput(packet.value, packet.packet, packet.snapshot, candidate.requestArtifact, candidate.receiptArtifact, candidate.scanner, authorization)
	if err != nil {
		return artifact.Artifact{}, ErrPacketAuthority
	}
	provenance := []string{analysis.OutputIdentity(), memory.OutputIdentity(), execution.Plan().PolicyIdentity(), authorizerIdentity}
	value, err := modelhandler.NewGenerationInputArtifact(input, packet.value, provenance, at)
	if err != nil {
		return artifact.Artifact{}, ErrPacketAuthority
	}
	return value, nil
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
