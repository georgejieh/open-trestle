package context

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/sourceinput"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

var ErrPacketAuthority = errors.New("packet authority or effect fence unavailable")

// PacketAuthority is an unwired, packet-only preparation boundary. Its optional
// shared journal gate cooperatively orders cancellation and physical Put, but
// does not authenticate root ownership or make two stores crash-atomic.
// Its return value is an intent, never a successful task completion.
type packetBuild struct {
	value          artifact.Artifact
	root, snapshot string
	packet         review.ContextPacket
	snapshotValue  review.ReviewSnapshot
}

// packetAssembler checks the source-bound packet without owning any effect boundary.
type packetAssembler struct {
	store     artifact.Store
	clock     artifact.Clock
	ownerRoot string
}

type PacketAuthority struct {
	store       artifact.Store
	coordinator *controlplane.Coordinator
	clock       artifact.Clock
	ownerRoot   string
}

// leaseBoundReads timestamps every assembly Get at the actual read boundary.
// This is not an atomic fence against cancellation during a Store operation.
type leaseBoundReads struct {
	artifact.Store
	clock artifact.Clock
	lease controlplane.TaskLease
}

func (r leaseBoundReads) Get(ctx context.Context, scope audit.ReviewScope, id string, _ time.Time) (artifact.Artifact, error) {
	now := r.clock.Now().UTC()
	if ctx.Err() != nil || !now.Before(r.lease.ExpiresAt()) {
		return artifact.Artifact{}, ErrPacketAuthority
	}
	return r.Store.Get(ctx, scope, id, now)
}
func (r leaseBoundReads) Put(context.Context, artifact.Artifact, time.Time) (bool, error) {
	return false, ErrPacketAuthority
}

func NewPacketAuthority(store artifact.Store, coordinator *controlplane.Coordinator, clock artifact.Clock, ownerRoot string) *PacketAuthority {
	return &PacketAuthority{store: store, coordinator: coordinator, clock: clock, ownerRoot: ownerRoot}
}

func PacketAuthorityHandlerIdentity() string {
	digest := sha256.Sum256([]byte("open-trestle/context-packet-authority-v4"))
	return hex.EncodeToString(digest[:])
}

func (p *PacketAuthority) Prepare(ctx context.Context, request controlplane.TaskExecutionRequest) (controlplane.PreparedContextPacket, error) {
	if p == nil || nilInterface(ctx) || nilInterface(p.store) || nilInterface(p.clock) || p.coordinator == nil || !validDigest(p.ownerRoot) ||
		request.Validate() != nil || request.Task().Kind() != controlplane.TaskAssembleContext ||
		request.Task().HandlerIdentity() != PacketAuthorityHandlerIdentity() ||
		request.Task().MaxAttempts() != 1 || !equalStrings(request.Task().Dependencies(), []string{"analysis", "memory"}) {
		return controlplane.PreparedContextPacket{}, ErrPacketAuthority
	}
	now := p.clock.Now().UTC()
	if ctx.Err() != nil || now.UnixMilli() <= 0 || !now.Before(request.Lease().ExpiresAt()) {
		return controlplane.PreparedContextPacket{}, ErrPacketAuthority
	}
	state, err := p.current(ctx, request)
	if err != nil {
		return controlplane.PreparedContextPacket{}, err
	}
	runtime, _ := state.Task(request.Task().Key())
	createdAt := now
	if prior, ok := runtime.PreparedContextPacket(); ok {
		createdAt = time.UnixMilli(prior.Descriptor().CreatedAtMilliseconds)
	}
	candidate, err := BuildPacketCandidate(ctx, p.store, request, state, p.clock, p.ownerRoot, now, createdAt)
	if err != nil {
		return controlplane.PreparedContextPacket{}, err
	}
	value, descriptor := candidate.Artifact(), candidate.Descriptor()
	root := descriptor.SourceRootIdentity
	now = p.clock.Now().UTC()
	if ctx.Err() != nil || !now.Before(request.Lease().ExpiresAt()) || !now.Before(value.ExpiresAt()) {
		return controlplane.PreparedContextPacket{}, ErrPacketAuthority
	}
	// A fresh state/source/lease check, v4 CAS, physical Put (including an
	// error-after-rename return), readback, and final fence share the same live
	// journal gate used by canceled Append. Unsupported journals fail before v4.
	var prepared controlplane.PreparedContextPacket
	err = p.coordinator.WithPacketEffectSection(ctx, func() error {
		freshAt := p.clock.Now().UTC()
		if ctx.Err() != nil || !freshAt.Before(request.Lease().ExpiresAt()) || !freshAt.Before(value.ExpiresAt()) {
			return ErrPacketAuthority
		}
		freshState, stateErr := p.current(ctx, request)
		if stateErr != nil {
			return stateErr
		}
		fresh, buildErr := BuildPacketCandidate(ctx, p.store, request, freshState, p.clock, p.ownerRoot, freshAt, createdAt)
		if buildErr != nil || !reflect.DeepEqual(fresh.Descriptor(), descriptor) || !samePacketArtifact(value, fresh.Artifact()) {
			return errors.Join(ErrPacketAuthority, buildErr)
		}
		freshAt = p.clock.Now().UTC()
		if ctx.Err() != nil || !freshAt.Before(request.Lease().ExpiresAt()) || !freshAt.Before(value.ExpiresAt()) {
			return ErrPacketAuthority
		}
		prepared, stateErr = p.coordinator.PrepareContextPacket(ctx, request.Plan(), request.Lease(), descriptor, freshAt)
		if stateErr != nil {
			return errors.Join(ErrPacketAuthority, stateErr)
		}
		for step := 0; step < 4; step++ {
			if fenceErr := p.fence(ctx, request, prepared, value, root); fenceErr != nil {
				return fenceErr
			}
			switch step {
			case 0:
				effectAt := p.clock.Now().UTC()
				if ctx.Err() != nil || !effectAt.Before(request.Lease().ExpiresAt()) || !effectAt.Before(value.ExpiresAt()) {
					return ErrPacketAuthority
				}
				if _, putErr := p.store.Put(ctx, value, effectAt); putErr != nil {
					// A failed Put may already have renamed the packet. Its physical
					// outcome is uncertain; never infer absent bytes from this error.
					return errors.Join(ErrPacketAuthority, putErr)
				}
			case 2:
				effectAt := p.clock.Now().UTC()
				if ctx.Err() != nil || !effectAt.Before(request.Lease().ExpiresAt()) || !effectAt.Before(value.ExpiresAt()) {
					return ErrPacketAuthority
				}
				stored, getErr := p.store.Get(ctx, request.Plan().Scope(), value.Identity(), effectAt)
				if getErr != nil || !samePacketEnvelope(value, stored) {
					return errors.Join(ErrPacketAuthority, getErr)
				}
			}
		}
		return nil
	})
	if err != nil {
		return prepared, errors.Join(ErrPacketAuthority, err)
	}
	return prepared, nil
}

func (p *PacketAuthority) current(ctx context.Context, request controlplane.TaskExecutionRequest) (controlplane.ReviewRunState, error) {
	plan, state, err := p.coordinator.Resume(ctx, request.Plan().Scope())
	if err != nil || plan.Identity() != request.Plan().Identity() || state.Status() != controlplane.ReviewRunActive {
		return controlplane.ReviewRunState{}, errors.Join(ErrPacketAuthority, err)
	}
	return state, nil
}

func (p *PacketAuthority) rebuild(ctx context.Context, request controlplane.TaskExecutionRequest, state controlplane.ReviewRunState, at, createdAt time.Time) (packetBuild, error) {
	return (packetAssembler{store: p.store, clock: p.clock, ownerRoot: p.ownerRoot}).rebuild(ctx, request, state, at, createdAt)
}

func (p packetAssembler) rebuild(ctx context.Context, request controlplane.TaskExecutionRequest, state controlplane.ReviewRunState, at, createdAt time.Time) (packetBuild, error) {
	runtime, ok := state.Task(request.Task().Key())
	if !ok || runtime.Status() != controlplane.TaskRuntimeLeased || runtime.Definition().Identity() != request.Task().Identity() ||
		runtime.Attempts() != request.Lease().Attempt() || runtime.WorkerIdentity() != request.Lease().WorkerIdentity() || runtime.LeaseExpiresAt() != request.Lease().ExpiresAt() ||
		!at.Before(runtime.LeaseExpiresAt()) || ctx.Err() != nil {
		return packetBuild{}, ErrPacketAuthority
	}
	for _, output := range request.DependencyOutputs() {
		upstreamTask, planned := request.Plan().Task(output.TaskKey())
		if !planned || !equalStrings(upstreamTask.Dependencies(), []string{"change"}) {
			return packetBuild{}, ErrPacketAuthority
		}
		upstream, exists := state.Task(output.TaskKey())
		if !exists || upstream.Status() != controlplane.TaskRuntimeSucceeded || upstream.OutputIdentity() != output.OutputIdentity() {
			return packetBuild{}, ErrPacketAuthority
		}
	}
	h := &Handler{store: leaseBoundReads{Store: p.store, clock: p.clock, lease: request.Lease()}, packetOnly: true}
	assembly, providerRequest, abstention, failure := h.assembleAt(ctx, request, at, createdAt)
	if failure != 0 || abstention != nil {
		return packetBuild{}, ErrPacketAuthority
	}
	root, err := p.sourceChain(ctx, request, state, assembly)
	if err != nil {
		return packetBuild{}, err
	}
	value := assembly.InitialContextArtifact
	if value.Kind() != artifact.KindContextPacket || value.MediaType() != "application/json" || value.Origin() != artifact.OriginHost ||
		!bytes.Equal(value.Payload(), providerRequest.Payload()) || value.Validate() != nil || len(value.Provenance()) != 6 ||
		review.ValidateContextPacketRequest(value.Payload(), assembly.Packet.Identity(), request.Plan().Scope().Identity(), assembly.Packet.MemoryScopeIdentity(), assembly.Packet.MemoryIdentity(), assembly.Snapshot, assembly.Packet.EvidenceItems()) != nil {
		return packetBuild{}, ErrPacketAuthority
	}
	return packetBuild{value: value, root: root, snapshot: assembly.Snapshot.Identity(), packet: assembly.Packet, snapshotValue: assembly.Snapshot}, nil
}

func (p packetAssembler) sourceChain(ctx context.Context, request controlplane.TaskExecutionRequest, state controlplane.ReviewRunState, assembly contextAssembly) (string, error) {
	reader := leaseBoundReads{Store: p.store, clock: p.clock, lease: request.Lease()}
	baseArtifact, headArtifact, changeArtifact := assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact, assembly.ChangeArtifact
	base, head := assembly.base, assembly.head
	packetExpiry := assembly.InitialContextArtifact.ExpiresAt()
	change, err := changecodec.ParseResultArtifactWithSnapshots(changeArtifact, base, head)
	if err != nil {
		return "", ErrPacketAuthority
	}
	changeTask, planned := request.Plan().Task("change")
	changeRuntime, ok := state.Task("change")
	if !planned || changeTask.Kind() != controlplane.TaskBuildChange || !equalStrings(changeTask.Dependencies(), []string{"source-base", "source-head"}) || !ok || changeRuntime.Status() != controlplane.TaskRuntimeSucceeded || changeRuntime.OutputIdentity() != changeArtifact.Identity() {
		return "", ErrPacketAuthority
	}
	var root, repository, adapter string
	for index, entry := range []struct {
		key      string
		snapshot sourceoutput.Snapshot
		value    artifact.Artifact
	}{{"source-base", base, baseArtifact}, {"source-head", head, headArtifact}} {
		task, exists := request.Plan().Task(entry.key)
		runtime, found := state.Task(entry.key)
		if !exists || !found || task.Kind() != controlplane.TaskAcquireSource || runtime.Status() != controlplane.TaskRuntimeSucceeded || runtime.OutputIdentity() != entry.value.Identity() ||
			task.InputIdentity() == "" || entry.snapshot.ArtifactIdentity() != entry.value.Identity() || entry.snapshot.ScopeIdentity() != request.Plan().Scope().Identity() {
			return "", ErrPacketAuthority
		}
		inputArtifact, getErr := reader.Get(ctx, request.Plan().Scope(), task.InputIdentity(), p.clock.Now().UTC())
		if getErr != nil || inputArtifact.Identity() != task.InputIdentity() || inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.Origin() != artifact.OriginHost || inputArtifact.MediaType() != "application/json" ||
			inputArtifact.Protection() != artifact.ProtectionProcessPrivate || !slices.Equal(inputArtifact.Provenance(), []string{request.Plan().RequestIdentity()}) ||
			inputArtifact.ExpiresAt().Before(packetExpiry) || inputArtifact.Classification() != entry.value.Classification() || inputArtifact.Protection() != entry.value.Protection() || entry.value.ExpiresAt().Before(packetExpiry) || !slices.Equal(entry.value.Provenance(), sortedPair(inputArtifact.Identity(), entry.snapshot.AcquisitionExecutionIdentity())) {
			return "", ErrPacketAuthority
		}
		input, parseErr := sourceinput.ParseInput(inputArtifact.Payload())
		if parseErr != nil || input.SchemaVersion() != 2 || !validDigest(input.SourceRootIdentity()) ||
			input.Repository().Identity() != entry.snapshot.RepositoryIdentity() || input.Revision().Identity() != entry.snapshot.RevisionIdentity() ||
			input.SourceAdapterIdentity() != entry.snapshot.SourceAdapterIdentity() ||
			task.HandlerIdentity() != boundSourceHandlerIdentity(input.SourceAdapterIdentity(), input.SourceRootIdentity()) {
			return "", ErrPacketAuthority
		}
		acquisition, makeErr := evidence.NewRepositoryAcquisitionRequest(input.Repository(), input.Revision(), input.Adapter(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
		if makeErr != nil || acquisition.Identity() != entry.snapshot.AcquisitionRequestIdentity() {
			return "", ErrPacketAuthority
		}
		// Re-read every stored file, not only selected head ranges. ParseFileArtifact
		// proves the execution and bytes; exact provenance closes its envelope.
		for _, ref := range entry.snapshot.Files() {
			fileValue, fileErr := reader.Get(ctx, request.Plan().Scope(), ref.ArtifactIdentity(), p.clock.Now().UTC())
			if fileErr != nil || fileValue.ExpiresAt().Before(packetExpiry) || !slices.Equal(fileValue.Provenance(), sortedPair(inputArtifact.Identity(), entry.snapshot.AcquisitionExecutionIdentity())) {
				return "", ErrPacketAuthority
			}
			if _, fileErr = sourceoutput.ParseFileArtifact(fileValue, entry.snapshot, ref); fileErr != nil {
				return "", ErrPacketAuthority
			}
		}
		if index == 0 {
			h := &Handler{store: reader}
			content, _, earliest, loadFailure := h.loadHead(ctx, request.Plan().Scope(), entry.snapshot, p.clock.Now().UTC(), packetExpiry)
			clearContents(content)
			if loadFailure != 0 || earliest.Before(packetExpiry) {
				return "", ErrPacketAuthority
			}
		}
		if index == 0 {
			root = input.SourceRootIdentity()
			repository = input.Repository().Identity()
			adapter = input.SourceAdapterIdentity()
		} else if root != input.SourceRootIdentity() || repository != input.Repository().Identity() || adapter != input.SourceAdapterIdentity() {
			return "", ErrPacketAuthority
		}
	}
	if root != p.ownerRoot || change.Repository().Identity() != repository || change.SourceAdapterIdentity() != adapter || change.BaseRevision().Identity() != base.RevisionIdentity() || change.HeadRevision().Identity() != head.RevisionIdentity() || change.HeadManifestIdentity() != head.ManifestIdentity() || change.HeadSnapshotIdentity() != head.Identity() || change.BaseSnapshotIdentity() != base.Identity() || change.BaseSnapshotArtifactIdentity() != baseArtifact.Identity() || change.HeadSnapshotArtifactIdentity() != headArtifact.Identity() {
		return "", ErrPacketAuthority
	}
	return root, nil
}

func (p *PacketAuthority) fence(ctx context.Context, request controlplane.TaskExecutionRequest, prepared controlplane.PreparedContextPacket, expected artifact.Artifact, root string) error {
	now := p.clock.Now().UTC()
	state, err := p.current(ctx, request)
	if err != nil || ctx.Err() != nil || !now.Before(request.Lease().ExpiresAt()) || !now.Before(expected.ExpiresAt()) || state.HeadIdentity() != prepared.Identity() {
		return ErrPacketAuthority
	}
	runtime, ok := state.Task(request.Task().Key())
	current, preparedOK := runtime.PreparedContextPacket()
	if !ok || !preparedOK || current.Identity() != prepared.Identity() || !reflect.DeepEqual(current.Descriptor(), prepared.Descriptor()) {
		return ErrPacketAuthority
	}
	actual, err := p.rebuild(ctx, request, state, now, expected.CreatedAt())
	if err != nil || actual.root != root || actual.snapshot != prepared.Descriptor().SnapshotIdentity || !samePacketArtifact(expected, actual.value) {
		return ErrPacketAuthority
	}
	return nil
}

func samePacketEnvelope(first, second artifact.Artifact) bool {
	if !samePacketArtifact(first, second) {
		return false
	}
	left, leftErr := artifact.Encode(first)
	right, rightErr := artifact.Encode(second)
	return leftErr == nil && rightErr == nil && bytes.Equal(left, right)
}

func samePacketArtifact(first, second artifact.Artifact) bool {
	return second.Validate() == nil && first.Identity() == second.Identity() && first.Scope().Identity() == second.Scope().Identity() &&
		first.Kind() == second.Kind() && first.MediaType() == second.MediaType() && first.Classification() == second.Classification() &&
		first.Origin() == second.Origin() && first.Protection() == second.Protection() && slices.Equal(first.Provenance(), second.Provenance()) &&
		first.PayloadDigest() == second.PayloadDigest() && first.CreatedAt() == second.CreatedAt() && first.ExpiresAt() == second.ExpiresAt() &&
		bytes.Equal(first.Payload(), second.Payload())
}

func sortedPair(a, b string) []string { value := []string{a, b}; slices.Sort(value); return value }
func boundSourceHandlerIdentity(adapter, root string) string {
	encoded, _ := json.Marshal(struct {
		Contract              string `json:"contract"`
		SchemaVersion         int    `json:"schema_version"`
		SourceAdapterIdentity string `json:"source_adapter_identity"`
		SourceRootIdentity    string `json:"source_root_identity"`
	}{"open-trestle/source-acquisition-handler", 2, adapter, root})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
