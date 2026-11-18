package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

var (
	// ErrInvalidAcquiredContextBinding identifies malformed source or audit lineage.
	ErrInvalidAcquiredContextBinding = errors.New("invalid acquired context binding")
	// ErrAcquiredContextSnapshotMismatch identifies a packet from another source snapshot.
	ErrAcquiredContextSnapshotMismatch = errors.New("acquired context snapshot mismatch")
	// ErrAcquiredContextSourceUnbound identifies packet source without exact file-slice proof.
	ErrAcquiredContextSourceUnbound = errors.New("acquired context source is not file-bound")
	// ErrAcquiredContextFileMismatch identifies slice proof from outside the acquired head.
	ErrAcquiredContextFileMismatch = errors.New("acquired context source file mismatch")
	// ErrAcquiredContextRangeNotCovered identifies a requested range absent from changed context.
	ErrAcquiredContextRangeNotCovered = errors.New("acquired review range is not covered by changed context")
	// ErrDuplicateAcquiredContextBinding identifies repeated slice proof.
	ErrDuplicateAcquiredContextBinding = errors.New("duplicate acquired context slice binding")
	// ErrInvalidAcquiredContextBindingIdentity identifies content inconsistent with its identity.
	ErrInvalidAcquiredContextBindingIdentity = errors.New("invalid acquired context binding identity")
)

// AcquiredContextBinding proves a model packet uses exact slices of the acquired head manifest.
type AcquiredContextBinding struct {
	identity                 string
	acquiredSnapshotIdentity string
	pipelineSnapshotIdentity string
	contextPacketIdentity    string
	reviewScopeIdentity      string
	headManifestIdentity     string
	sliceBindingIdentities   []string
	changedRangeCount        int
}

// BindAcquiredContextPacket verifies every source and covers every requested changed range.
func BindAcquiredContextPacket(snapshot AcquiredReviewSnapshot, packet ContextPacket) (AcquiredContextBinding, error) {
	if err := snapshot.Validate(); err != nil {
		return AcquiredContextBinding{}, err
	}
	if err := packet.Validate(); err != nil {
		return AcquiredContextBinding{}, err
	}
	if packet.SnapshotIdentity() != snapshot.PipelineSnapshotIdentity() {
		return AcquiredContextBinding{}, ErrAcquiredContextSnapshotMismatch
	}
	headManifest := snapshot.HeadManifest()
	sources := packet.Sources()
	bindingIdentities := make([]string, len(sources))
	seen := make(map[string]struct{}, len(sources))
	for index, source := range sources {
		if !source.HasSliceBinding() || source.SliceBinding().Validate() != nil {
			return AcquiredContextBinding{}, ErrAcquiredContextSourceUnbound
		}
		binding := source.SliceBinding()
		file, exists := headManifest.File(binding.SourceRange().Path())
		if !exists || file.Identity() != binding.RepositoryFileIdentity() || file.Digest() != binding.RepositoryFileDigest() {
			return AcquiredContextBinding{}, ErrAcquiredContextFileMismatch
		}
		if _, exists := seen[binding.Identity()]; exists {
			return AcquiredContextBinding{}, ErrDuplicateAcquiredContextBinding
		}
		seen[binding.Identity()] = struct{}{}
		bindingIdentities[index] = binding.Identity()
	}
	for _, required := range snapshot.Ranges() {
		covered := false
		for _, source := range sources {
			if source.Stage() == ContextStageChangedHunk && sourceRangeCovers(source.EvidenceItem().SourceRange(), required) {
				covered = true
				break
			}
		}
		if !covered {
			return AcquiredContextBinding{}, ErrAcquiredContextRangeNotCovered
		}
	}
	sort.Strings(bindingIdentities)
	binding := AcquiredContextBinding{
		acquiredSnapshotIdentity: snapshot.Identity(), pipelineSnapshotIdentity: snapshot.PipelineSnapshotIdentity(),
		contextPacketIdentity: packet.Identity(), reviewScopeIdentity: packet.ReviewScopeIdentity(),
		headManifestIdentity: headManifest.Identity(), sliceBindingIdentities: bindingIdentities,
		changedRangeCount: len(snapshot.Ranges()),
	}
	binding.identity = deriveAcquiredContextBindingIdentity(binding)
	return binding, nil
}
func sourceRangeCovers(container, required evidence.SourceRange) bool {
	matchingPath := container.Path() == required.Path()
	coversStart := container.StartLine() <= required.StartLine()
	coversEnd := container.EndLine() >= required.EndLine()
	return matchingPath && coversStart && coversEnd
}
func (b AcquiredContextBinding) Identity() string                 { return b.identity }
func (b AcquiredContextBinding) AcquiredSnapshotIdentity() string { return b.acquiredSnapshotIdentity }
func (b AcquiredContextBinding) PipelineSnapshotIdentity() string { return b.pipelineSnapshotIdentity }
func (b AcquiredContextBinding) ContextPacketIdentity() string    { return b.contextPacketIdentity }
func (b AcquiredContextBinding) ReviewScopeIdentity() string      { return b.reviewScopeIdentity }
func (b AcquiredContextBinding) HeadManifestIdentity() string     { return b.headManifestIdentity }
func (b AcquiredContextBinding) SliceBindingIdentities() []string {
	return append([]string(nil), b.sliceBindingIdentities...)
}
func (b AcquiredContextBinding) ChangedRangeCount() int { return b.changedRangeCount }
func (b AcquiredContextBinding) Validate() error {
	for _, id := range []string{b.acquiredSnapshotIdentity, b.pipelineSnapshotIdentity, b.contextPacketIdentity, b.reviewScopeIdentity, b.headManifestIdentity} {
		if !validCandidateDigest(id) {
			return ErrInvalidAcquiredContextBinding
		}
	}
	if len(b.sliceBindingIdentities) == 0 || len(b.sliceBindingIdentities) > maxSelectedContextSources || b.changedRangeCount <= 0 || b.changedRangeCount > maxSelectedContextSources {
		return ErrInvalidAcquiredContextBinding
	}
	previous := ""
	for _, id := range b.sliceBindingIdentities {
		if !validCandidateDigest(id) || id <= previous {
			return ErrInvalidAcquiredContextBinding
		}
		previous = id
	}
	if b.identity != deriveAcquiredContextBindingIdentity(b) {
		return ErrInvalidAcquiredContextBindingIdentity
	}
	return nil
}
func (b AcquiredContextBinding) String() string   { return "acquired context binding" }
func (b AcquiredContextBinding) GoString() string { return "review.AcquiredContextBinding{<redacted>}" }
func (b AcquiredContextBinding) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "acquired context binding", "review.AcquiredContextBinding{<redacted>}")
}

// AcquiredGenerationAuditReceipt binds source, selection, packet, and slice audit events.
type AcquiredGenerationAuditReceipt struct {
	identity                 string
	reviewScopeIdentity      string
	acquiredSnapshotIdentity string
	contextBindingIdentity   string
	selectionIdentity        string
	packetIdentity           string
	events                   []audit.Event
}

// RecordAcquiredGenerationContext records acquired source lineage before candidate generation.
func RecordAcquiredGenerationContext(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	snapshot AcquiredReviewSnapshot,
	packet ContextPacket,
	binding AcquiredContextBinding,
	occurredAt time.Time,
) (AcquiredGenerationAuditReceipt, error) {
	if isNilModelAuditLedger(ledger) {
		return AcquiredGenerationAuditReceipt{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	if err := packet.Validate(); err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	if err := binding.Validate(); err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	matchingSnapshot := binding.AcquiredSnapshotIdentity() == snapshot.Identity()
	matchingPacket := binding.ContextPacketIdentity() == packet.Identity()
	matchingScope := binding.ReviewScopeIdentity() == scope.Identity()
	if !matchingSnapshot || !matchingPacket || !matchingScope {
		return AcquiredGenerationAuditReceipt{}, ErrInvalidAcquiredContextBinding
	}
	snapshotEvent, err := RecordAcquiredReviewSnapshot(ctx, ledger, scope, snapshot, occurredAt)
	if err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	selection := packet.SourceSelection()
	selectionSpecification := modelAuditEventSpecification{
		kind: audit.EventContextSourcesSelected, subject: selection.Identity(),
		parents: []string{packet.Retrieval().Identity(), packet.SnapshotIdentity()},
	}
	selectionEvent, err := appendUniqueModelAuditEvent(ctx, ledger, scope, selectionSpecification, occurredAt)
	if err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	packetSpecification := modelAuditEventSpecification{
		kind: audit.EventContextPacketAssembled, subject: packet.Identity(),
		parents: []string{selection.Identity(), packet.Retrieval().Identity(), packet.SnapshotIdentity()},
	}
	packetEvent, err := appendUniqueModelAuditEvent(ctx, ledger, scope, packetSpecification, occurredAt)
	if err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	bindingEvent, err := RecordAcquiredContextBinding(ctx, ledger, scope, snapshot, binding, occurredAt)
	if err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	receipt := AcquiredGenerationAuditReceipt{
		reviewScopeIdentity: scope.Identity(), acquiredSnapshotIdentity: snapshot.Identity(),
		contextBindingIdentity: binding.Identity(), selectionIdentity: selection.Identity(),
		packetIdentity: packet.Identity(), events: []audit.Event{snapshotEvent, selectionEvent, packetEvent, bindingEvent},
	}
	receipt.identity = deriveAcquiredGenerationAuditReceiptIdentity(receipt)
	if err := receipt.Validate(); err != nil {
		return AcquiredGenerationAuditReceipt{}, err
	}
	return receipt, nil
}
func (r AcquiredGenerationAuditReceipt) Identity() string            { return r.identity }
func (r AcquiredGenerationAuditReceipt) ReviewScopeIdentity() string { return r.reviewScopeIdentity }
func (r AcquiredGenerationAuditReceipt) Events() []audit.Event {
	return append([]audit.Event(nil), r.events...)
}
func (r AcquiredGenerationAuditReceipt) Validate() error {
	for _, id := range []string{r.reviewScopeIdentity, r.acquiredSnapshotIdentity, r.contextBindingIdentity, r.selectionIdentity, r.packetIdentity} {
		if !validCandidateDigest(id) {
			return ErrInvalidAcquiredContextBinding
		}
	}
	if len(r.events) != 4 {
		return ErrInvalidAcquiredContextBinding
	}
	kinds := []audit.EventKind{audit.EventReviewSnapshotBound, audit.EventContextSourcesSelected, audit.EventContextPacketAssembled, audit.EventContextAcquisitionBound}
	subjects := []string{r.acquiredSnapshotIdentity, r.selectionIdentity, r.packetIdentity, r.contextBindingIdentity}
	var previousSequence uint64
	for index, event := range r.events {
		validEvent := event.Validate() == nil
		matchingScope := event.Scope().Identity() == r.reviewScopeIdentity
		matchingKind := event.Kind() == kinds[index]
		matchingSubject := event.SubjectIdentity() == subjects[index]
		ordered := index == 0 || event.Sequence() > previousSequence
		if !validEvent || !matchingScope || !matchingKind || !matchingSubject || !ordered {
			return ErrInvalidAcquiredContextBinding
		}
		previousSequence = event.Sequence()
	}
	if r.identity != deriveAcquiredGenerationAuditReceiptIdentity(r) {
		return ErrInvalidAcquiredContextBindingIdentity
	}
	return nil
}
func (r AcquiredGenerationAuditReceipt) String() string { return "acquired generation audit receipt" }
func (r AcquiredGenerationAuditReceipt) GoString() string {
	return "review.AcquiredGenerationAuditReceipt{<redacted>}"
}
func (r AcquiredGenerationAuditReceipt) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "acquired generation audit receipt", "review.AcquiredGenerationAuditReceipt{<redacted>}")
}
func deriveAcquiredGenerationAuditReceiptIdentity(receipt AcquiredGenerationAuditReceipt) string {
	eventIDs := make([]string, len(receipt.events))
	for index, event := range receipt.events {
		eventIDs[index] = event.Identity()
	}
	preimage := struct {
		Contract  string   `json:"contract"`
		Version   int      `json:"version"`
		Scope     string   `json:"scope"`
		Snapshot  string   `json:"snapshot"`
		Binding   string   `json:"binding"`
		Selection string   `json:"selection"`
		Packet    string   `json:"packet"`
		Events    []string `json:"events"`
	}{
		Contract: "open-trestle/acquired-generation-audit", Version: 1,
		Scope: receipt.reviewScopeIdentity, Snapshot: receipt.acquiredSnapshotIdentity,
		Binding: receipt.contextBindingIdentity, Selection: receipt.selectionIdentity,
		Packet: receipt.packetIdentity, Events: eventIDs,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// RecordAcquiredContextBinding appends exact acquired-source lineage for a model context packet.
func RecordAcquiredContextBinding(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	snapshot AcquiredReviewSnapshot,
	binding AcquiredContextBinding,
	occurredAt time.Time,
) (audit.Event, error) {
	if isNilModelAuditLedger(ledger) {
		return audit.Event{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := binding.Validate(); err != nil {
		return audit.Event{}, err
	}
	matchingScope := scope.Identity() == binding.ReviewScopeIdentity()
	matchingRepository := scope.RepositoryID() == snapshot.RepositoryIdentity()
	matchingSnapshot := binding.AcquiredSnapshotIdentity() == snapshot.Identity()
	matchingPipeline := binding.PipelineSnapshotIdentity() == snapshot.PipelineSnapshotIdentity()
	if !matchingScope || !matchingRepository || !matchingSnapshot || !matchingPipeline {
		return audit.Event{}, ErrInvalidAcquiredContextBinding
	}
	snapshotEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventReviewSnapshotBound, snapshot.Identity())
	if err != nil {
		return audit.Event{}, err
	}
	if !found {
		return audit.Event{}, ErrInvalidAcquiredContextBinding
	}
	packetEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventContextPacketAssembled, binding.ContextPacketIdentity())
	if err != nil {
		return audit.Event{}, err
	}
	if !found {
		return audit.Event{}, ErrInvalidAcquiredContextBinding
	}
	parents := []string{snapshot.Identity(), snapshotEvent.Identity(), binding.ContextPacketIdentity(), packetEvent.Identity(), binding.HeadManifestIdentity()}
	specification := modelAuditEventSpecification{
		kind: audit.EventContextAcquisitionBound, subject: binding.Identity(), parents: parents,
	}
	return appendUniqueModelAuditEvent(ctx, ledger, scope, specification, occurredAt)
}

func deriveAcquiredContextBindingIdentity(binding AcquiredContextBinding) string {
	preimage := struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Snapshot string   `json:"snapshot"`
		Pipeline string   `json:"pipeline"`
		Packet   string   `json:"packet"`
		Scope    string   `json:"scope"`
		Manifest string   `json:"manifest"`
		Slices   []string `json:"slices"`
		Changed  int      `json:"changed"`
	}{
		Contract: "open-trestle/acquired-context-binding", Version: 1,
		Snapshot: binding.acquiredSnapshotIdentity, Pipeline: binding.pipelineSnapshotIdentity,
		Packet: binding.contextPacketIdentity, Scope: binding.reviewScopeIdentity,
		Manifest: binding.headManifestIdentity, Slices: binding.sliceBindingIdentities,
		Changed: binding.changedRangeCount,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
