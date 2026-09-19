package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maxAcquiredReviewWorkspaceBytes = 4 << 10

var (
	// ErrInvalidAcquiredReviewWorkspace identifies an empty, excessive, or control-bearing workspace ID.
	ErrInvalidAcquiredReviewWorkspace = errors.New("invalid acquired review workspace")
	// ErrInvalidAcquiredReviewRepository identifies a noncanonical repository.
	ErrInvalidAcquiredReviewRepository = errors.New("invalid acquired review repository")
	// ErrInvalidAcquiredReviewRevision identifies a noncanonical base or head revision.
	ErrInvalidAcquiredReviewRevision = errors.New("invalid acquired review revision")
	// ErrInvalidAcquiredReviewBinding identifies cross-wired acquisition evidence.
	ErrInvalidAcquiredReviewBinding = errors.New("invalid acquired review evidence binding")
	// ErrInvalidAcquiredReviewManifest identifies noncanonical manifest metadata.
	ErrInvalidAcquiredReviewManifest = errors.New("invalid acquired review manifest")
	// ErrInvalidAcquiredReviewDelta identifies a delta inconsistent with its manifests.
	ErrInvalidAcquiredReviewDelta = errors.New("invalid acquired review manifest delta")
	// ErrAcquiredReviewRangeNotInHead identifies a requested path absent from the head.
	ErrAcquiredReviewRangeNotInHead = errors.New("acquired review range is not in head manifest")
	// ErrAcquiredReviewRangeNotChanged identifies a requested path absent from the change.
	ErrAcquiredReviewRangeNotChanged = errors.New("acquired review range is not on a changed head path")
	// ErrInvalidAcquiredReviewRanges identifies an empty, excessive, or noncanonical range set.
	ErrInvalidAcquiredReviewRanges = errors.New("invalid acquired review ranges")
	// ErrDuplicateAcquiredReviewRange identifies a repeated physical range.
	ErrDuplicateAcquiredReviewRange = errors.New("duplicate acquired review range")
	// ErrInvalidAcquiredReviewSnapshotIdentity identifies snapshot content inconsistent with its identity.
	ErrInvalidAcquiredReviewSnapshotIdentity = errors.New("invalid acquired review snapshot identity")
)

// AcquiredReviewSnapshot binds review scope to verified base and head acquisitions.
type AcquiredReviewSnapshot struct {
	identity         string
	workspace        string
	pipelineSnapshot ReviewSnapshot
	repository       evidence.RepositoryIdentity
	baseRevision     evidence.RevisionIdentity
	headRevision     evidence.RevisionIdentity
	baseBinding      evidence.RepositoryAcquisitionEvidenceBinding
	headBinding      evidence.RepositoryAcquisitionEvidenceBinding
	baseManifest     evidence.RepositoryManifest
	headManifest     evidence.RepositoryManifest
	manifestDelta    evidence.RepositoryManifestDelta
	ranges           []evidence.SourceRange
}

// NewAcquiredReviewPipelineSnapshot creates the aggregate snapshot consumed by model review.
func NewAcquiredReviewPipelineSnapshot(workspace string, headManifest evidence.RepositoryManifest, ranges []evidence.SourceRange) (ReviewSnapshot, error) {
	if !validAcquiredReviewWorkspace(workspace) {
		return ReviewSnapshot{}, ErrInvalidAcquiredReviewWorkspace
	}
	canonicalManifest, err := canonicalAcquiredReviewManifest(headManifest)
	if err != nil {
		return ReviewSnapshot{}, err
	}
	if len(ranges) == 0 || len(ranges) > maxSelectedContextSources {
		return ReviewSnapshot{}, ErrInvalidAcquiredReviewRanges
	}
	canonicalRanges := append([]evidence.SourceRange(nil), ranges...)
	sort.Slice(canonicalRanges, func(i, j int) bool {
		if canonicalRanges[i].Path() != canonicalRanges[j].Path() {
			return canonicalRanges[i].Path() < canonicalRanges[j].Path()
		}
		if canonicalRanges[i].StartLine() != canonicalRanges[j].StartLine() {
			return canonicalRanges[i].StartLine() < canonicalRanges[j].StartLine()
		}
		return canonicalRanges[i].EndLine() < canonicalRanges[j].EndLine()
	})
	for index, sourceRange := range canonicalRanges {
		rebuilt, rangeErr := evidence.NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
		if rangeErr != nil || rebuilt != sourceRange {
			return ReviewSnapshot{}, ErrInvalidAcquiredReviewRanges
		}
		if index > 0 && canonicalRanges[index-1] == sourceRange {
			return ReviewSnapshot{}, ErrDuplicateAcquiredReviewRange
		}
		if _, exists := canonicalManifest.File(sourceRange.Path()); !exists {
			return ReviewSnapshot{}, ErrAcquiredReviewRangeNotInHead
		}
	}
	revision, err := deriveAcquiredReviewRangeRevision(canonicalManifest, canonicalRanges)
	if err != nil {
		return ReviewSnapshot{}, err
	}
	return NewReviewSnapshot(workspace, revision, canonicalRanges)
}

// NewAcquiredReviewSnapshot validates one exact repository acquisition pair and changed-line scope.
func NewAcquiredReviewSnapshot(
	pipelineSnapshot ReviewSnapshot,
	repository evidence.RepositoryIdentity,
	baseRevision evidence.RevisionIdentity,
	headRevision evidence.RevisionIdentity,
	baseBinding evidence.RepositoryAcquisitionEvidenceBinding,
	headBinding evidence.RepositoryAcquisitionEvidenceBinding,
	baseManifest evidence.RepositoryManifest,
	headManifest evidence.RepositoryManifest,
	manifestDelta evidence.RepositoryManifestDelta,
) (AcquiredReviewSnapshot, error) {
	if err := pipelineSnapshot.Validate(); err != nil || !validAcquiredReviewWorkspace(pipelineSnapshot.Workspace()) {
		return AcquiredReviewSnapshot{}, ErrInvalidAcquiredReviewWorkspace
	}
	workspace := pipelineSnapshot.Workspace()
	ranges := pipelineSnapshot.Ranges()
	canonicalRepository, err := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	if err != nil || canonicalRepository.Identity() != repository.Identity() {
		return AcquiredReviewSnapshot{}, ErrInvalidAcquiredReviewRepository
	}
	canonicalBaseRevision, err := canonicalAcquiredReviewRevision(baseRevision)
	if err != nil {
		return AcquiredReviewSnapshot{}, err
	}
	canonicalHeadRevision, err := canonicalAcquiredReviewRevision(headRevision)
	if err != nil {
		return AcquiredReviewSnapshot{}, err
	}
	canonicalBaseManifest, err := canonicalAcquiredReviewManifest(baseManifest)
	if err != nil {
		return AcquiredReviewSnapshot{}, err
	}
	canonicalHeadManifest, err := canonicalAcquiredReviewManifest(headManifest)
	if err != nil {
		return AcquiredReviewSnapshot{}, err
	}
	canonicalDelta, err := evidence.NewRepositoryManifestDelta(canonicalBaseManifest, canonicalHeadManifest)
	if err != nil || canonicalDelta.Identity() != manifestDelta.Identity() {
		return AcquiredReviewSnapshot{}, ErrInvalidAcquiredReviewDelta
	}
	if err := validateAcquiredReviewBindings(canonicalRepository, canonicalBaseRevision, canonicalHeadRevision, baseBinding, headBinding, canonicalBaseManifest, canonicalHeadManifest); err != nil {
		return AcquiredReviewSnapshot{}, err
	}
	canonicalRanges, err := canonicalAcquiredReviewRanges(ranges, canonicalHeadManifest, canonicalDelta)
	if err != nil {
		return AcquiredReviewSnapshot{}, err
	}
	if !slices.Equal(pipelineSnapshot.Ranges(), canonicalRanges) {
		return AcquiredReviewSnapshot{}, ErrInvalidAcquiredReviewRanges
	}
	expectedPipelineRevision, err := deriveAcquiredReviewRangeRevision(canonicalHeadManifest, canonicalRanges)
	if err != nil || pipelineSnapshot.Revision() != expectedPipelineRevision {
		return AcquiredReviewSnapshot{}, ErrInvalidSourceSnapshotBinding
	}
	snapshot := AcquiredReviewSnapshot{
		workspace: strings.Clone(workspace), pipelineSnapshot: pipelineSnapshot, repository: canonicalRepository,
		baseRevision: canonicalBaseRevision, headRevision: canonicalHeadRevision,
		baseBinding: baseBinding, headBinding: headBinding,
		baseManifest: canonicalBaseManifest, headManifest: canonicalHeadManifest,
		manifestDelta: canonicalDelta, ranges: canonicalRanges,
	}
	snapshot.identity = deriveAcquiredReviewSnapshotIdentity(snapshot)
	return snapshot, nil
}

func validateAcquiredReviewBindings(
	repository evidence.RepositoryIdentity,
	baseRevision, headRevision evidence.RevisionIdentity,
	base, head evidence.RepositoryAcquisitionEvidenceBinding,
	baseManifest, headManifest evidence.RepositoryManifest,
) error {
	if base.BindingStatus() != evidence.RepositoryAcquisitionEvidenceStatusSupplied || head.BindingStatus() != evidence.RepositoryAcquisitionEvidenceStatusSupplied {
		return ErrInvalidAcquiredReviewBinding
	}
	identities := []string{
		base.Identity(), base.RequestIdentity(), base.ReceiptIdentity(), base.SourceAdapterIdentity(),
		head.Identity(), head.RequestIdentity(), head.ReceiptIdentity(), head.SourceAdapterIdentity(),
	}
	for _, identity := range identities {
		if !validCandidateDigest(identity) {
			return ErrInvalidAcquiredReviewBinding
		}
	}
	matchingRepository := base.RepositoryIdentity() == repository.Identity() && head.RepositoryIdentity() == repository.Identity()
	matchingRevisions := base.RevisionIdentity() == baseRevision.Identity() && head.RevisionIdentity() == headRevision.Identity()
	matchingManifests := base.ManifestIdentity() == baseManifest.Identity() && head.ManifestIdentity() == headManifest.Identity()
	matchingAdapter := base.SourceAdapterIdentity() == head.SourceAdapterIdentity()
	if !matchingRepository || !matchingRevisions || !matchingManifests || !matchingAdapter {
		return ErrInvalidAcquiredReviewBinding
	}
	return nil
}

func canonicalAcquiredReviewRanges(ranges []evidence.SourceRange, head evidence.RepositoryManifest, delta evidence.RepositoryManifestDelta) ([]evidence.SourceRange, error) {
	if len(ranges) == 0 || len(ranges) > maxSelectedContextSources {
		return nil, ErrInvalidAcquiredReviewRanges
	}
	canonical := append([]evidence.SourceRange(nil), ranges...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].Path() != canonical[j].Path() {
			return canonical[i].Path() < canonical[j].Path()
		}
		if canonical[i].StartLine() != canonical[j].StartLine() {
			return canonical[i].StartLine() < canonical[j].StartLine()
		}
		return canonical[i].EndLine() < canonical[j].EndLine()
	})
	for index, sourceRange := range canonical {
		rebuilt, err := evidence.NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
		if err != nil || rebuilt != sourceRange {
			return nil, ErrInvalidAcquiredReviewRanges
		}
		if index > 0 && canonical[index-1] == sourceRange {
			return nil, ErrDuplicateAcquiredReviewRange
		}
		headFile, exists := head.File(sourceRange.Path())
		if !exists {
			return nil, ErrAcquiredReviewRangeNotInHead
		}
		entry, changed := delta.Entry(sourceRange.Path())
		if !changed || entry.Kind() == evidence.RepositoryFileDeltaRemoved {
			return nil, ErrAcquiredReviewRangeNotChanged
		}
		entryHead, hasHead := entry.HeadFile()
		if !hasHead || entryHead.Identity() != headFile.Identity() {
			return nil, ErrInvalidAcquiredReviewDelta
		}
	}
	return canonical, nil
}

func canonicalAcquiredReviewRevision(revision evidence.RevisionIdentity) (evidence.RevisionIdentity, error) {
	canonical, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || canonical != revision {
		return evidence.RevisionIdentity{}, ErrInvalidAcquiredReviewRevision
	}
	return canonical, nil
}
func canonicalAcquiredReviewManifest(manifest evidence.RepositoryManifest) (evidence.RepositoryManifest, error) {
	canonical, err := evidence.NewRepositoryManifest(manifest.Files())
	if err != nil || canonical.Identity() != manifest.Identity() {
		return evidence.RepositoryManifest{}, ErrInvalidAcquiredReviewManifest
	}
	return canonical, nil
}
func validAcquiredReviewWorkspace(workspace string) bool {
	if len(workspace) == 0 || len(workspace) > maxAcquiredReviewWorkspaceBytes || !utf8.ValidString(workspace) || strings.ContainsRune(workspace, 0) {
		return false
	}
	for _, character := range workspace {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (s AcquiredReviewSnapshot) Identity() string                 { return s.identity }
func (s AcquiredReviewSnapshot) Workspace() string                { return s.workspace }
func (s AcquiredReviewSnapshot) PipelineSnapshot() ReviewSnapshot { return s.pipelineSnapshot }
func (s AcquiredReviewSnapshot) PipelineSnapshotIdentity() string {
	return s.pipelineSnapshot.Identity()
}
func (s AcquiredReviewSnapshot) Repository() evidence.RepositoryIdentity {
	repository, _ := evidence.NewRepositoryIdentity(s.repository.Authority(), s.repository.Namespace(), s.repository.Name())
	return repository
}
func (s AcquiredReviewSnapshot) RepositoryIdentity() string              { return s.repository.Identity() }
func (s AcquiredReviewSnapshot) BaseRevision() evidence.RevisionIdentity { return s.baseRevision }
func (s AcquiredReviewSnapshot) HeadRevision() evidence.RevisionIdentity { return s.headRevision }
func (s AcquiredReviewSnapshot) BaseBindingIdentity() string             { return s.baseBinding.Identity() }
func (s AcquiredReviewSnapshot) HeadBindingIdentity() string             { return s.headBinding.Identity() }
func (s AcquiredReviewSnapshot) BaseManifest() evidence.RepositoryManifest {
	manifest, _ := evidence.NewRepositoryManifest(s.baseManifest.Files())
	return manifest
}
func (s AcquiredReviewSnapshot) HeadManifest() evidence.RepositoryManifest {
	manifest, _ := evidence.NewRepositoryManifest(s.headManifest.Files())
	return manifest
}
func (s AcquiredReviewSnapshot) ManifestDelta() evidence.RepositoryManifestDelta {
	return s.manifestDelta
}
func (s AcquiredReviewSnapshot) Ranges() []evidence.SourceRange {
	return append([]evidence.SourceRange(nil), s.ranges...)
}
func (s AcquiredReviewSnapshot) MatchesPublicationTarget(target PublicationTarget) bool {
	validChildren := s.Validate() == nil && target.Validate() == nil
	matchingRepository := s.RepositoryIdentity() == target.RepositoryIdentity().Identity()
	matchingHead := s.HeadRevision().Identity() == target.HeadRevision().Identity()
	return validChildren && matchingRepository && matchingHead
}
func (s AcquiredReviewSnapshot) Validate() error {
	rebuilt, err := NewAcquiredReviewSnapshot(s.pipelineSnapshot, s.repository, s.baseRevision, s.headRevision, s.baseBinding, s.headBinding, s.baseManifest, s.headManifest, s.manifestDelta)
	if err != nil {
		return err
	}
	if rebuilt.identity != s.identity {
		return ErrInvalidAcquiredReviewSnapshotIdentity
	}
	return nil
}
func (s AcquiredReviewSnapshot) String() string   { return "acquired review snapshot" }
func (s AcquiredReviewSnapshot) GoString() string { return "review.AcquiredReviewSnapshot{<redacted>}" }
func (s AcquiredReviewSnapshot) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "acquired review snapshot", "review.AcquiredReviewSnapshot{<redacted>}")
}

// RecordAcquiredReviewSnapshot appends the exact source binding before model or publication work.
func RecordAcquiredReviewSnapshot(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, snapshot AcquiredReviewSnapshot, occurredAt time.Time) (audit.Event, error) {
	if isNilModelAuditLedger(ledger) {
		return audit.Event{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return audit.Event{}, err
	}
	if scope.RepositoryID() != snapshot.RepositoryIdentity() {
		return audit.Event{}, ErrPublicationAuditScopeMismatch
	}
	parents := []string{
		snapshot.PipelineSnapshotIdentity(), snapshot.BaseRevision().Identity(), snapshot.HeadRevision().Identity(),
		snapshot.BaseBindingIdentity(), snapshot.HeadBindingIdentity(), snapshot.ManifestDelta().Identity(),
	}
	return appendUniqueModelAuditEvent(ctx, ledger, scope, modelAuditEventSpecification{
		kind: audit.EventReviewSnapshotBound, subject: snapshot.Identity(), parents: parents,
	}, occurredAt)
}

func deriveAcquiredReviewRangeRevision(manifest evidence.RepositoryManifest, ranges []evidence.SourceRange) (string, error) {
	type rangeWire struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
		File  string `json:"file"`
	}
	preimage := struct {
		Contract string      `json:"contract"`
		Version  int         `json:"version"`
		Manifest string      `json:"manifest"`
		Ranges   []rangeWire `json:"ranges"`
	}{Contract: "open-trestle/acquired-review-range-set", Version: 1, Manifest: manifest.Identity(), Ranges: make([]rangeWire, len(ranges))}
	for index, sourceRange := range ranges {
		file, exists := manifest.File(sourceRange.Path())
		if !exists {
			return "", ErrAcquiredReviewRangeNotInHead
		}
		preimage.Ranges[index] = rangeWire{sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine(), file.Identity()}
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func deriveAcquiredReviewSnapshotIdentity(snapshot AcquiredReviewSnapshot) string {
	type rangeWire struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
	}
	preimage := struct {
		Contract         string      `json:"contract"`
		Version          int         `json:"version"`
		Workspace        string      `json:"workspace"`
		PipelineSnapshot string      `json:"pipeline_snapshot"`
		Repository       string      `json:"repository"`
		BaseRevision     string      `json:"base_revision"`
		HeadRevision     string      `json:"head_revision"`
		BaseBinding      string      `json:"base_binding"`
		HeadBinding      string      `json:"head_binding"`
		BaseManifest     string      `json:"base_manifest"`
		HeadManifest     string      `json:"head_manifest"`
		Delta            string      `json:"delta"`
		Ranges           []rangeWire `json:"ranges"`
	}{
		Contract: "open-trestle/acquired-review-snapshot", Version: 1,
		Workspace: snapshot.workspace, PipelineSnapshot: snapshot.pipelineSnapshot.Identity(), Repository: snapshot.repository.Identity(),
		BaseRevision: snapshot.baseRevision.Identity(), HeadRevision: snapshot.headRevision.Identity(),
		BaseBinding: snapshot.baseBinding.Identity(), HeadBinding: snapshot.headBinding.Identity(),
		BaseManifest: snapshot.baseManifest.Identity(), HeadManifest: snapshot.headManifest.Identity(),
		Delta: snapshot.manifestDelta.Identity(), Ranges: make([]rangeWire, len(snapshot.ranges)),
	}
	for index, sourceRange := range snapshot.ranges {
		preimage.Ranges[index] = rangeWire{sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine()}
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
