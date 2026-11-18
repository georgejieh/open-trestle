package review

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// RecordedContext describes validated source accounting, not model execution authority.
type RecordedContext struct {
	identity, memoryScopeIdentity, memoryIdentity string
	snapshot                                      ReviewSnapshot
	evidenceItems                                 []evidence.EvidenceItem
	analyzed, selected, omitted                   int
}

func (r RecordedContext) Identity() string            { return r.identity }
func (r RecordedContext) MemoryScopeIdentity() string { return r.memoryScopeIdentity }
func (r RecordedContext) MemoryIdentity() string      { return r.memoryIdentity }
func (r RecordedContext) Snapshot() ReviewSnapshot    { return r.snapshot }
func (r RecordedContext) EvidenceItems() []evidence.EvidenceItem {
	return append([]evidence.EvidenceItem(nil), r.evidenceItems...)
}
func (r RecordedContext) Analyzed() int { return r.analyzed }
func (r RecordedContext) Selected() int { return r.selected }
func (r RecordedContext) Omitted() int  { return r.omitted }

// ParseRecordedContext reconstructs the acquired snapshot from exact head index metadata.
// It reads no source files and does not authorize dispatch.
func ParseRecordedContext(payload []byte, scope audit.ReviewScope, head sourceoutput.Snapshot) (RecordedContext, error) {
	if scope.Validate() != nil || head.ScopeIdentity() != scope.Identity() || len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return RecordedContext{}, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || len(wire.Sources) == 0 || len(wire.Sources) > maxContextSourcesCeiling || len(wire.SourceOmissions) > 16384 || wire.SourceCoverage.Available > maxContextSourceCandidates || wire.SourceCoverage.Analyzed > maxContextSourceCandidates+65536 {
		return RecordedContext{}, ErrInvalidContextPacketRequest
	}
	files := make([]evidence.RepositoryFile, 0, head.FileCount())
	for _, ref := range head.Files() {
		file, err := evidence.NewRecordedRepositoryFile(ref.Path(), ref.Digest(), ref.SizeBytes())
		if err != nil {
			return RecordedContext{}, ErrInvalidContextPacketRequest
		}
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil || manifest.Identity() != head.ManifestIdentity() {
		return RecordedContext{}, ErrInvalidContextPacketRequest
	}
	// The snapshot holds head ranges only: removed_lines sources carry base
	// line numbers and are evidence, not snapshot ranges.
	ranges := make([]evidence.SourceRange, 0, len(wire.Sources))
	items := make([]evidence.EvidenceItem, len(wire.Sources))
	for i, source := range wire.Sources {
		sourceRange, rangeErr := evidence.NewSourceRange(source.Path, source.StartLine, source.EndLine)
		if rangeErr != nil {
			return RecordedContext{}, ErrInvalidContextPacketRequest
		}
		if source.Stage != ContextStageRemovedLines.String() {
			ranges = append(ranges, sourceRange)
		}
		items[i], err = evidence.NewEvidenceItem(source.SourceID, evidence.EvidenceKindSource, source.EvidenceDigest, sourceRange)
		if err != nil {
			return RecordedContext{}, ErrInvalidContextPacketRequest
		}
	}
	snapshot, err := NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, ranges)
	if err != nil {
		return RecordedContext{}, ErrInvalidContextPacketRequest
	}
	digest := sha256.Sum256(payload)
	identity := hex.EncodeToString(digest[:])
	memoryIdentity := deriveContextMemoryIdentityFromWire(wire)
	if ValidateRecordedContextPacketRequest(payload, identity, scope.Identity(), wire.MemoryScopeIdentity, memoryIdentity, snapshot, items) != nil {
		return RecordedContext{}, ErrInvalidContextPacketRequest
	}
	if _, err := summarizeContextSourceOmissions(wire.SourceOmissions, wire.SourceCoverage.Omitted-wire.SourceCoverage.PreselectionOmitted); err != nil {
		return RecordedContext{}, ErrInvalidContextPacketRequest
	}
	return RecordedContext{identity: identity, memoryScopeIdentity: wire.MemoryScopeIdentity, memoryIdentity: memoryIdentity, snapshot: snapshot, evidenceItems: items, analyzed: wire.SourceCoverage.Analyzed, selected: wire.SourceCoverage.Selected, omitted: wire.SourceCoverage.Omitted}, nil
}
