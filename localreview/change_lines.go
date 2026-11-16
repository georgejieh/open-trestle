package localreview

import (
	"bytes"
	"context"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

// Change-line accounting: which head lines the reviewed change touched, per
// path, from a fresh bounded diff of the base and head files the source tasks
// already recorded. It decides the pre-existing class and the walkthrough's
// line counts. No Git object is read again and no model is called.

const (
	// deletionWindowLines is how many unchanged head lines on each side of a
	// deletion point count as touched by the deletion, the same window the
	// deterministic analysis binds as a deletion's reviewable context.
	deletionWindowLines = 8
	// changeLineReadBytes bounds the base and head bytes read for the whole
	// accounting; a path past it has unknown lines.
	changeLineReadBytes = 64 << 20
)

// pathChange is the line accounting of one changed path.
type pathChange struct {
	kind string // added, modified or removed
	// known is false when the lines could not be computed (binary or
	// non-UTF-8 content, a diff past its bounds, or unreadable files). A path
	// with unknown lines never yields a pre-existing finding.
	known          bool
	added, removed uint32
	// changed holds inclusive head ranges of added or replaced lines.
	changed [][2]uint32
	// deletions holds, for each block of removed base lines, the first head
	// line after it (one past the last head line at the end of the file).
	deletions []uint32
}

// changeLines is the accounting of every path in the recorded change model,
// with the generation context's change evidence: the source IDs of its
// changed hunks and removed lines. Without that evidence (evidence nil) no
// finding is pre-existing.
type changeLines struct {
	paths    map[string]*pathChange
	evidence map[string]bool
}

// touches reports whether the head lines start..end overlap a changed range or
// the window around a deletion point.
func (p *pathChange) touches(start, end uint32) bool {
	for _, lines := range p.changed {
		if start <= lines[1] && lines[0] <= end {
			return true
		}
	}
	for _, point := range p.deletions {
		low := uint32(1)
		if point > deletionWindowLines {
			low = point - deletionWindowLines
		}
		high := point + deletionWindowLines - 1
		if start <= high && low <= end {
			return true
		}
	}
	return false
}

// preExisting reports a verified finding that is anchored only on unchanged
// context lines and that cites no evidence of the change, so the verifier
// confirmed it from unchanged code alone. Both of these hold:
//
//   - it is on head lines, in an unchanged file (such as a direct reference:
//     a caller of a changed declaration) or in a modified file whose lines are
//     known, and it overlaps no changed line and no deletion window;
//   - none of its evidence is a changed hunk or removed lines.
//
// A finding on removed base lines, in an added file, in a path whose lines
// are unknown, or in a run whose change evidence is unknown is never
// pre-existing, so an uncertain finding keeps blocking.
func (c changeLines) preExisting(finding ReportFinding) bool {
	start, end := finding.StartLine, finding.EndLine
	if c.evidence == nil || finding.Side != diagnostics.LineSideHead || start == 0 || end < start {
		return false
	}
	for _, id := range finding.EvidenceIDs {
		if c.evidence[id] {
			return false
		}
	}
	lines, changed := c.paths[finding.Path]
	if !changed {
		return true
	}
	return lines.known && lines.kind == string(evidence.RepositoryFileDeltaModified) && !lines.touches(start, end)
}

// changeLineAccounting builds the accounting from a recorded change model and
// its base and head snapshots. It fails only when the snapshots cannot be
// read back; a single path that cannot be diffed has unknown lines. The
// change evidence is added separately (withContextEvidence).
func (s *Session) changeLineAccounting(ctx context.Context, scope audit.ReviewScope, recorded recordedChange, at time.Time) (changeLines, error) {
	base, err := sourcehandler.ParseSnapshotArtifact(recorded.base)
	if err != nil {
		return changeLines{}, err
	}
	head, err := sourcehandler.ParseSnapshotArtifact(recorded.head)
	if err != nil {
		return changeLines{}, err
	}
	baseFiles, headFiles := map[string]sourcehandler.FileReference{}, map[string]sourcehandler.FileReference{}
	for _, reference := range base.Files() {
		baseFiles[reference.Path()] = reference
	}
	for _, reference := range head.Files() {
		headFiles[reference.Path()] = reference
	}
	budget := changeLineReadBytes
	read := func(snapshot sourcehandler.Snapshot, reference sourcehandler.FileReference) ([]byte, bool) {
		if reference.SizeBytes() > budget {
			return nil, false
		}
		value, err := s.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
		if err != nil {
			return nil, false
		}
		file, err := sourcehandler.ParseFileArtifact(value, snapshot, reference)
		if err != nil {
			return nil, false
		}
		budget -= reference.SizeBytes()
		return file.Content(), true
	}
	lines := changeLines{paths: map[string]*pathChange{}}
	for _, entry := range recorded.change.Entries() {
		value := &pathChange{kind: entry.Kind()}
		lines.paths[entry.Path()] = value
		switch entry.Kind() {
		case string(evidence.RepositoryFileDeltaAdded):
			reference, ok := headFiles[entry.Path()]
			if !ok {
				continue
			}
			content, ok := read(head, reference)
			if !ok {
				continue
			}
			count := lineCount(content)
			clear(content)
			value.known, value.added = true, count
			if count > 0 {
				value.changed = [][2]uint32{{1, count}}
			}
		case string(evidence.RepositoryFileDeltaRemoved):
			reference, ok := baseFiles[entry.Path()]
			if !ok {
				continue
			}
			content, ok := read(base, reference)
			if !ok {
				continue
			}
			value.known, value.removed = true, lineCount(content)
			clear(content)
		case string(evidence.RepositoryFileDeltaModified):
			baseReference, hasBase := baseFiles[entry.Path()]
			headReference, hasHead := headFiles[entry.Path()]
			if !hasBase || !hasHead {
				continue
			}
			baseContent, ok := read(base, baseReference)
			if !ok {
				continue
			}
			headContent, ok := read(head, headReference)
			if !ok {
				clear(baseContent)
				continue
			}
			diffModifiedFile(value, entry.Path(), baseContent, headContent)
			clear(baseContent)
			clear(headContent)
		}
	}
	return lines, nil
}

// withContextEvidence adds a recorded generation context's change evidence.
// An unreadable context leaves the evidence unknown, which classifies no
// finding as pre-existing.
func (c changeLines) withContextEvidence(contextPayload []byte) changeLines {
	if c.paths == nil {
		return c
	}
	ids, err := review.ContextChangeEvidence(contextPayload)
	if err != nil {
		return c
	}
	c.evidence = ids
	return c
}

// diffModifiedFile fills a modified path's lines from the canonical bounded
// diff. A file the diff cannot represent keeps unknown lines.
func diffModifiedFile(value *pathChange, path string, baseContent, headContent []byte) {
	patch, err := evidence.GenerateUnifiedFileDiff(path, baseContent, headContent)
	if err != nil {
		return
	}
	_, lineMap, err := evidence.ParseUnifiedFileDiff(path, baseContent, headContent, patch)
	if err != nil {
		return
	}
	for _, hunk := range lineMap.Hunks() {
		value.added += uint32(hunk.HeadLineCount())
		value.removed += uint32(hunk.BaseLineCount())
		if hunk.HeadLineCount() > 0 {
			value.changed = append(value.changed, [2]uint32{uint32(hunk.HeadStartLine()), uint32(hunk.HeadStartLine() + hunk.HeadLineCount() - 1)})
		} else {
			value.deletions = append(value.deletions, uint32(hunk.HeadStartLine()))
		}
	}
	value.known = true
}

// lineCount counts lines; a last line without a newline still counts.
func lineCount(content []byte) uint32 {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		count++
	}
	return uint32(count)
}
