package localreview

import (
	"bytes"
	"context"
	"path"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// Change-line accounting: which head lines the reviewed change touched, per
// path, from a fresh bounded diff of the base and head files the source tasks
// already recorded. With the run's semantic-impact profile it decides the
// origin class (introduced, unproven or pre-existing) and the walkthrough's
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
// finding is on unchanged lines. isolated records that the run's
// semantic-impact profile proves nothing outside the changed declarations
// reaches them (see isolatedChange); without that proof no finding on
// unchanged lines is pre-existing.
type changeLines struct {
	paths    map[string]*pathChange
	evidence map[string]bool
	isolated bool
}

// findingOrigin is the deterministic origin class of a verified finding.
type findingOrigin int

const (
	// originIntroduced: on lines the change touched, citing change evidence,
	// or where the lines or the change evidence are unknown.
	originIntroduced findingOrigin = iota
	// originUnproven: on unchanged lines and citing no change evidence, but
	// the change may still cause it, for example a caller of a changed
	// function. It blocks like an introduced finding.
	originUnproven
	// originPreExisting: on unchanged lines of an unchanged Go file, citing no
	// change evidence, in a run whose profile proves that nothing outside the
	// changed declarations reaches them. It never blocks.
	originPreExisting
)

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

// origin classifies a verified finding. It is on unchanged lines when both
// of these hold:
//
//   - it is on head lines, in an unchanged file (such as a direct reference:
//     a caller of a changed declaration) or in a modified file whose lines are
//     known, and it overlaps no changed line and no deletion window;
//   - none of its evidence is a changed hunk or removed lines.
//
// Unchanged lines do not prove that the defect predates the change: a
// changed function can break an unchanged caller, and unchanged lines of a
// modified file can depend on its changed imports or declarations. So such a
// finding is pre-existing only when it is in an unchanged Go file and the
// run's semantic-impact profile proves that nothing outside the changed
// declarations reaches them (isolated); otherwise its origin is unproven. A
// finding on removed base lines, in an added file, in a path whose lines are
// unknown, or in a run whose change evidence is unknown is introduced, so an
// uncertain finding keeps blocking.
func (c changeLines) origin(finding ReportFinding) findingOrigin {
	start, end := finding.StartLine, finding.EndLine
	if c.evidence == nil || finding.Side != diagnostics.LineSideHead || start == 0 || end < start {
		return originIntroduced
	}
	for _, id := range finding.EvidenceIDs {
		if c.evidence[id] {
			return originIntroduced
		}
	}
	lines, changed := c.paths[finding.Path]
	switch {
	case changed && !(lines.known && lines.kind == string(evidence.RepositoryFileDeltaModified) && !lines.touches(start, end)):
		return originIntroduced
	case changed || !c.isolated || path.Ext(finding.Path) != ".go":
		return originUnproven
	}
	return originPreExisting
}

// preExisting reports a finding whose origin is established as pre-existing.
func (c changeLines) preExisting(finding ReportFinding) bool {
	return c.origin(finding) == originPreExisting
}

// withImpact records whether the run's semantic-impact profile and context
// manifest prove the change isolated (see isolatedChange).
func (c changeLines) withImpact(profile semanticimpact.Profile, manifest review.ContextManifestSummary) changeLines {
	c.isolated = isolatedChange(profile, manifest)
	return c
}

// isolatedChange reports a change that nothing outside the changed
// declarations can reach. All of these hold:
//
//   - the semantic-impact profile records no coverage gap: every changed
//     path was analysed as Go;
//   - no changed declaration is a method or an init function, which code can
//     reach without naming them (an interface call from another package, a
//     method set that satisfies an interface, package initialization);
//   - the context manifest shows a complete repository index that found no
//     dependent of any changed definition outside the changed definitions.
//
// Dependents are reference candidates matched by name across the indexed
// head, so code that calls, uses or passes on a changed definition leaves
// one.
func isolatedChange(profile semanticimpact.Profile, manifest review.ContextManifestSummary) bool {
	if profile.Identity() == "" || len(profile.Gaps()) != 0 {
		return false
	}
	for _, declaration := range profile.Declarations() {
		if declaration.Kind() == "method" || declaration.Kind() == "function" && declaration.Name() == "init" {
			return false
		}
	}
	return manifest.Present && manifest.State == review.ContextIndexUsed && manifest.Complete && manifest.Dependents == 0
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
