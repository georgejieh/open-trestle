package analysis

import (
	"context"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	"github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	// deletionContextLines is how many unchanged head lines on each side of a
	// deletion point are bound as reviewable context.
	deletionContextLines = 8
	// removedLinesPerPoint and removedBytesPerPoint bound the removed base
	// text bound at one deletion point; removedBytesPerEntry bounds the total
	// for one entry. Removed text past a bound is recorded as a
	// removed_lines_limit gap, never truncated.
	removedLinesPerPoint = 64
	removedBytesPerPoint = 8 << 10
	removedBytesPerEntry = 32 << 10
)

// deletionContext is the reviewable evidence for one deletion-only entry: the
// unchanged head lines around each deletion point, bound to the exact head
// file; one deleted_lines gap per distinct deletion point that records where
// base lines were removed; and, for each deletion point, either the removed
// base lines bound to the exact base file or a removed_lines_limit gap.
type deletionContext struct {
	items   []Item
	removed []Item
	gaps    []Gap
}

// buildDeletionContext derives deletion points by diffing the exact base and
// head files of a deletion-only entry. It returns ok=false, with no failure,
// whenever context cannot be built within bounds (empty head, diff limits,
// unsupported content, evidence limits); the caller then records the
// whole-entry no_changed_head_lines gap exactly as before.
func (h *Handler) buildDeletionContext(ctx context.Context, scope audit.ReviewScope, at time.Time, base, head source.Snapshot, entry changehandler.Entry, loaded *int, expires *time.Time, itemCount, removedCount, gapCount int) (deletionContext, bool, controlplane.RunFailure) {
	headReference, baseReference, ok := deletionReferences(base, head, entry)
	if !ok {
		return deletionContext{}, false, controlplane.RunFailureInvalidInput
	}
	if headReference.SizeBytes() == 0 || *loaded+headReference.SizeBytes()+baseReference.SizeBytes() > maximumEvidenceSourceBytes {
		return deletionContext{}, false, 0
	}
	headContent, failureCode := h.loadSourceFile(ctx, scope, at, head, headReference, expires)
	if failureCode != 0 {
		return deletionContext{}, false, failureCode
	}
	defer clear(headContent)
	baseContent, failureCode := h.loadSourceFile(ctx, scope, at, base, baseReference, expires)
	if failureCode != 0 {
		return deletionContext{}, false, failureCode
	}
	defer clear(baseContent)
	*loaded += len(headContent) + len(baseContent)
	repositoryFile, err := evidence.NewRepositoryFile(entry.Path(), headContent)
	if err != nil || repositoryFile.Identity() != entry.HeadIdentity() || repositoryFile.Digest() != entry.HeadDigest() {
		return deletionContext{}, false, controlplane.RunFailureInvalidInput
	}
	baseFile, err := evidence.NewRepositoryFile(entry.Path(), baseContent)
	if err != nil || baseFile.Digest() != entry.BaseDigest() || baseFile.Digest() != baseReference.Digest() || baseFile.SizeBytes() != baseReference.SizeBytes() {
		return deletionContext{}, false, controlplane.RunFailureInvalidInput
	}
	patch, err := evidence.GenerateUnifiedFileDiff(entry.Path(), baseContent, headContent)
	if err != nil {
		return deletionContext{}, false, 0
	}
	_, lineMap, err := evidence.ParseUnifiedFileDiff(entry.Path(), baseContent, headContent, patch)
	if err != nil {
		return deletionContext{}, false, 0
	}
	headLines := lineMap.HeadLineCount()
	type window struct{ start, end int }
	type removal struct{ start, end, headLine int }
	var windows, markers []window
	var removedRanges []removal
	for _, hunk := range lineMap.Hunks() {
		if hunk.Kind() != evidence.HunkKindDeletion || hunk.BaseLineCount() < 1 {
			// A deletion-only entry has no changed head lines, so any other
			// hunk means the diff disagrees with the change model.
			return deletionContext{}, false, controlplane.RunFailureInvalidInput
		}
		// The cursor is the head line that follows the removed base lines; it
		// is headLines+1 for a deletion at the end of the file.
		cursor := hunk.HeadStartLine()
		before, after := cursor-1, cursor
		if before < 1 {
			before = after
		}
		// The removed text names its deletion point by the marker's first
		// head line.
		removedRanges = append(removedRanges, removal{hunk.BaseStartLine(), hunk.BaseStartLine() + hunk.BaseLineCount() - 1, before})
		if after > headLines {
			after = before
		}
		// In a one-line head file, deletions before and after its only line
		// share the same marker; record that deletion point once.
		if count := len(markers); count == 0 || markers[count-1] != (window{before, after}) {
			markers = append(markers, window{before, after})
		}
		start, end := max(1, cursor-deletionContextLines), min(headLines, cursor+deletionContextLines-1)
		if count := len(windows); count > 0 && start <= windows[count-1].end+1 {
			windows[count-1].end = max(windows[count-1].end, end)
			continue
		}
		windows = append(windows, window{start, end})
	}
	if len(windows) == 0 || itemCount+len(windows) > maximumEvidenceItems || removedCount+len(removedRanges) > maximumEvidenceItems || gapCount+len(markers)+len(removedRanges) > maximumEvidenceItems {
		return deletionContext{}, false, 0
	}
	var result deletionContext
	for _, value := range windows {
		sourceRange, err := evidence.NewSourceRange(entry.Path(), value.start, value.end)
		if err != nil {
			return deletionContext{}, false, controlplane.RunFailureInvalidInput
		}
		slice, ok := physicalLineSlice(headContent, value.start, value.end)
		if !ok {
			return deletionContext{}, false, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(repositoryFile, headContent, sourceRange, slice)
		if err != nil {
			return deletionContext{}, false, 0
		}
		item, err := analysiscodec.NewDeletionContextItem(entry, binding)
		if err != nil {
			return deletionContext{}, false, controlplane.RunFailureInternal
		}
		result.items = append(result.items, item)
	}
	for _, value := range markers {
		result.gaps = append(result.gaps, analysiscodec.NewGap(entry, value.start, value.end, analysiscodec.DeletionContextReason))
	}
	// Bind the removed base lines of each deletion point to the exact base
	// file. A point past a bound is recorded whole as removed_lines_limit at its
	// base range; its text is never truncated.
	entryBytes := 0
	for _, value := range removedRanges {
		slice, ok := physicalLineSlice(baseContent, value.start, value.end)
		if !ok {
			return deletionContext{}, false, controlplane.RunFailureInvalidInput
		}
		if value.end-value.start+1 > removedLinesPerPoint || len(slice) > removedBytesPerPoint || len(slice) > removedBytesPerEntry-entryBytes {
			result.gaps = append(result.gaps, analysiscodec.NewGap(entry, value.start, value.end, analysiscodec.RemovedLinesLimitReason))
			continue
		}
		sourceRange, err := evidence.NewSourceRange(entry.Path(), value.start, value.end)
		if err != nil {
			return deletionContext{}, false, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(baseFile, baseContent, sourceRange, slice)
		if err != nil {
			return deletionContext{}, false, controlplane.RunFailureInvalidInput
		}
		item, err := analysiscodec.NewRemovedLinesItem(entry, binding, value.headLine)
		if err != nil {
			return deletionContext{}, false, controlplane.RunFailureInternal
		}
		result.removed = append(result.removed, item)
		entryBytes += len(slice)
	}
	return result, true, 0
}

func deletionReferences(base, head source.Snapshot, entry changehandler.Entry) (source.FileReference, source.FileReference, bool) {
	var headReference, baseReference source.FileReference
	foundHead, foundBase := false, false
	for _, reference := range head.Files() {
		if reference.Path() == entry.Path() {
			headReference, foundHead = reference, true
			break
		}
	}
	for _, reference := range base.Files() {
		if reference.Path() == entry.Path() {
			baseReference, foundBase = reference, true
			break
		}
	}
	ok := foundHead && foundBase && headReference.Digest() == entry.HeadDigest() && baseReference.Digest() == entry.BaseDigest()
	return headReference, baseReference, ok
}

func (h *Handler) loadSourceFile(ctx context.Context, scope audit.ReviewScope, at time.Time, snapshot source.Snapshot, reference source.FileReference, expires *time.Time) ([]byte, controlplane.RunFailure) {
	fileArtifact, err := h.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	file, err := source.ParseFileArtifact(fileArtifact, snapshot, reference)
	if err != nil {
		return nil, controlplane.RunFailureInvalidInput
	}
	if fileArtifact.ExpiresAt().Before(*expires) {
		*expires = fileArtifact.ExpiresAt()
	}
	return file.Content(), 0
}
