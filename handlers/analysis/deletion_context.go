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

// deletionContextLines is how many unchanged head lines on each side of a
// deletion point are bound as reviewable context.
const deletionContextLines = 8

// deletionContext is the reviewable evidence for one deletion-only entry: the
// unchanged head lines around each deletion point, bound to the exact head
// file, and one deleted_lines gap per deletion point that records where base
// lines were removed. The removed base text is not supplied.
type deletionContext struct {
	items []Item
	gaps  []Gap
}

// buildDeletionContext derives deletion points by diffing the exact base and
// head files of a deletion-only entry. It returns ok=false, with no failure,
// whenever context cannot be built within bounds (empty head, diff limits,
// unsupported content, evidence limits); the caller then records the
// whole-entry no_changed_head_lines gap exactly as before.
func (h *Handler) buildDeletionContext(ctx context.Context, scope audit.ReviewScope, at time.Time, base, head source.Snapshot, entry changehandler.Entry, loaded *int, expires *time.Time, itemCount, gapCount int) (deletionContext, bool, controlplane.RunFailure) {
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
	var windows, markers []window
	for _, hunk := range lineMap.Hunks() {
		if hunk.Kind() != evidence.HunkKindDeletion {
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
		if after > headLines {
			after = before
		}
		markers = append(markers, window{before, after})
		start, end := max(1, cursor-deletionContextLines), min(headLines, cursor+deletionContextLines-1)
		if count := len(windows); count > 0 && start <= windows[count-1].end+1 {
			windows[count-1].end = max(windows[count-1].end, end)
			continue
		}
		windows = append(windows, window{start, end})
	}
	if len(windows) == 0 || itemCount+len(windows) > maximumEvidenceItems || gapCount+len(markers) > maximumEvidenceItems {
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
