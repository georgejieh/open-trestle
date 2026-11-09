package context

import (
	"context"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// appendRemovedLinesCandidates adds the removed base lines of each deletion
// point (deterministic evidence version 7) as removed_lines sources. Each one
// is rebound to the exact base file: the base snapshot reference must carry the
// digest the analysis record and its change entry name, and the reloaded bytes
// must rebuild the record's repository-file identity and slice binding.
// Removed text that cannot be supplied is an explicit omission at its base
// lines; it is never truncated.
func (h *Handler) appendRemovedLinesCandidates(ctx context.Context, scope audit.ReviewScope, at time.Time, base sourceoutput.Snapshot, removed []analysiscodec.Item, memoryScope memorycore.Scope, candidates []review.ContextSource, omissions []review.ContextSourceOmission, expires *time.Time) ([]review.ContextSource, []review.ContextSourceOmission, controlplane.RunFailure) {
	references := make(map[string]sourceoutput.FileReference, base.FileCount())
	for _, reference := range base.Files() {
		references[reference.Path()] = reference
	}
	contents := make(map[string][]byte)
	defer clearContents(contents)
	loaded := 0
	for _, item := range removed {
		if ctx.Err() != nil {
			return nil, nil, controlplane.RunFailureCanceled
		}
		reference, ok := references[item.Path()]
		if !ok || reference.Digest() != item.FileDigest() {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		content, cached := contents[item.Path()]
		if !cached {
			if loaded > maximumContextRepositoryBytes-reference.SizeBytes() {
				return nil, nil, controlplane.RunFailureResourceLimit
			}
			value, err := h.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
			if err != nil {
				return nil, nil, readFailure(ctx, err)
			}
			file, err := sourceoutput.ParseFileArtifact(value, base, reference)
			if err != nil {
				return nil, nil, controlplane.RunFailureInvalidInput
			}
			content = file.Content()
			contents[item.Path()] = content
			loaded += len(content)
			if value.ExpiresAt().Before(*expires) {
				*expires = value.ExpiresAt()
			}
		}
		repositoryFile, err := evidence.NewRepositoryFile(item.Path(), content)
		if err != nil || repositoryFile.Identity() != item.FileIdentity() || repositoryFile.Digest() != item.FileDigest() || repositoryFile.SizeBytes() != reference.SizeBytes() {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		rangeValue, err := evidence.NewSourceRange(item.Path(), item.StartLine(), item.EndLine())
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		slice, ok := physicalLineSlice(content, item.StartLine(), item.EndLine())
		if !ok {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(repositoryFile, content, rangeValue, slice)
		if err != nil || binding.Identity() != item.BindingIdentity() || binding.SliceBytes() != item.SliceBytes() || binding.SliceDigest() != item.Digest() {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		reason := ""
		switch {
		case !memoryScope.AllowsPath(item.Path()):
			reason = "path_not_authorized"
		case !strings.HasSuffix(item.Path(), ".go") && excludedFallbackPath(item.Path()):
			reason = "excluded_path"
		case !isFallbackText(slice):
			reason = "non_text_content"
		case len(slice) > maximumContextSourceBytes:
			reason = "source_size_limit"
		case len(candidates) >= maximumContextCandidates:
			reason = "candidate_limit"
		}
		if reason != "" {
			omission, err := review.NewContextSourceOmission(item.Path(), item.StartLine(), item.EndLine(), reason)
			if err != nil {
				return nil, nil, controlplane.RunFailureInternal
			}
			omissions = append(omissions, omission)
			continue
		}
		evidenceItem, err := item.EvidenceItem()
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		source, err := review.NewRemovedLinesContextSource(evidenceItem, slice, binding, item.HeadLine())
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		candidates = append(candidates, source)
	}
	return candidates, omissions, 0
}

// fitRemovedLinesCandidates keeps a deletion point's removed text only when a
// selected changed hunk of its file contains its head line: every later
// readback treats such text without that head context as unbound. The removed
// text of an emptied or removed file has no head line and no head context to
// need. A dropped source is recorded as a packet_budget omission at its base
// lines. Removed text sorts after changed hunks, so dropping it never changes
// which changed hunks are selected.
func fitRemovedLinesCandidates(candidates []review.ContextSource, limits review.ContextLimits, omissions []review.ContextSourceOmission) ([]review.ContextSource, review.ContextSourceSelection, []review.ContextSourceOmission, controlplane.RunFailure) {
	for {
		selection, err := review.SelectContextSources(candidates, limits)
		if err != nil {
			return nil, review.ContextSourceSelection{}, nil, controlplane.RunFailureResourceLimit
		}
		var hunks []evidence.SourceRange
		for _, source := range selection.SelectedSources() {
			if source.Stage() == review.ContextStageChangedHunk {
				hunks = append(hunks, source.EvidenceItem().SourceRange())
			}
		}
		unanchored := make(map[string]bool)
		for _, source := range selection.SelectedSources() {
			if source.Stage() == review.ContextStageRemovedLines && source.HeadLine() != 0 && !headLineSelected(hunks, source.EvidenceItem().SourceRange().Path(), source.HeadLine()) {
				unanchored[source.ReferenceID()] = true
			}
		}
		if len(unanchored) == 0 {
			return candidates, selection, omissions, 0
		}
		kept := make([]review.ContextSource, 0, len(candidates)-len(unanchored))
		for _, source := range candidates {
			if !unanchored[source.ReferenceID()] {
				kept = append(kept, source)
				continue
			}
			rangeValue := source.EvidenceItem().SourceRange()
			omission, err := review.NewContextSourceOmission(rangeValue.Path(), rangeValue.StartLine(), rangeValue.EndLine(), "packet_budget")
			if err != nil {
				return nil, review.ContextSourceSelection{}, nil, controlplane.RunFailureInternal
			}
			omissions = append(omissions, omission)
		}
		candidates = kept
	}
}

// headLineSelected reports whether a selected changed hunk of path contains line.
func headLineSelected(hunks []evidence.SourceRange, path string, line int) bool {
	for _, hunk := range hunks {
		if hunk.Path() == path && hunk.StartLine() <= line && line <= hunk.EndLine() {
			return true
		}
	}
	return false
}
