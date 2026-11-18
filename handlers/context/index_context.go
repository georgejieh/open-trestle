package context

import (
	"context"
	"slices"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

// IndexContextSource proposes context for a change from a repository index:
// line ranges of unchanged head code and host-computed facts. The handler
// binds every range against the head snapshot it already verified, so the
// text a model sees comes from that snapshot, never from the index.
type IndexContextSource interface {
	Identity() string
	ContextPlan(ctx context.Context, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.ContextPlan, error)
}

// indexContextFit is the index context a packet includes and what it left
// out.
type indexContextFit struct {
	sources  []review.ContextSource
	included []review.ContextManifestSource
	omitted  []review.ContextManifestOmission
}

// fitIndexContext binds the plan's items in priority order, by stage and
// then rank, into the bytes and source slots the selected sources left. An
// item that does not fit is left out with its reason and a later, smaller
// item may still fit.
func fitIndexContext(plan review.ContextPlan, contents map[string][]byte, scope memorycore.Scope, existing []review.ContextSource, freeBytes, freeSources, freeCandidates int) (indexContextFit, controlplane.RunFailure) {
	fit := indexContextFit{}
	omit := func(stage review.ContextStage, reason string, count int) {
		fit.omitted = append(fit.omitted, review.ContextManifestOmission{Stage: stage, Reason: reason, Count: count})
	}
	for stage, count := range plan.StageOmitted {
		omit(stage, review.ContextOmittedStageLimit, count)
	}
	shown := map[string][][2]int{}
	references := map[string]bool{}
	for _, source := range existing {
		rangeValue := source.EvidenceItem().SourceRange()
		shown[rangeValue.Path()] = append(shown[rangeValue.Path()], [2]int{rangeValue.StartLine(), rangeValue.EndLine()})
		references[source.ReferenceID()] = true
	}
	items := slices.Clone(plan.Items)
	slices.SortStableFunc(items, func(a, b review.ContextPlanItem) int { return int(a.Stage) - int(b.Stage) })
	for _, item := range items {
		content, ok := contents[item.Path]
		lastLine := lineCount(content)
		start, end := item.StartLine, min(item.EndLine, lastLine)
		if !ok || start < 1 || start > end || !indexStage(item.Stage) {
			omit(item.Stage, review.ContextOmittedRange, 1)
			continue
		}
		if !scope.AllowsPath(item.Path) {
			omit(item.Stage, review.ContextOmittedPath, 1)
			continue
		}
		if slices.ContainsFunc(shown[item.Path], func(r [2]int) bool { return r[0] <= start && end <= r[1] }) {
			omit(item.Stage, review.ContextOmittedDuplicate, 1)
			continue
		}
		slice, ok := physicalLineSlice(content, start, end)
		if !ok {
			omit(item.Stage, review.ContextOmittedRange, 1)
			continue
		}
		switch {
		case !isFallbackText(slice):
			omit(item.Stage, review.ContextOmittedContent, 1)
			continue
		case len(slice) > maximumContextSourceBytes:
			omit(item.Stage, review.ContextOmittedSizeLimit, 1)
			continue
		case freeSources == 0 || freeCandidates == 0:
			omit(item.Stage, review.ContextOmittedSourceLimit, 1)
			continue
		case len(slice) > freeBytes:
			omit(item.Stage, review.ContextOmittedPacketBudget, 1)
			continue
		}
		source, failure := bindIndexSource(item, content, slice, end)
		if failure != 0 {
			return indexContextFit{}, failure
		}
		if references[source.ReferenceID()] {
			omit(item.Stage, review.ContextOmittedDuplicate, 1)
			continue
		}
		references[source.ReferenceID()] = true
		shown[item.Path] = append(shown[item.Path], [2]int{start, end})
		fit.sources = append(fit.sources, source)
		fit.included = append(fit.included, review.ContextManifestSource{SourceID: source.ReferenceID(), Stage: item.Stage, Rank: item.Rank, Depth: item.Depth})
		freeBytes -= len(slice)
		freeSources--
		freeCandidates--
	}
	return fit, 0
}

func indexStage(stage review.ContextStage) bool {
	switch stage {
	case review.ContextStageEnclosingSymbol, review.ContextStageDirectReference, review.ContextStageRelatedTest, review.ContextStageRepositoryMap:
		return true
	}
	return false
}

func bindIndexSource(item review.ContextPlanItem, content, slice []byte, end int) (review.ContextSource, controlplane.RunFailure) {
	file, err := evidence.NewRepositoryFile(item.Path, content)
	if err != nil {
		return review.ContextSource{}, controlplane.RunFailureInvalidInput
	}
	rangeValue, err := evidence.NewSourceRange(item.Path, item.StartLine, end)
	if err != nil {
		return review.ContextSource{}, controlplane.RunFailureInvalidInput
	}
	binding, err := evidence.BindSourceSlice(file, content, rangeValue, slice)
	if err != nil {
		return review.ContextSource{}, controlplane.RunFailureInvalidInput
	}
	evidenceItem, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), rangeValue)
	if err != nil {
		return review.ContextSource{}, controlplane.RunFailureInvalidInput
	}
	source, err := review.NewBoundContextSource(item.Stage, memorycore.TaintRepositoryControlled, evidenceItem, slice, binding)
	if err != nil {
		return review.ContextSource{}, controlplane.RunFailureInvalidInput
	}
	return source, 0
}

// lineCount counts the physical lines of content.
func lineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	n := 0
	for _, b := range content {
		if b == '\n' {
			n++
		}
	}
	if content[len(content)-1] != '\n' {
		n++
	}
	return n
}

// manifestDefinitions places each changed definition of the plan on the
// first selected changed_hunk or enclosing_symbol source of its file that
// overlaps it, at the first line they share.
func manifestDefinitions(plan review.ContextPlan, selected []review.ContextSource) ([]review.ContextManifestDefinition, int) {
	const maxListed = 256
	out := []review.ContextManifestDefinition{}
	notListed := 0
	for _, d := range plan.Changed {
		placed := false
		for _, source := range selected {
			rangeValue := source.EvidenceItem().SourceRange()
			if source.Stage() != review.ContextStageChangedHunk && source.Stage() != review.ContextStageEnclosingSymbol || rangeValue.Path() != d.Path || rangeValue.EndLine() < d.StartLine || rangeValue.StartLine() > d.EndLine {
				continue
			}
			if len(out) < maxListed {
				out = append(out, review.ContextManifestDefinition{SourceID: source.ReferenceID(), Line: max(d.StartLine, rangeValue.StartLine()), Dependents: d.Dependents, Tests: min(d.Tests, d.Dependents)})
				placed = true
			}
			break
		}
		if !placed {
			notListed++
		}
	}
	return out, notListed
}

// indexContextPlan asks the bound source for a plan. A failure of the source
// leaves the review with what it has, recorded as the index state; only
// cancellation fails the task.
func (h *Handler) indexContextPlan(ctx context.Context, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity) (review.ContextPlan, controlplane.RunFailure) {
	if nilInterface(h.index) {
		return review.UnavailableContextPlan(review.ContextIndexUnavailable), 0
	}
	plan, err := h.index.ContextPlan(ctx, repository, base, head)
	if ctx.Err() != nil {
		return review.ContextPlan{}, controlplane.RunFailureCanceled
	}
	if err != nil {
		return review.UnavailableContextPlan(review.ContextIndexFailed), 0
	}
	switch plan.State {
	case review.ContextIndexUsed:
		return plan, 0
	case review.ContextIndexUnavailable, review.ContextIndexOverBudget:
		return review.UnavailableContextPlan(plan.State), 0
	}
	return review.UnavailableContextPlan(review.ContextIndexFailed), 0
}
