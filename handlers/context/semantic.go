package context

import (
	"fmt"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

type semanticOmissionSummary struct {
	path        string
	line, count int
}

func appendSemanticCandidates(contents map[string][]byte, memoryScope memorycore.Scope, profile semanticimpact.Profile, candidates []review.ContextSource, omissions []review.ContextSourceOmission) ([]review.ContextSource, []review.ContextSourceOmission, controlplane.RunFailure) {
	seenReferences := map[string]bool{}
	seenRanges := map[string]bool{}
	rejectedRanges := map[string]string{}
	for _, candidate := range candidates {
		seenReferences[candidate.ReferenceID()] = true
		sourceRange := candidate.EvidenceItem().SourceRange()
		seenRanges[semanticRangeKey(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())] = true
	}
	summaries := map[string]semanticOmissionSummary{}
	omit := func(reason, path string, line int) {
		value := summaries[reason]
		if value.count == 0 {
			value.path, value.line = path, line
		}
		value.count++
		summaries[reason] = value
	}
	for _, ref := range profile.References() {
		content, ok := contents[ref.Path()]
		if !ok {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		sourceRange, err := evidence.NewSourceRange(ref.Path(), ref.Line(), ref.Line())
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		rangeKey := semanticRangeKey(ref.Path(), ref.Line(), ref.Line())
		if reason, exists := rejectedRanges[rangeKey]; exists {
			omit(reason, ref.Path(), ref.Line())
			continue
		}
		if seenRanges[rangeKey] {
			omit("semantic_duplicate_source", ref.Path(), ref.Line())
			continue
		}
		if len(candidates) >= maximumContextCandidates {
			omit("semantic_candidate_limit", ref.Path(), ref.Line())
			rejectedRanges[rangeKey] = "semantic_candidate_limit"
			continue
		}
		if !memoryScope.AllowsPath(ref.Path()) {
			omit("semantic_path_not_authorized", ref.Path(), ref.Line())
			rejectedRanges[rangeKey] = "semantic_path_not_authorized"
			continue
		}
		slice, ok := physicalLineSlice(content, ref.Line(), ref.Line())
		if !ok {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		if len(slice) > maximumContextSourceBytes {
			omit("semantic_source_size_limit", ref.Path(), ref.Line())
			rejectedRanges[rangeKey] = "semantic_source_size_limit"
			continue
		}
		file, err := evidence.NewRepositoryFile(ref.Path(), content)
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		binding, err := evidence.BindSourceSlice(file, content, sourceRange, slice)
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		if seenReferences[binding.Identity()] {
			omit("semantic_duplicate_source", ref.Path(), ref.Line())
			seenRanges[rangeKey] = true
			continue
		}
		item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), sourceRange)
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		candidate, err := review.NewBoundContextSource(review.ContextStageDirectReference, memorycore.TaintRepositoryControlled, item, slice, binding)
		if err != nil {
			return nil, nil, controlplane.RunFailureInvalidInput
		}
		candidates = append(candidates, candidate)
		seenReferences[binding.Identity()] = true
		seenRanges[rangeKey] = true
	}
	for reason, summary := range summaries {
		value, err := review.NewCountedContextSourceOmission(summary.path, summary.line, summary.line, reason, uint32(summary.count))
		if err != nil {
			return nil, nil, controlplane.RunFailureInternal
		}
		omissions = append(omissions, value)
	}
	return candidates, omissions, 0
}
func semanticRangeKey(path string, start, end int) string {
	return fmt.Sprintf("%s\x00%d\x00%d", path, start, end)
}
