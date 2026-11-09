package context

import (
	"bytes"
	"sort"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

const (
	maximumInstructionFileBytes  = 8 << 10
	maximumInstructionTotalBytes = 16 << 10
)

// repositoryInstructionReason prefixes every instruction-file omission reason.
// Review accounting keys on the prefix to keep instruction context out of
// changed-source coverage.
func repositoryInstructionReason(reason string) string { return "repository_instruction_" + reason }

// appendRepositoryInstructionCandidates adds the base tree's instruction files
// as bounded repository_context sources. A pull request author controls the
// head tree, so a head edit to an instruction file must never steer review: the
// edit is already a changed_hunk source and is reviewed as code. A base file is
// used only when the head holds byte-identical content (equal digest and size),
// so the source binds identically to the immutable head snapshot that every
// later readback checks. A base file that the head changed or deleted is
// recorded as repository_instruction_changed. A file absent from the base,
// including every file against an empty base, contributes nothing. Sources are
// repository-controlled data and advisory preferences only: the model contract
// still treats all source content as untrusted data that cannot override
// instructions.
func appendRepositoryInstructionCandidates(base []sourceoutput.FileReference, contents map[string][]byte, scope memorycore.Scope, candidates []review.ContextSource, omissions []review.ContextSourceOmission) ([]review.ContextSource, []review.ContextSourceOmission, controlplane.RunFailure) {
	omit := func(filePath string, start, end int, reason string) controlplane.RunFailure {
		omission, err := review.NewContextSourceOmission(filePath, start, end, repositoryInstructionReason(reason))
		if err != nil {
			return controlplane.RunFailureInternal
		}
		omissions = append(omissions, omission)
		return 0
	}
	instructionPaths := review.RepositoryInstructionPaths()
	baseFiles := make(map[string]sourceoutput.FileReference, len(instructionPaths))
	for _, reference := range base {
		baseFiles[reference.Path()] = reference
	}
	used := 0
	for _, filePath := range instructionPaths {
		baseFile, inBase := baseFiles[filePath]
		if !inBase || baseFile.SizeBytes() == 0 {
			continue
		}
		content, inHead := contents[filePath]
		var failure controlplane.RunFailure
		switch {
		case !scope.AllowsPath(filePath):
			failure = omit(filePath, 0, 0, "path_not_authorized")
		case !inHead || !sameBaseContent(baseFile, filePath, content):
			failure = omit(filePath, 0, 0, "changed")
		case !isFallbackText(content):
			failure = omit(filePath, 0, 0, "unsupported_content")
		case len(candidates) >= maximumContextCandidates:
			failure = omit(filePath, 0, 0, "candidate_limit")
		default:
			var source review.ContextSource
			var added bool
			source, added, failure = instructionSource(filePath, content, min(maximumInstructionFileBytes, maximumInstructionTotalBytes-used), candidates, omit)
			if added {
				candidates = append(candidates, source)
				used += source.SizeBytes()
			}
		}
		if failure != 0 {
			return nil, nil, failure
		}
	}
	return candidates, omissions, 0
}

// sameBaseContent reports whether head content is byte-identical to the base
// file reference, by the same digest the source snapshot recorded.
func sameBaseContent(base sourceoutput.FileReference, filePath string, content []byte) bool {
	if len(content) != base.SizeBytes() {
		return false
	}
	file, err := evidence.NewRepositoryFile(filePath, content)
	return err == nil && file.Digest() == base.Digest()
}

// fitRepositoryInstructionCandidates keeps only the instruction sources that the
// deterministic stage-first selection would select after every changed source,
// and records the rest as repository_instruction_packet_budget. Instruction
// context therefore never appears as a selection omission, which would count
// against changed-source coverage. Selection order is stage first, then
// reference ID, so earlier-stage results do not depend on these sources.
func fitRepositoryInstructionCandidates(baseline review.ContextSourceSelection, instructions []review.ContextSource, omissions []review.ContextSourceOmission, maxSourceBytes uint32) ([]review.ContextSource, []review.ContextSourceOmission, controlplane.RunFailure) {
	ordered := append([]review.ContextSource(nil), instructions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ReferenceID() < ordered[j].ReferenceID() })
	count, used := baseline.SelectedCount(), baseline.SelectedBytes()
	kept := make([]review.ContextSource, 0, len(ordered))
	for _, source := range ordered {
		size := uint32(source.SizeBytes())
		if count < review.MaxSelectedContextSources && size <= maxSourceBytes-used {
			kept = append(kept, source)
			count++
			used += size
			continue
		}
		rangeValue := source.EvidenceItem().SourceRange()
		omission, err := review.NewContextSourceOmission(rangeValue.Path(), rangeValue.StartLine(), rangeValue.EndLine(), repositoryInstructionReason("packet_budget"))
		if err != nil {
			return nil, nil, controlplane.RunFailureInternal
		}
		omissions = append(omissions, omission)
	}
	return kept, omissions, 0
}

// instructionSource builds one source from the longest whole-line prefix that
// fits the remaining byte allowance, recording truncation as an omission.
func instructionSource(filePath string, content []byte, allowance int, existing []review.ContextSource, omit func(string, int, int, string) controlplane.RunFailure) (review.ContextSource, bool, controlplane.RunFailure) {
	totalLines := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		totalLines++
	}
	endLine := totalLines
	if len(content) > allowance {
		cut := -1
		if allowance > 0 {
			cut = bytes.LastIndexByte(content[:allowance], '\n')
		}
		if cut < 0 {
			return review.ContextSource{}, false, omit(filePath, 0, 0, "size_limit")
		}
		endLine = bytes.Count(content[:cut+1], []byte{'\n'})
		if failure := omit(filePath, endLine+1, totalLines, "truncated"); failure != 0 {
			return review.ContextSource{}, false, failure
		}
	}
	slice, ok := physicalLineSlice(content, 1, endLine)
	if !ok || !utf8.Valid(slice) {
		return review.ContextSource{}, false, controlplane.RunFailureInvalidInput
	}
	repositoryFile, err := evidence.NewRepositoryFile(filePath, content)
	if err != nil {
		return review.ContextSource{}, false, controlplane.RunFailureInvalidInput
	}
	rangeValue, err := evidence.NewSourceRange(filePath, 1, endLine)
	if err != nil {
		return review.ContextSource{}, false, controlplane.RunFailureInvalidInput
	}
	binding, err := evidence.BindSourceSlice(repositoryFile, content, rangeValue, slice)
	if err != nil {
		return review.ContextSource{}, false, controlplane.RunFailureInvalidInput
	}
	for _, candidate := range existing {
		if candidate.ReferenceID() == binding.Identity() {
			// The identical slice is already a changed hunk; do not duplicate it.
			return review.ContextSource{}, false, 0
		}
	}
	item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), rangeValue)
	if err != nil {
		return review.ContextSource{}, false, controlplane.RunFailureInvalidInput
	}
	source, err := review.NewBoundContextSource(review.ContextStageRepositoryContext, memorycore.TaintRepositoryControlled, item, slice, binding)
	if err != nil {
		return review.ContextSource{}, false, controlplane.RunFailureInvalidInput
	}
	return source, true, 0
}
