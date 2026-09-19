package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	maxContextSourceCandidates = 128
	maxSelectedContextSources  = 32
)

var (
	// ErrInvalidContextSourceSelectionReason identifies an unknown selection result.
	ErrInvalidContextSourceSelectionReason = errors.New("invalid context source selection reason")
	// ErrInvalidContextSourceSelection identifies malformed or inconsistent selection accounting.
	ErrInvalidContextSourceSelection = errors.New("invalid context source selection")
	// ErrInvalidContextSourceSelectionIdentity identifies selection content inconsistent with its identity.
	ErrInvalidContextSourceSelectionIdentity = errors.New("invalid context source selection identity")
)

// ContextSourceSelectionReason states why one available source was included or omitted.
type ContextSourceSelectionReason uint8

const (
	ContextSourceSelected ContextSourceSelectionReason = iota + 1
	ContextSourceOmittedByteLimit
	ContextSourceOmittedCountLimit
)

func (r ContextSourceSelectionReason) String() string {
	switch r {
	case ContextSourceSelected:
		return "selected"
	case ContextSourceOmittedByteLimit:
		return "omitted_byte_limit"
	case ContextSourceOmittedCountLimit:
		return "omitted_count_limit"
	default:
		return ""
	}
}

// ParseContextSourceSelectionReason parses one exact stable reason token.
func ParseContextSourceSelectionReason(value string) (ContextSourceSelectionReason, error) {
	for reason := ContextSourceSelected; reason <= ContextSourceOmittedCountLimit; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, ErrInvalidContextSourceSelectionReason
}

func (r ContextSourceSelectionReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidContextSourceSelectionReason
	}
	return nil
}

// ContextSourceSelectionEntry is a content-free decision for one available source.
type ContextSourceSelectionEntry struct {
	sourceIdentity string
	referenceID    string
	stage          ContextStage
	sizeBytes      uint32
	reason         ContextSourceSelectionReason
}

func (e ContextSourceSelectionEntry) SourceIdentity() string               { return e.sourceIdentity }
func (e ContextSourceSelectionEntry) ReferenceID() string                  { return e.referenceID }
func (e ContextSourceSelectionEntry) Stage() ContextStage                  { return e.stage }
func (e ContextSourceSelectionEntry) SizeBytes() uint32                    { return e.sizeBytes }
func (e ContextSourceSelectionEntry) Reason() ContextSourceSelectionReason { return e.reason }
func (e ContextSourceSelectionEntry) Selected() bool                       { return e.reason == ContextSourceSelected }
func (e ContextSourceSelectionEntry) String() string                       { return "review context source selection entry" }
func (e ContextSourceSelectionEntry) GoString() string {
	return "review.ContextSourceSelectionEntry{<redacted>}"
}

func (e ContextSourceSelectionEntry) Validate() error {
	if !validCandidateDigest(e.sourceIdentity) || !validCandidateReference(e.referenceID) || e.stage.Validate() != nil || e.sizeBytes == 0 || e.sizeBytes > maxContextSourceBytes || e.reason.Validate() != nil {
		return ErrInvalidContextSourceSelection
	}
	return nil
}

// ContextSourceOmissionCategory is a closed content-free omission class.
type ContextSourceOmissionCategory uint8

const (
	ContextOmissionAuthorization ContextSourceOmissionCategory = iota + 1
	ContextOmissionResourceLimit
	ContextOmissionUnsupported
	ContextOmissionAnalysisFailure
	ContextOmissionDuplicate
	ContextOmissionSelectionLimit
)

func (c ContextSourceOmissionCategory) String() string {
	switch c {
	case ContextOmissionAuthorization:
		return "authorization"
	case ContextOmissionResourceLimit:
		return "resource_limit"
	case ContextOmissionUnsupported:
		return "unsupported"
	case ContextOmissionAnalysisFailure:
		return "analysis_failure"
	case ContextOmissionDuplicate:
		return "duplicate"
	case ContextOmissionSelectionLimit:
		return "selection_limit"
	default:
		return ""
	}
}

// ContextSourceOmissionSummary aggregates one omission class without paths or content.
type ContextSourceOmissionSummary struct {
	reason ContextSourceOmissionCategory
	count  uint32
}

func newContextSourceOmissionSummary(reason ContextSourceOmissionCategory, count uint32) (ContextSourceOmissionSummary, error) {
	if reason.String() == "" || count == 0 || count > maxContextSourceCandidates+65536 {
		return ContextSourceOmissionSummary{}, ErrInvalidContextSourceSelection
	}
	return ContextSourceOmissionSummary{reason: reason, count: count}, nil
}
func (s ContextSourceOmissionSummary) Reason() ContextSourceOmissionCategory { return s.reason }
func (s ContextSourceOmissionSummary) Count() uint32                         { return s.count }
func (s ContextSourceOmissionSummary) Validate() error {
	rebuilt, err := newContextSourceOmissionSummary(s.reason, s.count)
	if err != nil || rebuilt != s {
		return ErrInvalidContextSourceSelection
	}
	return nil
}

// ContextSourceCoverage is content-free accounting for analyzed, selected, and omitted review sources.
type ContextSourceCoverage struct {
	verificationContextIdentity, reviewScopeIdentity, snapshotIdentity, candidateBatchIdentity string
	analyzedCount, selectedCount, omittedCount                                                 uint32
	omissionSummaries                                                                          []ContextSourceOmissionSummary
}

func newContextSourceCoverage(verificationContextIdentity, reviewScopeIdentity, snapshotIdentity, candidateBatchIdentity string, analyzedCount, selectedCount, omittedCount int, omissionSummaries []ContextSourceOmissionSummary) (ContextSourceCoverage, error) {
	validBindings := validCandidateDigest(verificationContextIdentity) && validCandidateDigest(reviewScopeIdentity) && validCandidateDigest(snapshotIdentity) && validCandidateDigest(candidateBatchIdentity)
	validCounts := analyzedCount > 0 && analyzedCount <= maxContextSourceCandidates+65536 && selectedCount > 0 && selectedCount <= maxSelectedContextSources && omittedCount >= 0
	canonicalSummaries := append([]ContextSourceOmissionSummary(nil), omissionSummaries...)
	sort.Slice(canonicalSummaries, func(i, j int) bool {
		return canonicalSummaries[i].Reason().String() < canonicalSummaries[j].Reason().String()
	})
	summaryTotal := uint64(0)
	validSummaries := len(canonicalSummaries) <= 6
	for index, summary := range canonicalSummaries {
		if summary.Validate() != nil || index > 0 && canonicalSummaries[index-1].Reason() == summary.Reason() {
			validSummaries = false
		}
		summaryTotal += uint64(summary.Count())
	}
	if len(canonicalSummaries) > 0 && summaryTotal != uint64(omittedCount) {
		validSummaries = false
	}
	if !validBindings || !validCounts || !validSummaries || uint64(selectedCount)+uint64(omittedCount) != uint64(analyzedCount) {
		return ContextSourceCoverage{}, ErrInvalidContextSourceSelection
	}
	return ContextSourceCoverage{verificationContextIdentity: verificationContextIdentity, reviewScopeIdentity: reviewScopeIdentity, snapshotIdentity: snapshotIdentity, candidateBatchIdentity: candidateBatchIdentity, analyzedCount: uint32(analyzedCount), selectedCount: uint32(selectedCount), omittedCount: uint32(omittedCount), omissionSummaries: canonicalSummaries}, nil
}

func (c ContextSourceCoverage) VerificationContextIdentity() string {
	return c.verificationContextIdentity
}
func (c ContextSourceCoverage) ReviewScopeIdentity() string    { return c.reviewScopeIdentity }
func (c ContextSourceCoverage) SnapshotIdentity() string       { return c.snapshotIdentity }
func (c ContextSourceCoverage) CandidateBatchIdentity() string { return c.candidateBatchIdentity }
func (c ContextSourceCoverage) AnalyzedCount() uint32          { return c.analyzedCount }
func (c ContextSourceCoverage) SelectedCount() uint32          { return c.selectedCount }
func (c ContextSourceCoverage) OmittedCount() uint32           { return c.omittedCount }
func (c ContextSourceCoverage) OmissionSummaries() []ContextSourceOmissionSummary {
	return append([]ContextSourceOmissionSummary(nil), c.omissionSummaries...)
}
func (c ContextSourceCoverage) Validate() error {
	rebuilt, err := newContextSourceCoverage(c.verificationContextIdentity, c.reviewScopeIdentity, c.snapshotIdentity, c.candidateBatchIdentity, int(c.analyzedCount), int(c.selectedCount), int(c.omittedCount), c.omissionSummaries)
	if err != nil || rebuilt.verificationContextIdentity != c.verificationContextIdentity || rebuilt.reviewScopeIdentity != c.reviewScopeIdentity || rebuilt.snapshotIdentity != c.snapshotIdentity || rebuilt.candidateBatchIdentity != c.candidateBatchIdentity || rebuilt.analyzedCount != c.analyzedCount || rebuilt.selectedCount != c.selectedCount || rebuilt.omittedCount != c.omittedCount || len(rebuilt.omissionSummaries) != len(c.omissionSummaries) {
		return ErrInvalidContextSourceSelection
	}
	for index := range rebuilt.omissionSummaries {
		if rebuilt.omissionSummaries[index] != c.omissionSummaries[index] {
			return ErrInvalidContextSourceSelection
		}
	}
	return nil
}

// ContextSourceSelection records every candidate and the deterministic bounded subset.
type ContextSourceSelection struct {
	identity        string
	limits          ContextLimits
	entries         []ContextSourceSelectionEntry
	selectedSources []ContextSource
	selectedBytes   uint32
}

// SelectContextSources applies fixed stage-first, reference-ID ordering and explicit bounds.
func SelectContextSources(candidates []ContextSource, limits ContextLimits) (ContextSourceSelection, error) {
	if err := limits.Validate(); err != nil {
		return ContextSourceSelection{}, err
	}
	if len(candidates) == 0 || len(candidates) > maxContextSourceCandidates {
		return ContextSourceSelection{}, ErrInvalidContextSource
	}
	canonical := append([]ContextSource(nil), candidates...)
	seenReferences := make(map[string]struct{}, len(canonical))
	for _, source := range canonical {
		if err := source.Validate(); err != nil {
			return ContextSourceSelection{}, err
		}
		if _, exists := seenReferences[source.ReferenceID()]; exists {
			return ContextSourceSelection{}, ErrDuplicateContextSource
		}
		seenReferences[source.ReferenceID()] = struct{}{}
	}
	sort.Slice(canonical, func(left, right int) bool {
		if canonical[left].Stage() != canonical[right].Stage() {
			return canonical[left].Stage() < canonical[right].Stage()
		}
		return canonical[left].ReferenceID() < canonical[right].ReferenceID()
	})
	selection := ContextSourceSelection{
		limits: limits, entries: make([]ContextSourceSelectionEntry, len(canonical)),
		selectedSources: make([]ContextSource, 0, min(len(canonical), maxSelectedContextSources)),
	}
	for index, source := range canonical {
		reason := ContextSourceSelected
		size := uint32(source.SizeBytes())
		switch {
		case len(selection.selectedSources) >= maxSelectedContextSources:
			reason = ContextSourceOmittedCountLimit
		case size > limits.MaxSourceBytes()-selection.selectedBytes:
			reason = ContextSourceOmittedByteLimit
		default:
			selection.selectedSources = append(selection.selectedSources, source)
			selection.selectedBytes += size
		}
		selection.entries[index] = ContextSourceSelectionEntry{
			sourceIdentity: source.Identity(), referenceID: source.ReferenceID(),
			stage: source.Stage(), sizeBytes: size, reason: reason,
		}
	}
	selection.identity = deriveContextSourceSelectionIdentity(selection)
	if err := selection.Validate(); err != nil {
		return ContextSourceSelection{}, err
	}
	return selection, nil
}

func (s ContextSourceSelection) Identity() string      { return s.identity }
func (s ContextSourceSelection) CandidateCount() int   { return len(s.entries) }
func (s ContextSourceSelection) SelectedCount() int    { return len(s.selectedSources) }
func (s ContextSourceSelection) OmittedCount() int     { return len(s.entries) - len(s.selectedSources) }
func (s ContextSourceSelection) SelectedBytes() uint32 { return s.selectedBytes }
func (s ContextSourceSelection) Entries() []ContextSourceSelectionEntry {
	return append([]ContextSourceSelectionEntry(nil), s.entries...)
}
func (s ContextSourceSelection) SelectedSources() []ContextSource {
	return append([]ContextSource(nil), s.selectedSources...)
}
func (s ContextSourceSelection) SourceIdentities() []string {
	identities := make([]string, len(s.entries))
	for index, entry := range s.entries {
		identities[index] = entry.SourceIdentity()
	}
	return identities
}
func (s ContextSourceSelection) String() string   { return "review context source selection" }
func (s ContextSourceSelection) GoString() string { return "review.ContextSourceSelection{<redacted>}" }
func (s ContextSourceSelection) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "review context source selection", "review.ContextSourceSelection{<redacted>}")
}

// Validate verifies complete deterministic accounting and selected-source correspondence.
func (s ContextSourceSelection) Validate() error {
	if err := s.limits.Validate(); err != nil {
		return err
	}
	if len(s.entries) == 0 || len(s.entries) > maxContextSourceCandidates || len(s.selectedSources) > maxSelectedContextSources {
		return ErrInvalidContextSourceSelection
	}
	selectedIndex := 0
	selectedBytes := uint32(0)
	previousStage := ContextStage(0)
	previousReference := ""
	seenReferences := make(map[string]struct{}, len(s.entries))
	for _, entry := range s.entries {
		if err := entry.Validate(); err != nil {
			return err
		}
		if entry.stage < previousStage || entry.stage == previousStage && previousReference != "" && entry.referenceID <= previousReference {
			return ErrInvalidContextSourceSelection
		}
		if _, exists := seenReferences[entry.referenceID]; exists {
			return ErrDuplicateContextSource
		}
		seenReferences[entry.referenceID] = struct{}{}
		expected := ContextSourceSelected
		switch {
		case selectedIndex >= maxSelectedContextSources:
			expected = ContextSourceOmittedCountLimit
		case entry.sizeBytes > s.limits.MaxSourceBytes()-selectedBytes:
			expected = ContextSourceOmittedByteLimit
		}
		if entry.reason != expected {
			return ErrInvalidContextSourceSelection
		}
		if entry.Selected() {
			if selectedIndex >= len(s.selectedSources) {
				return ErrInvalidContextSourceSelection
			}
			source := s.selectedSources[selectedIndex]
			if err := source.Validate(); err != nil {
				return err
			}
			if source.Identity() != entry.sourceIdentity || source.ReferenceID() != entry.referenceID || source.Stage() != entry.stage || source.SizeBytes() != int(entry.sizeBytes) {
				return ErrInvalidContextSourceSelection
			}
			selectedIndex++
			selectedBytes += entry.sizeBytes
		}
		previousStage, previousReference = entry.stage, entry.referenceID
	}
	if selectedIndex != len(s.selectedSources) || selectedBytes != s.selectedBytes || s.selectedBytes > s.limits.MaxSourceBytes() {
		return ErrInvalidContextSourceSelection
	}
	if s.identity != deriveContextSourceSelectionIdentity(s) {
		return ErrInvalidContextSourceSelectionIdentity
	}
	return nil
}

func deriveContextSourceSelectionIdentity(selection ContextSourceSelection) string {
	type entryRecord struct {
		Source    string `json:"source"`
		Reference string `json:"reference"`
		Stage     string `json:"stage"`
		Bytes     uint32 `json:"bytes"`
		Reason    string `json:"reason"`
	}
	entries := make([]entryRecord, len(selection.entries))
	for index, entry := range selection.entries {
		entries[index] = entryRecord{
			Source: entry.sourceIdentity, Reference: entry.referenceID,
			Stage: entry.stage.String(), Bytes: entry.sizeBytes, Reason: entry.reason.String(),
		}
	}
	preimage := struct {
		Contract       string        `json:"contract"`
		Version        int           `json:"version"`
		MaxSourceBytes uint32        `json:"max_source_bytes"`
		MaxSources     int           `json:"max_sources"`
		SelectedBytes  uint32        `json:"selected_bytes"`
		Entries        []entryRecord `json:"entries"`
	}{
		Contract: "open-trestle/review-context-source-selection", Version: 1,
		MaxSourceBytes: selection.limits.MaxSourceBytes(), MaxSources: maxSelectedContextSources,
		SelectedBytes: selection.selectedBytes, Entries: entries,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
