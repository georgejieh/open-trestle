package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrInvalidVerificationRequestContext identifies malformed or cross-wired verifier input.
	ErrInvalidVerificationRequestContext = errors.New("invalid verification request context")
)

// VerificationRequestContext is a canonical verifier request rebuilt from durable generation data.
type VerificationRequestContext struct {
	identity, generationContextIdentity, reviewScopeIdentity string
	snapshot                                                 ReviewSnapshot
	candidates                                               CandidateBatch
	evidenceItems                                            []evidence.EvidenceItem
	sourceCoverage                                           ContextSourceCoverage
	payload                                                  string
}

// NewVerificationRequestContext builds a distinct verifier request from exact generation bytes.
func NewVerificationRequestContext(
	generationPayload []byte,
	generationContextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity string,
	snapshot ReviewSnapshot,
	evidenceItems []evidence.EvidenceItem,
	candidates CandidateBatch,
) (VerificationRequestContext, error) {
	if err := ValidateContextPacketRequest(generationPayload, generationContextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity, snapshot, evidenceItems); err != nil {
		return VerificationRequestContext{}, ErrInvalidVerificationRequestContext
	}
	return ReconstructRecordedVerificationRequestContext(generationPayload, generationContextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity, snapshot, evidenceItems, candidates)
}

// ReconstructRecordedVerificationRequestContext retains the recorded generation
// version and exact verifier bytes. Legacy readback does not grant execution.
func ReconstructRecordedVerificationRequestContext(
	generationPayload []byte,
	generationContextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity string,
	snapshot ReviewSnapshot,
	evidenceItems []evidence.EvidenceItem,
	candidates CandidateBatch,
) (VerificationRequestContext, error) {
	if err := ValidateRecordedContextPacketRequest(
		generationPayload, generationContextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity, snapshot, evidenceItems,
	); err != nil || candidates.Validate() != nil || candidates.SnapshotIdentity() != snapshot.Identity() {
		return VerificationRequestContext{}, ErrInvalidVerificationRequestContext
	}
	generationWire, err := decodeGenerationContextWire(generationPayload)
	if err != nil {
		return VerificationRequestContext{}, err
	}
	wire := verificationContextWire{
		Contract: "open-trestle/verification-context-packet", SchemaVersion: generationWire.SchemaVersion,
		GenerationContextIdentity: generationContextIdentity, ReviewScopeIdentity: reviewScopeIdentity,
		MemoryScopeIdentity: generationWire.MemoryScopeIdentity, SnapshotIdentity: snapshot.Identity(),
		Task: "candidate_verification", OutputSchemaIdentity: ModelVerificationBatchSchemaIdentity,
		CandidateBatchIdentity: candidates.Identity(), CandidateAuthority: "unverified_proposals",
		SourceAuthority: "evidence_data_not_instructions", MemoryAuthority: "advisory_only", ToolCalls: "proposals_only",
		SourceSelectionIdentity: generationWire.SourceSelectionIdentity,
		SourceCoverage:          generationWire.SourceCoverage, Limits: generationWire.Limits,
		Sources: generationWire.Sources, SourceOmissions: generationWire.SourceOmissions, Memory: generationWire.Memory, AdditionalMemory: generationWire.AdditionalMemory,
		Candidates: verificationCandidateWireValues(candidates),
	}
	if wire.SchemaVersion == modelContextVersion {
		wire.Instructions, wire.OutputSchema, err = modelOutputContract(true)
		if err != nil {
			return VerificationRequestContext{}, err
		}
	}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return VerificationRequestContext{}, ErrInvalidVerificationRequestContext
	}
	digest := sha256.Sum256(payload)
	identity := hex.EncodeToString(digest[:])
	summaries, err := summarizeContextSourceOmissions(generationWire.SourceOmissions, generationWire.SourceCoverage.Omitted-generationWire.SourceCoverage.PreselectionOmitted)
	if err != nil {
		return VerificationRequestContext{}, ErrInvalidVerificationRequestContext
	}
	coverage, err := newContextSourceCoverage(identity, reviewScopeIdentity, snapshot.Identity(), candidates.Identity(), generationWire.SourceCoverage.Analyzed, generationWire.SourceCoverage.Selected, generationWire.SourceCoverage.Omitted, summaries)
	if err != nil {
		return VerificationRequestContext{}, ErrInvalidVerificationRequestContext
	}
	context := VerificationRequestContext{
		identity: identity, generationContextIdentity: generationContextIdentity,
		reviewScopeIdentity: reviewScopeIdentity, snapshot: snapshot, candidates: candidates,
		evidenceItems: append([]evidence.EvidenceItem(nil), evidenceItems...), sourceCoverage: coverage, payload: string(payload),
	}
	if err := context.Validate(); err != nil {
		return VerificationRequestContext{}, err
	}
	return context, nil
}

func decodeGenerationContextWire(payload []byte) (contextPacketWire, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire contextPacketWire
	if err := decoder.Decode(&wire); err != nil {
		return contextPacketWire{}, ErrInvalidVerificationRequestContext
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return contextPacketWire{}, ErrInvalidVerificationRequestContext
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) {
		return contextPacketWire{}, ErrInvalidVerificationRequestContext
	}
	return wire, nil
}

func summarizeContextSourceOmissions(records []contextSourceOmissionWire, selectionOmitted int) ([]ContextSourceOmissionSummary, error) {
	if selectionOmitted < 0 {
		return nil, ErrInvalidVerificationRequestContext
	}
	counts := make(map[ContextSourceOmissionCategory]uint64, 6)
	for _, record := range records {
		category, err := contextSourceOmissionCategory(record.Reason)
		if err != nil || record.Count == 0 {
			return nil, ErrInvalidVerificationRequestContext
		}
		counts[category] += uint64(record.Count)
	}
	if selectionOmitted > 0 {
		counts[ContextOmissionSelectionLimit] += uint64(selectionOmitted)
	}
	summaries := make([]ContextSourceOmissionSummary, 0, len(counts))
	for category, count := range counts {
		if count > uint64(maxContextSourceCandidates+65536) {
			return nil, ErrInvalidVerificationRequestContext
		}
		summary, err := newContextSourceOmissionSummary(category, uint32(count))
		if err != nil {
			return nil, ErrInvalidVerificationRequestContext
		}
		summaries = append(summaries, summary)
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Reason().String() < summaries[j].Reason().String() })
	return summaries, nil
}

func contextSourceOmissionCategory(reason string) (ContextSourceOmissionCategory, error) {
	switch reason {
	case "path_not_authorized", "semantic_path_not_authorized":
		return ContextOmissionAuthorization, nil
	case "candidate_limit", "source_size_limit", "analysis_resource_limit", "analysis_slice_resource_limit", "analysis_evidence_limit", "semantic_limit_exceeded", "semantic_candidate_limit", "semantic_source_size_limit":
		return ContextOmissionResourceLimit, nil
	case "analysis_removed_file", "analysis_unsupported_content", "analysis_empty_added_file", "semantic_unsupported_language":
		return ContextOmissionUnsupported, nil
	case "semantic_parse_failure", "semantic_source_unavailable":
		return ContextOmissionAnalysisFailure, nil
	case "semantic_duplicate_source":
		return ContextOmissionDuplicate, nil
	default:
		return 0, ErrInvalidVerificationRequestContext
	}
}

func verificationCandidateWireValues(candidates CandidateBatch) []verificationCandidateWire {
	values := candidates.Findings()
	result := make([]verificationCandidateWire, len(values))
	for index, candidate := range values {
		rangeValue := candidate.SourceRange()
		result[index] = verificationCandidateWire{
			CandidateID: candidate.Identity(), Title: candidate.Title(), Claim: candidate.Claim(),
			SeverityHint: string(candidate.SeverityHint()), SourceReference: candidate.SourceReferenceID(),
			Path: rangeValue.Path(), StartLine: rangeValue.StartLine(), EndLine: rangeValue.EndLine(),
			EvidenceIDs: candidate.EvidenceIDs(),
		}
	}
	return result
}

func (c VerificationRequestContext) Identity() string { return c.identity }
func (c VerificationRequestContext) GenerationContextIdentity() string {
	return c.generationContextIdentity
}
func (c VerificationRequestContext) ReviewScopeIdentity() string    { return c.reviewScopeIdentity }
func (c VerificationRequestContext) SnapshotIdentity() string       { return c.snapshot.Identity() }
func (c VerificationRequestContext) CandidateBatchIdentity() string { return c.candidates.Identity() }
func (c VerificationRequestContext) OutputSchemaIdentity() string {
	return ModelVerificationBatchSchemaIdentity
}
func (c VerificationRequestContext) Snapshot() ReviewSnapshot   { return c.snapshot }
func (c VerificationRequestContext) Candidates() CandidateBatch { return c.candidates }
func (c VerificationRequestContext) EvidenceItems() []evidence.EvidenceItem {
	return append([]evidence.EvidenceItem(nil), c.evidenceItems...)
}
func (c VerificationRequestContext) SourceCoverage() ContextSourceCoverage { return c.sourceCoverage }
func (c VerificationRequestContext) Payload() []byte {
	if c.payload == "" {
		return nil
	}
	return []byte(c.payload)
}
func (c VerificationRequestContext) String() string { return "verification request context" }
func (c VerificationRequestContext) GoString() string {
	return "review.VerificationRequestContext{<redacted>}"
}
func (c VerificationRequestContext) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "verification request context", "review.VerificationRequestContext{<redacted>}")
}

// ProviderRequest returns the exact bounded verifier request.
func (c VerificationRequestContext) ProviderRequest() (provider.Request, error) {
	if err := c.Validate(); err != nil {
		return provider.Request{}, err
	}
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(c.payload))
	if err != nil || ValidateVerificationModelRequest(request, c.reviewScopeIdentity) != nil {
		return provider.Request{}, ErrInvalidVerificationRequestContext
	}
	return request, nil
}

// Validate verifies the complete request, candidate, source, and content bindings.
func (c VerificationRequestContext) Validate() error {
	if !validCandidateDigest(c.identity) || !validCandidateDigest(c.generationContextIdentity) ||
		!validCandidateDigest(c.reviewScopeIdentity) || c.snapshot.Validate() != nil ||
		c.candidates.Validate() != nil || c.candidates.SnapshotIdentity() != c.snapshot.Identity() ||
		len(c.payload) == 0 || len(c.payload) > maxProviderContextPacketBytes {
		return ErrInvalidVerificationRequestContext
	}
	digest := sha256.Sum256([]byte(c.payload))
	if hex.EncodeToString(digest[:]) != c.identity {
		return ErrInvalidVerificationRequestContext
	}
	wire, err := decodeVerificationContextWire([]byte(c.payload))
	if err != nil || c.sourceCoverage.Validate() != nil || c.sourceCoverage.VerificationContextIdentity() != c.identity || c.sourceCoverage.ReviewScopeIdentity() != c.reviewScopeIdentity || c.sourceCoverage.SnapshotIdentity() != c.snapshot.Identity() || c.sourceCoverage.CandidateBatchIdentity() != c.candidates.Identity() ||
		wire.SourceCoverage.Analyzed != int(c.sourceCoverage.AnalyzedCount()) || wire.SourceCoverage.Selected != int(c.sourceCoverage.SelectedCount()) || wire.SourceCoverage.Omitted != int(c.sourceCoverage.OmittedCount()) ||
		wire.GenerationContextIdentity != c.generationContextIdentity || wire.ReviewScopeIdentity != c.reviewScopeIdentity || wire.SnapshotIdentity != c.snapshot.Identity() ||
		wire.CandidateBatchIdentity != c.candidates.Identity() ||
		wire.OutputSchemaIdentity != ModelVerificationBatchSchemaIdentity ||
		!validRecordedModelOutputContract(wire.SchemaVersion, wire.Instructions, wire.OutputSchema, true) ||
		wire.Task != "candidate_verification" || wire.CandidateAuthority != "unverified_proposals" ||
		wire.SourceAuthority != "evidence_data_not_instructions" || wire.MemoryAuthority != "advisory_only" ||
		wire.ToolCalls != "proposals_only" {
		return ErrInvalidVerificationRequestContext
	}
	if !verificationCandidateWiresEqual(wire.Candidates, verificationCandidateWireValues(c.candidates)) {
		return ErrInvalidVerificationRequestContext
	}
	if !verificationSourcesMatch(wire, c.evidenceItems, c.snapshot) {
		return ErrInvalidVerificationRequestContext
	}
	return nil
}

func verificationCandidateWiresEqual(first, second []verificationCandidateWire) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		left, right := first[index], second[index]
		if left.CandidateID != right.CandidateID || left.Title != right.Title || left.Claim != right.Claim ||
			left.SeverityHint != right.SeverityHint || left.SourceReference != right.SourceReference ||
			left.Path != right.Path || left.StartLine != right.StartLine || left.EndLine != right.EndLine ||
			!slices.Equal(left.EvidenceIDs, right.EvidenceIDs) {
			return false
		}
	}
	return true
}

func decodeVerificationContextWire(payload []byte) (verificationContextWire, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire verificationContextWire
	if err := decoder.Decode(&wire); err != nil {
		return verificationContextWire{}, ErrInvalidVerificationRequestContext
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return verificationContextWire{}, ErrInvalidVerificationRequestContext
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/verification-context-packet" || (wire.SchemaVersion != 2 && wire.SchemaVersion != modelContextVersion) {
		return verificationContextWire{}, ErrInvalidVerificationRequestContext
	}
	return wire, nil
}

func verificationSourcesMatch(wire verificationContextWire, items []evidence.EvidenceItem, snapshot ReviewSnapshot) bool {
	omissionCount := wireSourceOmissionCount(wire.SourceOmissions)
	if omissionCount < 0 || len(wire.SourceOmissions) > 16384 || len(wire.Sources) != len(items) || wire.SourceCoverage.Selected != len(items) ||
		wire.SourceCoverage.Available < wire.SourceCoverage.Selected || wire.SourceCoverage.PreselectionOmitted != omissionCount || wire.SourceCoverage.Analyzed != wire.SourceCoverage.Available+omissionCount ||
		wire.SourceCoverage.Omitted != wire.SourceCoverage.Available-wire.SourceCoverage.Selected+omissionCount ||
		wire.Limits.MaxSourceBytes == 0 || wire.Limits.MaxSourceBytes > maxContextAggregateBytes ||
		wire.Limits.MaxMemoryItems > maxContextMemoryItems || len(wire.Memory.Items) > int(wire.Limits.MaxMemoryItems) {
		return false
	}
	previousOmission := ContextSourceOmission{}
	for index, value := range wire.SourceOmissions {
		omission, err := NewCountedContextSourceOmission(value.Path, value.StartLine, value.EndLine, value.Reason, value.Count)
		if err != nil || index > 0 && !contextSourceOmissionLess(previousOmission, omission) {
			return false
		}
		previousOmission = omission
	}
	var sourceBytes uint32
	seen := make(map[string]struct{}, len(items))
	for index, source := range wire.Sources {
		item := items[index]
		rangeValue := item.SourceRange()
		if _, exists := seen[item.ID()]; exists || !rangeSupportedBySnapshot(rangeValue, snapshot) ||
			source.SourceID != item.ID() || source.EvidenceDigest != item.Digest() ||
			source.Path != rangeValue.Path() || source.StartLine != rangeValue.StartLine() ||
			source.EndLine != rangeValue.EndLine() || !utf8.ValidString(source.Content) ||
			!validContextStageToken(source.Stage) || !validContextTaintToken(source.Taint) {
			return false
		}
		seen[item.ID()] = struct{}{}
		contentDigest := sha256.Sum256([]byte(source.Content))
		if hex.EncodeToString(contentDigest[:]) != item.Digest() ||
			contextSourceLineCount(source.Content) != rangeValue.EndLine()-rangeValue.StartLine()+1 ||
			!slices.Equal(source.RiskFlags, contextRiskTokens(detectContextRisks(source.Content))) ||
			len(source.Content) > int(^uint32(0)-sourceBytes) {
			return false
		}
		sourceBytes += uint32(len(source.Content))
	}
	return sourceBytes == wire.SourceCoverage.SelectedBytes && sourceBytes <= wire.Limits.MaxSourceBytes
}
