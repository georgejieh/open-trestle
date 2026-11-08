package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	maxCandidateFindings       = 16
	maxCandidateEvidenceSet    = 2_048
	maxCandidateEvidence       = 4
	maxCandidateTitleRunes     = 128
	maxCandidateClaimRunes     = 1_024
	maxCandidateReferenceBytes = 64
	maxCandidateSourceLine     = 1_000_000
	maxCandidateFixBytes       = 1_024
	// maxCandidateFixRunes is the schema's maxLength, counted in characters.
	// Four UTF-8 bytes per character at most keeps it within the byte bound.
	maxCandidateFixRunes = maxCandidateFixBytes / 4
)

// CandidateCategory is the closed advisory defect category of a
// model-candidate-batch-v2 proposal. It does not affect verification or final
// severity. The zero value means a v1 candidate without a category.
type CandidateCategory string

const (
	CandidateCategoryCorrectness     CandidateCategory = "correctness"
	CandidateCategorySecurity        CandidateCategory = "security"
	CandidateCategoryConcurrency     CandidateCategory = "concurrency"
	CandidateCategoryPerformance     CandidateCategory = "performance"
	CandidateCategoryReliability     CandidateCategory = "reliability"
	CandidateCategoryMaintainability CandidateCategory = "maintainability"
	CandidateCategoryStyle           CandidateCategory = "style"
	CandidateCategoryDocumentation   CandidateCategory = "documentation"
	CandidateCategoryTesting         CandidateCategory = "testing"
)

func (c CandidateCategory) String() string { return string(c) }

// Validate accepts only one of the closed category values.
func (c CandidateCategory) Validate() error {
	switch c {
	case CandidateCategoryCorrectness, CandidateCategorySecurity, CandidateCategoryConcurrency,
		CandidateCategoryPerformance, CandidateCategoryReliability, CandidateCategoryMaintainability,
		CandidateCategoryStyle, CandidateCategoryDocumentation, CandidateCategoryTesting:
		return nil
	default:
		return ErrInvalidCandidateCategory
	}
}

var (
	// ErrInvalidCandidateResponseEnvelope identifies a non-structured, incomplete, or multipart model result.
	ErrInvalidCandidateResponseEnvelope = errors.New("invalid candidate response envelope")
	// ErrInvalidCandidateDocumentJSON identifies malformed candidate JSON.
	ErrInvalidCandidateDocumentJSON = errors.New("invalid candidate document JSON")
	// ErrDuplicateCandidateDocumentKey identifies ambiguous duplicate object keys.
	ErrDuplicateCandidateDocumentKey = errors.New("duplicate candidate document key")
	// ErrInvalidCandidateDocumentShape identifies missing, unknown, or noncanonical fields.
	ErrInvalidCandidateDocumentShape = errors.New("invalid candidate document shape")
	// ErrInvalidCandidateSchemaVersion identifies an unsupported candidate schema.
	ErrInvalidCandidateSchemaVersion = errors.New("invalid candidate schema version")
	// ErrTooManyCandidateFindings identifies output beyond the finding-count bound.
	ErrTooManyCandidateFindings = errors.New("too many candidate findings")
	// ErrInvalidCandidateText identifies empty, excessive, or schema-incompatible text.
	ErrInvalidCandidateText = errors.New("invalid candidate text")
	// ErrInvalidCandidateSeverity identifies an unknown advisory severity.
	ErrInvalidCandidateSeverity = errors.New("invalid candidate severity")
	// ErrInvalidCandidateEvidenceSet identifies an excessive or malformed evidence allowlist.
	ErrInvalidCandidateEvidenceSet = errors.New("invalid candidate evidence set")
	// ErrInvalidCandidateReference identifies a malformed host-issued source or evidence reference.
	ErrInvalidCandidateReference = errors.New("invalid candidate reference")
	// ErrDuplicateCandidateEvidence identifies repeated or noncanonical evidence references.
	ErrDuplicateCandidateEvidence = errors.New("duplicate candidate evidence")
	// ErrCandidateEvidenceNotAllowed identifies a model-cited reference outside the supplied allowlist.
	ErrCandidateEvidenceNotAllowed = errors.New("candidate evidence not allowed")
	// ErrCandidateRangeNotSupported identifies a location outside the source reference or immutable snapshot.
	ErrCandidateRangeNotSupported = errors.New("candidate range not supported by snapshot")
	// ErrCandidateEvidenceRangeMismatch identifies a location not covered by any cited evidence item.
	ErrCandidateEvidenceRangeMismatch = errors.New("candidate range not supported by cited evidence")
	// ErrDuplicateCandidateFinding identifies a repeated semantic proposal.
	ErrDuplicateCandidateFinding = errors.New("duplicate candidate finding")
	// ErrInvalidCandidateCategory identifies a missing or unknown v2 candidate category.
	ErrInvalidCandidateCategory = errors.New("invalid candidate category")
	// ErrInvalidCandidateFix identifies empty, excessive, or schema-incompatible fix guidance.
	ErrInvalidCandidateFix = errors.New("invalid candidate fix guidance")
	// ErrInvalidCandidateFindingIdentity identifies finding content inconsistent with its identity.
	ErrInvalidCandidateFindingIdentity = errors.New("invalid candidate finding identity")
	// ErrInvalidCandidateBatchIdentity identifies batch content inconsistent with its identity.
	ErrInvalidCandidateBatchIdentity = errors.New("invalid candidate batch identity")
)

type candidateEvidenceBinding struct {
	identity    string
	digest      string
	sourceRange evidence.SourceRange
}

// CandidateFinding is an unverified, evidence-bound model proposal.
type CandidateFinding struct {
	identity          string
	responseIdentity  string
	snapshotIdentity  string
	ordinal           uint8
	title             string
	claim             string
	severityHint      Severity
	sourceReferenceID string
	sourceRange       evidence.SourceRange
	evidenceBindings  []candidateEvidenceBinding
	category          CandidateCategory
	fix               string
}

func (f CandidateFinding) Identity() string                  { return f.identity }
func (f CandidateFinding) Ordinal() uint8                    { return f.ordinal }
func (f CandidateFinding) Title() string                     { return f.title }
func (f CandidateFinding) Claim() string                     { return f.claim }
func (f CandidateFinding) SeverityHint() Severity            { return f.severityHint }
func (f CandidateFinding) SourceReferenceID() string         { return f.sourceReferenceID }
func (f CandidateFinding) SourceRange() evidence.SourceRange { return f.sourceRange }

// Category returns the advisory v2 category, or the zero value for a v1 candidate.
func (f CandidateFinding) Category() CandidateCategory { return f.category }

// Fix returns optional untrusted plain-text fix guidance. It is never verified
// or applied; the empty string means no guidance.
func (f CandidateFinding) Fix() string { return f.fix }
func (f CandidateFinding) EvidenceIDs() []string {
	identities := make([]string, len(f.evidenceBindings))
	for index, binding := range f.evidenceBindings {
		identities[index] = binding.identity
	}
	return identities
}
func (f CandidateFinding) String() string   { return "candidate finding" }
func (f CandidateFinding) GoString() string { return "review.CandidateFinding{<redacted>}" }
func (f CandidateFinding) Format(state fmt.State, verb rune) {
	formatted := "candidate finding"
	if verb == 'q' {
		formatted = `"candidate finding"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "review.CandidateFinding{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies candidate bounds, evidence bindings, and content identity.
func (f CandidateFinding) Validate() error {
	if !validCandidateDigest(f.responseIdentity) || !validCandidateDigest(f.snapshotIdentity) || f.ordinal == 0 || f.ordinal > maxCandidateFindings {
		return ErrInvalidCandidateFindingIdentity
	}
	if !validCandidateTitle(f.title) || !validCandidateClaim(f.claim) {
		return ErrInvalidCandidateText
	}
	if !isKnownSeverity(f.severityHint) {
		return ErrInvalidCandidateSeverity
	}
	if err := validateCandidateGuidance(f.category, f.fix); err != nil {
		return err
	}
	if !validCandidateReference(f.sourceReferenceID) {
		return ErrInvalidCandidateReference
	}
	if !validCandidateSourceRange(f.sourceRange) {
		return ErrCandidateRangeNotSupported
	}
	if len(f.evidenceBindings) == 0 || len(f.evidenceBindings) > maxCandidateEvidence {
		return ErrInvalidCandidateEvidenceSet
	}
	previous := ""
	citedRange := false
	for _, binding := range f.evidenceBindings {
		if !validCandidateReference(binding.identity) || !validCandidateDigest(binding.digest) || !validCandidateSourceRange(binding.sourceRange) {
			return ErrInvalidCandidateEvidenceSet
		}
		if previous != "" && binding.identity <= previous {
			return ErrDuplicateCandidateEvidence
		}
		citedRange = citedRange || rangeContains(binding.sourceRange, f.sourceRange)
		previous = binding.identity
	}
	if !citedRange {
		return ErrCandidateEvidenceRangeMismatch
	}
	if f.identity != deriveCandidateFindingIdentity(f) {
		return ErrInvalidCandidateFindingIdentity
	}
	return nil
}

// CandidateBatch is one strictly decoded set of unverified model proposals.
type CandidateBatch struct {
	identity         string
	responseIdentity string
	snapshotIdentity string
	findings         []CandidateFinding
	// categorized marks a model-candidate-batch-v2 batch: every finding carries a category.
	categorized bool
	// repositoryContextOmitted counts v2 proposals dropped at admission because
	// their source_range named a repository_context source. It is derived only
	// from the exact response and context bytes and is bound into the identity.
	repositoryContextOmitted uint8
}

// RepositoryContextAnchorOmittedCount reports proposals dropped because they
// were located in a repository_context source rather than reviewed code.
func (b CandidateBatch) RepositoryContextAnchorOmittedCount() int {
	return int(b.repositoryContextOmitted)
}

func (b CandidateBatch) Identity() string { return b.identity }

// SchemaVersion returns the model candidate batch schema the batch was admitted under: 1 or 2.
func (b CandidateBatch) SchemaVersion() int {
	if b.categorized {
		return 2
	}
	return 1
}
func (b CandidateBatch) ResponseIdentity() string { return b.responseIdentity }
func (b CandidateBatch) SnapshotIdentity() string { return b.snapshotIdentity }
func (b CandidateBatch) Findings() []CandidateFinding {
	return append([]CandidateFinding(nil), b.findings...)
}
func (b CandidateBatch) String() string   { return "candidate finding batch" }
func (b CandidateBatch) GoString() string { return "review.CandidateBatch{<redacted>}" }
func (b CandidateBatch) Format(state fmt.State, verb rune) {
	formatted := "candidate finding batch"
	if verb == 'q' {
		formatted = `"candidate finding batch"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "review.CandidateBatch{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies all candidate bindings, ordering, uniqueness, and identity.
func (b CandidateBatch) Validate() error {
	if !validCandidateDigest(b.responseIdentity) || !validCandidateDigest(b.snapshotIdentity) || len(b.findings)+int(b.repositoryContextOmitted) > maxCandidateFindings || b.repositoryContextOmitted > 0 && !b.categorized {
		return ErrInvalidCandidateBatchIdentity
	}
	seen := make(map[string]struct{}, len(b.findings))
	for index, finding := range b.findings {
		if err := finding.Validate(); err != nil {
			return err
		}
		if finding.ordinal != uint8(index+1) || finding.responseIdentity != b.responseIdentity || finding.snapshotIdentity != b.snapshotIdentity || (finding.category != "") != b.categorized {
			return ErrInvalidCandidateBatchIdentity
		}
		fingerprint := deriveCandidateContentFingerprint(finding)
		if _, exists := seen[fingerprint]; exists {
			return ErrDuplicateCandidateFinding
		}
		seen[fingerprint] = struct{}{}
	}
	if b.identity != deriveCandidateBatchIdentity(b) {
		return ErrInvalidCandidateBatchIdentity
	}
	return nil
}

type candidateDocument struct {
	SchemaVersion int                        `json:"schema_version"`
	Candidates    []candidateFindingDocument `json:"candidates"`
}

type candidateFindingDocument struct {
	Title        string                       `json:"title"`
	Claim        string                       `json:"claim"`
	Category     string                       `json:"category,omitempty"`
	Fix          string                       `json:"fix,omitempty"`
	SeverityHint string                       `json:"severity_hint"`
	SourceRange  candidateSourceRangeDocument `json:"source_range"`
	EvidenceIDs  []string                     `json:"evidence_ids"`
}

type candidateSourceRangeDocument struct {
	SourceID  string `json:"source_id"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// ValidateCandidateDocumentSyntax enforces the public model-candidate-batch-v1 schema syntax.
// It does not establish source, evidence, or factual authority.
func ValidateCandidateDocumentSyntax(payload []byte) error {
	return validateCandidateDocumentSyntax(payload, 1)
}

// ValidateCandidateDocumentV2Syntax enforces the public model-candidate-batch-v2
// schema syntax: a required closed category and optional bounded fix guidance.
// It does not establish source, evidence, factual, category, or fix authority.
func ValidateCandidateDocumentV2Syntax(payload []byte) error {
	return validateCandidateDocumentSyntax(payload, 2)
}

func validateCandidateDocumentSyntax(payload []byte, version int) error {
	if err := rejectDuplicateCandidateJSONKeys(payload); err != nil {
		return err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return ErrInvalidCandidateDocumentJSON
	}
	if !exactJSONKeys(root, "schema_version", "candidates") || firstNonSpace(root["candidates"]) != '[' {
		return ErrInvalidCandidateDocumentShape
	}
	var rawCandidates []json.RawMessage
	if err := json.Unmarshal(root["candidates"], &rawCandidates); err != nil {
		return ErrInvalidCandidateDocumentShape
	}
	if len(rawCandidates) > maxCandidateFindings {
		return ErrTooManyCandidateFindings
	}
	for _, encoded := range rawCandidates {
		var candidate map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &candidate); err != nil || !exactCandidateDocumentKeys(candidate, version) || firstNonSpace(candidate["source_range"]) != '{' || firstNonSpace(candidate["evidence_ids"]) != '[' {
			return ErrInvalidCandidateDocumentShape
		}
		var sourceRange map[string]json.RawMessage
		if err := json.Unmarshal(candidate["source_range"], &sourceRange); err != nil || !exactJSONKeys(sourceRange, "source_id", "start_line", "end_line") {
			return ErrInvalidCandidateDocumentShape
		}
		// A present fix must be nonblank; absence is the only way to give no guidance.
		if raw, present := candidate["fix"]; present {
			var fix string
			if json.Unmarshal(raw, &fix) != nil || !validCandidateFix(fix) {
				return ErrInvalidCandidateFix
			}
		}
	}
	var document candidateDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCandidateDocumentJSON, err)
	}
	if document.SchemaVersion != version {
		return ErrInvalidCandidateSchemaVersion
	}
	for _, candidate := range document.Candidates {
		if !validCandidateTitle(candidate.Title) || !validCandidateClaim(candidate.Claim) {
			return ErrInvalidCandidateText
		}
		if version == 2 {
			if err := CandidateCategory(candidate.Category).Validate(); err != nil {
				return err
			}
			if err := validateCandidateGuidance(CandidateCategory(candidate.Category), candidate.Fix); err != nil {
				return err
			}
		}
		if !isKnownSeverity(Severity(candidate.SeverityHint)) {
			return ErrInvalidCandidateSeverity
		}
		if !validCandidateReference(candidate.SourceRange.SourceID) || candidate.SourceRange.StartLine < 1 || candidate.SourceRange.StartLine > maxCandidateSourceLine || candidate.SourceRange.EndLine < 1 || candidate.SourceRange.EndLine > maxCandidateSourceLine {
			return ErrInvalidCandidateReference
		}
		if len(candidate.EvidenceIDs) == 0 || len(candidate.EvidenceIDs) > maxCandidateEvidence {
			return ErrInvalidCandidateEvidenceSet
		}
		seen := make(map[string]struct{}, len(candidate.EvidenceIDs))
		for _, identity := range candidate.EvidenceIDs {
			if !validCandidateReference(identity) {
				return ErrInvalidCandidateReference
			}
			if _, exists := seen[identity]; exists {
				return ErrDuplicateCandidateEvidence
			}
			seen[identity] = struct{}{}
		}
	}
	return nil
}

// exactCandidateDocumentKeys requires the exact v1 candidate keys, or for v2 the
// v1 keys plus a string category and an optional string fix.
func exactCandidateDocumentKeys(candidate map[string]json.RawMessage, version int) bool {
	if version == 1 {
		return exactJSONKeys(candidate, "title", "claim", "severity_hint", "source_range", "evidence_ids")
	}
	keys := []string{"title", "claim", "category", "severity_hint", "source_range", "evidence_ids"}
	if fix, present := candidate["fix"]; present {
		if firstNonSpace(fix) != '"' {
			return false
		}
		keys = append(keys, "fix")
	}
	return exactJSONKeys(candidate, keys...) && firstNonSpace(candidate["category"]) == '"'
}

// validateCandidateGuidance checks a category and its optional fix guidance. A
// v1 candidate has neither; fix guidance never appears without a category.
func validateCandidateGuidance(category CandidateCategory, fix string) error {
	if category == "" {
		if fix != "" {
			return ErrInvalidCandidateFix
		}
		return nil
	}
	if err := category.Validate(); err != nil {
		return err
	}
	if fix != "" && !validCandidateFix(fix) {
		return ErrInvalidCandidateFix
	}
	return nil
}

func validCandidateFix(value string) bool {
	return len(value) <= maxCandidateFixBytes && validCandidateFreeText(value, maxCandidateFixRunes)
}

// candidateBatchMatchesContextVersion reports whether a candidate batch can be the
// output of a generation context version. A categorized v2 batch requires a
// version 7 context. An uncategorized v1 batch is accepted for every version so
// that recorded readback and investigation projections keep their v1 candidates.
func candidateBatchMatchesContextVersion(version int, batch CandidateBatch) bool {
	return !batch.categorized || version == modelGenerationContextVersion
}

// CandidateBatchMatchesContext reports whether a batch is exactly the candidate
// schema the recorded generation context requested: v2 for a version 7 context
// and v1 for every earlier generation context.
func CandidateBatchMatchesContext(contextPayload []byte, batch CandidateBatch) bool {
	var header struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
	}
	if len(contextPayload) == 0 || len(contextPayload) > maxProviderContextPacketBytes || json.Unmarshal(contextPayload, &header) != nil || header.Contract != "open-trestle/review-context-packet" {
		return false
	}
	return batch.categorized == (header.SchemaVersion == modelGenerationContextVersion)
}

// ParseCandidateBatch strictly decodes one model-candidate-batch-v1 response
// against exact snapshot evidence. New generation contexts request v2; use
// ParseContextCandidateBatch for their responses.
func ParseCandidateBatch(response provider.Response, snapshot ReviewSnapshot, evidenceItems []evidence.EvidenceItem) (CandidateBatch, error) {
	return parseCandidateBatch(response, snapshot, evidenceItems, 1, nil)
}

// ParseContextCandidateBatch strictly decodes one response against the output
// contract of the exact generation context bytes it answers. A version 7 context
// requires model-candidate-batch-v2 and drops, and counts, each candidate whose
// source_range names a repository_context source: repository instruction files
// are advisory preferences, not reviewed code, and changed instruction lines are
// a separate changed_hunk source. Earlier versions require v1.
func ParseContextCandidateBatch(response provider.Response, contextPayload []byte, snapshot ReviewSnapshot, evidenceItems []evidence.EvidenceItem) (CandidateBatch, error) {
	if len(contextPayload) == 0 || len(contextPayload) > maxProviderContextPacketBytes {
		return CandidateBatch{}, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(contextPayload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" || !validRecordedModelOutputContract(wire.SchemaVersion, wire.Instructions, wire.InstructionsIdentity, wire.OutputSchema, false) {
		return CandidateBatch{}, ErrInvalidContextPacketRequest
	}
	if wire.SchemaVersion != modelGenerationContextVersion {
		return ParseCandidateBatch(response, snapshot, evidenceItems)
	}
	if len(wire.Sources) != len(evidenceItems) {
		return CandidateBatch{}, ErrInvalidCandidateEvidenceSet
	}
	repositoryContext := make(map[string]struct{})
	for index, source := range wire.Sources {
		if source.SourceID != evidenceItems[index].ID() {
			return CandidateBatch{}, ErrInvalidCandidateEvidenceSet
		}
		if source.Stage == ContextStageRepositoryContext.String() {
			repositoryContext[source.SourceID] = struct{}{}
		}
	}
	return parseCandidateBatch(response, snapshot, evidenceItems, 2, repositoryContext)
}

func parseCandidateBatch(response provider.Response, snapshot ReviewSnapshot, evidenceItems []evidence.EvidenceItem, version int, repositoryContext map[string]struct{}) (CandidateBatch, error) {
	if err := response.Validate(); err != nil {
		return CandidateBatch{}, err
	}
	parts := response.Parts()
	if response.Capability() != provider.CapabilityReviewV1 || response.FinishReason() != provider.ResponseFinishStop || len(parts) != 1 || parts[0].Kind() != provider.ResponsePartStructuredData {
		return CandidateBatch{}, ErrInvalidCandidateResponseEnvelope
	}
	if err := snapshot.Validate(); err != nil {
		return CandidateBatch{}, err
	}
	allowedEvidence, err := validateCandidateEvidenceSet(evidenceItems)
	if err != nil {
		return CandidateBatch{}, err
	}
	payload := parts[0].Payload()
	if err := validateCandidateDocumentSyntax(payload, version); err != nil {
		return CandidateBatch{}, err
	}
	var document candidateDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return CandidateBatch{}, ErrInvalidCandidateDocumentJSON
	}
	findings := make([]CandidateFinding, 0, len(document.Candidates))
	seen := make(map[string]struct{}, len(document.Candidates))
	omitted := uint8(0)
	for _, candidate := range document.Candidates {
		if _, anchored := repositoryContext[candidate.SourceRange.SourceID]; anchored {
			// A proposal located in repository instruction context is not about
			// reviewed code. Drop only that proposal, deterministically, and keep
			// the rest; kept proposals take contiguous ordinals.
			omitted++
			continue
		}
		finding, err := newCandidateFinding(response.Identity(), snapshot, uint8(len(findings)+1), candidate, allowedEvidence)
		if err != nil {
			return CandidateBatch{}, err
		}
		fingerprint := deriveCandidateContentFingerprint(finding)
		if _, exists := seen[fingerprint]; exists {
			return CandidateBatch{}, ErrDuplicateCandidateFinding
		}
		seen[fingerprint] = struct{}{}
		findings = append(findings, finding)
	}
	if len(findings) == 0 {
		findings = nil
	}
	batch := CandidateBatch{responseIdentity: response.Identity(), snapshotIdentity: snapshot.Identity(), findings: findings, categorized: version == 2, repositoryContextOmitted: omitted}
	batch.identity = deriveCandidateBatchIdentity(batch)
	if err := batch.Validate(); err != nil {
		return CandidateBatch{}, err
	}
	return batch, nil
}

func newCandidateFinding(responseIdentity string, snapshot ReviewSnapshot, ordinal uint8, document candidateFindingDocument, allowed map[string]evidence.EvidenceItem) (CandidateFinding, error) {
	sourceItem, exists := allowed[document.SourceRange.SourceID]
	if !exists {
		return CandidateFinding{}, ErrCandidateEvidenceNotAllowed
	}
	sourceRange, err := evidence.NewSourceRange(sourceItem.SourceRange().Path(), document.SourceRange.StartLine, document.SourceRange.EndLine)
	if err != nil || !validCandidateSourceRange(sourceRange) || !rangeContains(sourceItem.SourceRange(), sourceRange) || !rangeSupportedBySnapshot(sourceRange, snapshot) {
		return CandidateFinding{}, ErrCandidateRangeNotSupported
	}
	bindings := make([]candidateEvidenceBinding, 0, len(document.EvidenceIDs))
	citedRange := false
	for _, identity := range document.EvidenceIDs {
		item, exists := allowed[identity]
		if !exists {
			return CandidateFinding{}, ErrCandidateEvidenceNotAllowed
		}
		bindings = append(bindings, candidateEvidenceBinding{identity: item.ID(), digest: item.Digest(), sourceRange: item.SourceRange()})
		citedRange = citedRange || rangeContains(item.SourceRange(), sourceRange)
	}
	if !citedRange {
		return CandidateFinding{}, ErrCandidateEvidenceRangeMismatch
	}
	sort.Slice(bindings, func(left, right int) bool { return bindings[left].identity < bindings[right].identity })
	finding := CandidateFinding{
		responseIdentity: responseIdentity, snapshotIdentity: snapshot.Identity(), ordinal: ordinal,
		title: document.Title, claim: document.Claim, severityHint: Severity(document.SeverityHint),
		sourceReferenceID: document.SourceRange.SourceID, sourceRange: sourceRange, evidenceBindings: bindings,
		category: CandidateCategory(document.Category), fix: document.Fix,
	}
	finding.identity = deriveCandidateFindingIdentity(finding)
	return finding, nil
}

func validateCandidateEvidenceSet(items []evidence.EvidenceItem) (map[string]evidence.EvidenceItem, error) {
	if len(items) > maxCandidateEvidenceSet {
		return nil, ErrInvalidCandidateEvidenceSet
	}
	allowed := make(map[string]evidence.EvidenceItem, len(items))
	for _, item := range items {
		if !validCandidateReference(item.ID()) || !validCandidateDigest(item.Digest()) || !validCandidateSourceRange(item.SourceRange()) {
			return nil, ErrInvalidCandidateEvidenceSet
		}
		if _, err := evidence.NewEvidenceItem(item.ID(), item.Kind(), item.Digest(), item.SourceRange()); err != nil {
			return nil, ErrInvalidCandidateEvidenceSet
		}
		if _, exists := allowed[item.ID()]; exists {
			return nil, ErrDuplicateCandidateEvidence
		}
		allowed[item.ID()] = item
	}
	return allowed, nil
}

func rangeSupportedBySnapshot(candidate evidence.SourceRange, snapshot ReviewSnapshot) bool {
	for _, supported := range snapshot.Ranges() {
		if rangeContains(supported, candidate) {
			return true
		}
	}
	return false
}

func rangeContains(container, candidate evidence.SourceRange) bool {
	return container.Path() == candidate.Path() && container.StartLine() <= candidate.StartLine() && container.EndLine() >= candidate.EndLine()
}

func validCandidateSourceRange(sourceRange evidence.SourceRange) bool {
	return sourceRange.StartLine() >= 1 && sourceRange.EndLine() >= sourceRange.StartLine() && sourceRange.EndLine() <= maxCandidateSourceLine
}

func validCandidateTitle(value string) bool {
	return validCandidateFreeText(value, maxCandidateTitleRunes) && !strings.ContainsAny(value, "\r\n")
}

func validCandidateClaim(value string) bool {
	return validCandidateFreeText(value, maxCandidateClaimRunes)
}

func validCandidateFreeText(value string, maxRunes int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	hasVisibleText := false
	for _, character := range value {
		if unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) || character == unicode.ReplacementChar {
			return false
		}
		if unicode.IsControl(character) {
			switch character {
			case '\t', '\n', '\r':
				continue
			default:
				return false
			}
		}
		if !unicode.IsSpace(character) {
			hasVisibleText = true
		}
	}
	return hasVisibleText
}

func validCandidateReference(value string) bool {
	if len(value) == 0 || len(value) > maxCandidateReferenceBytes || !isCandidateAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if isCandidateAlphaNumeric(character) || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func isCandidateAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func validCandidateDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func exactJSONKeys(values map[string]json.RawMessage, keys ...string) bool {
	if len(values) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := values[key]; !exists {
			return false
		}
	}
	return true
}

func firstNonSpace(value []byte) byte {
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) == 0 {
		return 0
	}
	return trimmed[0]
}

func rejectDuplicateCandidateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumeCandidateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidCandidateDocumentJSON
	}
	return nil
}

func consumeCandidateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidCandidateDocumentJSON
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInvalidCandidateDocumentJSON
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidCandidateDocumentJSON
			}
			if _, exists := seen[key]; exists {
				return ErrDuplicateCandidateDocumentKey
			}
			seen[key] = struct{}{}
			if err := consumeCandidateJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := consumeCandidateJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidCandidateDocumentJSON
	}
	closing, err := decoder.Token()
	if err != nil {
		return ErrInvalidCandidateDocumentJSON
	}
	if closeDelimiter, ok := closing.(json.Delim); !ok || delimiter == '{' && closeDelimiter != '}' || delimiter == '[' && closeDelimiter != ']' {
		return ErrInvalidCandidateDocumentJSON
	}
	return nil
}

func deriveCandidateFindingIdentity(finding CandidateFinding) string {
	type bindingRecord struct {
		Identity string `json:"identity"`
		Digest   string `json:"digest"`
		Path     string `json:"path"`
		Start    int    `json:"start"`
		End      int    `json:"end"`
	}
	bindings := make([]bindingRecord, len(finding.evidenceBindings))
	for index, binding := range finding.evidenceBindings {
		bindings[index] = bindingRecord{
			Identity: binding.identity, Digest: binding.digest, Path: binding.sourceRange.Path(),
			Start: binding.sourceRange.StartLine(), End: binding.sourceRange.EndLine(),
		}
	}
	type findingRecord struct {
		Contract        string          `json:"contract"`
		Version         int             `json:"version"`
		Response        string          `json:"response"`
		Snapshot        string          `json:"snapshot"`
		Ordinal         uint8           `json:"ordinal"`
		Title           string          `json:"title"`
		Claim           string          `json:"claim"`
		SeverityHint    string          `json:"severity_hint"`
		SourceReference string          `json:"source_reference"`
		Path            string          `json:"path"`
		Start           int             `json:"start"`
		End             int             `json:"end"`
		Evidence        []bindingRecord `json:"evidence"`
	}
	preimage := findingRecord{
		Contract: "open-trestle/candidate-finding", Version: 1,
		Response: finding.responseIdentity, Snapshot: finding.snapshotIdentity, Ordinal: finding.ordinal,
		Title: finding.title, Claim: finding.claim, SeverityHint: string(finding.severityHint),
		SourceReference: finding.sourceReferenceID, Path: finding.sourceRange.Path(),
		Start: finding.sourceRange.StartLine(), End: finding.sourceRange.EndLine(), Evidence: bindings,
	}
	var encoded []byte
	if finding.category == "" {
		// A v1 candidate keeps its historical preimage exactly.
		encoded, _ = json.Marshal(preimage)
	} else {
		preimage.Version = 2
		encoded, _ = json.Marshal(struct {
			findingRecord
			Category string `json:"category"`
			Fix      string `json:"fix"`
		}{preimage, string(finding.category), finding.fix})
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveCandidateContentFingerprint(finding CandidateFinding) string {
	preimage := struct {
		Title        string   `json:"title"`
		Claim        string   `json:"claim"`
		SeverityHint string   `json:"severity_hint"`
		Path         string   `json:"path"`
		Start        int      `json:"start"`
		End          int      `json:"end"`
		Evidence     []string `json:"evidence"`
	}{
		Title: finding.title, Claim: finding.claim, SeverityHint: string(finding.severityHint),
		Path: finding.sourceRange.Path(), Start: finding.sourceRange.StartLine(),
		End: finding.sourceRange.EndLine(), Evidence: finding.EvidenceIDs(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveCandidateBatchIdentity(batch CandidateBatch) string {
	findingIdentities := make([]string, len(batch.findings))
	for index, finding := range batch.findings {
		findingIdentities[index] = finding.Identity()
	}
	preimage := struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Response string   `json:"response"`
		Snapshot string   `json:"snapshot"`
		Findings []string `json:"findings"`
		// Omitted only when nonzero, so batches without dropped proposals keep
		// their identities.
		RepositoryContextOmitted uint8 `json:"repository_context_anchor_omitted,omitempty"`
	}{
		Contract: "open-trestle/candidate-batch", Version: batch.SchemaVersion(),
		Response: batch.responseIdentity, Snapshot: batch.snapshotIdentity, Findings: findingIdentities,
		RepositoryContextOmitted: batch.repositoryContextOmitted,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
