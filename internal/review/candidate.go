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
)

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
}

func (f CandidateFinding) Identity() string                  { return f.identity }
func (f CandidateFinding) Ordinal() uint8                    { return f.ordinal }
func (f CandidateFinding) Title() string                     { return f.title }
func (f CandidateFinding) Claim() string                     { return f.claim }
func (f CandidateFinding) SeverityHint() Severity            { return f.severityHint }
func (f CandidateFinding) SourceReferenceID() string         { return f.sourceReferenceID }
func (f CandidateFinding) SourceRange() evidence.SourceRange { return f.sourceRange }
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
}

func (b CandidateBatch) Identity() string         { return b.identity }
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
	if !validCandidateDigest(b.responseIdentity) || !validCandidateDigest(b.snapshotIdentity) || len(b.findings) > maxCandidateFindings {
		return ErrInvalidCandidateBatchIdentity
	}
	seen := make(map[string]struct{}, len(b.findings))
	for index, finding := range b.findings {
		if err := finding.Validate(); err != nil {
			return err
		}
		if finding.ordinal != uint8(index+1) || finding.responseIdentity != b.responseIdentity || finding.snapshotIdentity != b.snapshotIdentity {
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
		if err := json.Unmarshal(encoded, &candidate); err != nil || !exactJSONKeys(candidate, "title", "claim", "severity_hint", "source_range", "evidence_ids") || firstNonSpace(candidate["source_range"]) != '{' || firstNonSpace(candidate["evidence_ids"]) != '[' {
			return ErrInvalidCandidateDocumentShape
		}
		var sourceRange map[string]json.RawMessage
		if err := json.Unmarshal(candidate["source_range"], &sourceRange); err != nil || !exactJSONKeys(sourceRange, "source_id", "start_line", "end_line") {
			return ErrInvalidCandidateDocumentShape
		}
	}
	var document candidateDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCandidateDocumentJSON, err)
	}
	if document.SchemaVersion != 1 {
		return ErrInvalidCandidateSchemaVersion
	}
	for _, candidate := range document.Candidates {
		if !validCandidateTitle(candidate.Title) || !validCandidateClaim(candidate.Claim) {
			return ErrInvalidCandidateText
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

// ParseCandidateBatch strictly decodes one structured response against exact snapshot evidence.
func ParseCandidateBatch(response provider.Response, snapshot ReviewSnapshot, evidenceItems []evidence.EvidenceItem) (CandidateBatch, error) {
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
	if err := ValidateCandidateDocumentSyntax(payload); err != nil {
		return CandidateBatch{}, err
	}
	var document candidateDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return CandidateBatch{}, ErrInvalidCandidateDocumentJSON
	}
	findings := make([]CandidateFinding, len(document.Candidates))
	seen := make(map[string]struct{}, len(document.Candidates))
	for index, candidate := range document.Candidates {
		finding, err := newCandidateFinding(response.Identity(), snapshot, uint8(index+1), candidate, allowedEvidence)
		if err != nil {
			return CandidateBatch{}, err
		}
		fingerprint := deriveCandidateContentFingerprint(finding)
		if _, exists := seen[fingerprint]; exists {
			return CandidateBatch{}, ErrDuplicateCandidateFinding
		}
		seen[fingerprint] = struct{}{}
		findings[index] = finding
	}
	if len(findings) == 0 {
		findings = nil
	}
	batch := CandidateBatch{responseIdentity: response.Identity(), snapshotIdentity: snapshot.Identity(), findings: findings}
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
	for _, character := range value {
		switch character {
		case ' ', '\t', '\n', '\v', '\f', '\r':
		default:
			return true
		}
	}
	return false
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
	preimage := struct {
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
	}{
		Contract: "open-trestle/candidate-finding", Version: 1,
		Response: finding.responseIdentity, Snapshot: finding.snapshotIdentity, Ordinal: finding.ordinal,
		Title: finding.title, Claim: finding.claim, SeverityHint: string(finding.severityHint),
		SourceReference: finding.sourceReferenceID, Path: finding.sourceRange.Path(),
		Start: finding.sourceRange.StartLine(), End: finding.sourceRange.EndLine(), Evidence: bindings,
	}
	encoded, _ := json.Marshal(preimage)
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
	}{
		Contract: "open-trestle/candidate-batch", Version: 1,
		Response: batch.responseIdentity, Snapshot: batch.snapshotIdentity, Findings: findingIdentities,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
