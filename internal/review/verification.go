package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxVerificationRationaleRunes = 1_024

var (
	// ErrInvalidVerificationResponseEnvelope identifies incomplete, non-structured, or multipart verifier output.
	ErrInvalidVerificationResponseEnvelope = errors.New("invalid verification response envelope")
	// ErrInvalidVerificationDocumentJSON identifies malformed verifier JSON.
	ErrInvalidVerificationDocumentJSON = errors.New("invalid verification document JSON")
	// ErrDuplicateVerificationDocumentKey identifies ambiguous duplicate object keys.
	ErrDuplicateVerificationDocumentKey = errors.New("duplicate verification document key")
	// ErrInvalidVerificationDocumentShape identifies missing, unknown, or noncanonical fields.
	ErrInvalidVerificationDocumentShape = errors.New("invalid verification document shape")
	// ErrInvalidVerificationSchemaVersion identifies an unsupported verifier schema.
	ErrInvalidVerificationSchemaVersion = errors.New("invalid verification schema version")
	// ErrInvalidVerificationOutcome identifies an unknown verifier verdict.
	ErrInvalidVerificationOutcome = errors.New("invalid verification outcome")
	// ErrInvalidVerificationSeverity identifies severity inconsistent with the verdict.
	ErrInvalidVerificationSeverity = errors.New("invalid verification severity")
	// ErrInvalidVerificationRationale identifies blank or excessive rationale text.
	ErrInvalidVerificationRationale = errors.New("invalid verification rationale")
	// ErrVerificationCandidateNotAllowed identifies a verdict for a candidate outside the exact batch.
	ErrVerificationCandidateNotAllowed = errors.New("verification candidate not allowed")
	// ErrDuplicateVerificationCandidate identifies repeated verdicts for one candidate.
	ErrDuplicateVerificationCandidate = errors.New("duplicate verification candidate")
	// ErrVerificationCandidateSetMismatch identifies a missing candidate verdict.
	ErrVerificationCandidateSetMismatch = errors.New("verification candidate set mismatch")
	// ErrVerificationEvidenceNotAllowed identifies verifier evidence outside the host allowlist.
	ErrVerificationEvidenceNotAllowed = errors.New("verification evidence not allowed")
	// ErrVerificationEvidenceRangeMismatch identifies a verified verdict without cited range support.
	ErrVerificationEvidenceRangeMismatch = errors.New("verification evidence range mismatch")
	// ErrInvalidVerificationResult identifies inconsistent verdict fields.
	ErrInvalidVerificationResult = errors.New("invalid verification result")
	// ErrInvalidVerificationResultIdentity identifies verdict content inconsistent with its identity.
	ErrInvalidVerificationResultIdentity = errors.New("invalid verification result identity")
	// ErrInvalidVerificationBatchIdentity identifies batch content inconsistent with its identity.
	ErrInvalidVerificationBatchIdentity = errors.New("invalid verification batch identity")
)

// VerificationOutcome identifies an independent verifier's bounded verdict.
type VerificationOutcome uint8

const (
	VerificationVerified VerificationOutcome = iota + 1
	VerificationRejected
	VerificationInconclusive
)

func (o VerificationOutcome) String() string {
	switch o {
	case VerificationVerified:
		return "verified"
	case VerificationRejected:
		return "rejected"
	case VerificationInconclusive:
		return "inconclusive"
	default:
		return ""
	}
}

// ParseVerificationOutcome parses one exact stable verifier verdict.
func ParseVerificationOutcome(value string) (VerificationOutcome, error) {
	for outcome := VerificationVerified; outcome <= VerificationInconclusive; outcome++ {
		if outcome.String() == value {
			return outcome, nil
		}
	}
	return 0, ErrInvalidVerificationOutcome
}

func (o VerificationOutcome) Validate() error {
	if o.String() == "" {
		return ErrInvalidVerificationOutcome
	}
	return nil
}

// VerificationResult is one immutable verdict bound to a candidate and exact evidence.
type VerificationResult struct {
	identity          string
	responseIdentity  string
	snapshotIdentity  string
	candidateIdentity string
	outcome           VerificationOutcome
	finalSeverity     Severity
	rationale         string
	sourceRange       evidence.SourceRange
	evidenceBindings  []candidateEvidenceBinding
	// side is the candidate's location side. Bindings record a side only for
	// a verdict on a categorized (v2) candidate.
	side LineSide
}

func (r VerificationResult) Identity() string             { return r.identity }
func (r VerificationResult) ResponseIdentity() string     { return r.responseIdentity }
func (r VerificationResult) SnapshotIdentity() string     { return r.snapshotIdentity }
func (r VerificationResult) CandidateIdentity() string    { return r.candidateIdentity }
func (r VerificationResult) Outcome() VerificationOutcome { return r.outcome }
func (r VerificationResult) FinalSeverity() Severity      { return r.finalSeverity }
func (r VerificationResult) Rationale() string            { return r.rationale }

// Side returns the side of the candidate location the verdict answers.
func (r VerificationResult) Side() LineSide { return r.side }
func (r VerificationResult) EvidenceIDs() []string {
	identities := make([]string, len(r.evidenceBindings))
	for index, binding := range r.evidenceBindings {
		identities[index] = binding.identity
	}
	return identities
}
func (r VerificationResult) String() string   { return "verification result" }
func (r VerificationResult) GoString() string { return "review.VerificationResult{<redacted>}" }
func (r VerificationResult) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "verification result", "review.VerificationResult{<redacted>}")
}

// Validate verifies verdict semantics, evidence bindings, range support, and identity.
func (r VerificationResult) Validate() error {
	if !validCandidateDigest(r.responseIdentity) || !validCandidateDigest(r.snapshotIdentity) || !validCandidateDigest(r.candidateIdentity) || !validCandidateSourceRange(r.sourceRange) || !validLineSide(r.side) {
		return ErrInvalidVerificationResult
	}
	if err := r.outcome.Validate(); err != nil {
		return err
	}
	if !validCandidateFreeText(r.rationale, maxVerificationRationaleRunes) {
		return ErrInvalidVerificationRationale
	}
	if len(r.evidenceBindings) > maxCandidateEvidence {
		return ErrInvalidCandidateEvidenceSet
	}
	previous := ""
	citedRange := false
	for _, binding := range r.evidenceBindings {
		if !validCandidateReference(binding.identity) || !validCandidateDigest(binding.digest) || !validCandidateSourceRange(binding.sourceRange) || !validLineSide(binding.side) || previous != "" && binding.identity <= previous {
			return ErrInvalidCandidateEvidenceSet
		}
		citedRange = citedRange || bindingCovers(binding, r.side, r.sourceRange)
		previous = binding.identity
	}
	if r.outcome == VerificationVerified {
		if !isKnownSeverity(r.finalSeverity) {
			return ErrInvalidVerificationSeverity
		}
		if len(r.evidenceBindings) == 0 || !citedRange {
			return ErrVerificationEvidenceRangeMismatch
		}
	} else if r.finalSeverity != "" {
		return ErrInvalidVerificationSeverity
	}
	if r.identity != deriveVerificationResultIdentity(r) {
		return ErrInvalidVerificationResultIdentity
	}
	return nil
}

// VerificationBatch contains exactly one result for every candidate in its bound batch.
type VerificationBatch struct {
	identity               string
	responseIdentity       string
	candidateBatchIdentity string
	snapshotIdentity       string
	candidateIdentities    []string
	results                []VerificationResult
}

func (b VerificationBatch) Identity() string               { return b.identity }
func (b VerificationBatch) ResponseIdentity() string       { return b.responseIdentity }
func (b VerificationBatch) CandidateBatchIdentity() string { return b.candidateBatchIdentity }
func (b VerificationBatch) SnapshotIdentity() string       { return b.snapshotIdentity }
func (b VerificationBatch) Results() []VerificationResult {
	return append([]VerificationResult(nil), b.results...)
}
func (b VerificationBatch) String() string   { return "verification batch" }
func (b VerificationBatch) GoString() string { return "review.VerificationBatch{<redacted>}" }
func (b VerificationBatch) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "verification batch", "review.VerificationBatch{<redacted>}")
}

// Validate verifies exact candidate coverage, canonical result order, and identity.
func (b VerificationBatch) Validate() error {
	if !validCandidateDigest(b.responseIdentity) || !validCandidateDigest(b.candidateBatchIdentity) || !validCandidateDigest(b.snapshotIdentity) || len(b.candidateIdentities) > maxCandidateFindings || len(b.results) != len(b.candidateIdentities) {
		return ErrInvalidVerificationBatchIdentity
	}
	seenCandidates := make(map[string]struct{}, len(b.candidateIdentities))
	for index, candidateIdentity := range b.candidateIdentities {
		if !validCandidateDigest(candidateIdentity) {
			return ErrInvalidVerificationBatchIdentity
		}
		if _, exists := seenCandidates[candidateIdentity]; exists {
			return ErrInvalidVerificationBatchIdentity
		}
		seenCandidates[candidateIdentity] = struct{}{}
		result := b.results[index]
		if err := result.Validate(); err != nil {
			return err
		}
		if result.responseIdentity != b.responseIdentity || result.snapshotIdentity != b.snapshotIdentity || result.candidateIdentity != candidateIdentity {
			return ErrInvalidVerificationBatchIdentity
		}
	}
	if b.identity != deriveVerificationBatchIdentity(b) {
		return ErrInvalidVerificationBatchIdentity
	}
	return nil
}

type verificationDocument struct {
	SchemaVersion int                           `json:"schema_version"`
	Verdicts      []verificationVerdictDocument `json:"verdicts"`
}

type verificationVerdictDocument struct {
	CandidateID string   `json:"candidate_id"`
	Outcome     string   `json:"outcome"`
	Severity    string   `json:"severity"`
	Rationale   string   `json:"rationale"`
	EvidenceIDs []string `json:"evidence_ids"`
	// Check is read only by VerificationAuthoredChecks, which drops an
	// invalid one, so its content never refuses the verdict.
	Check json.RawMessage `json:"check,omitempty"`
}

// ValidateVerificationDocumentSyntax enforces the public
// model-verification-batch-v2 schema syntax, apart from each verdict's
// optional check. A version 1 document, which has no check, is accepted too.
func ValidateVerificationDocumentSyntax(payload []byte) error {
	if err := rejectDuplicateCandidateJSONKeys(payload); err != nil {
		if errors.Is(err, ErrDuplicateCandidateDocumentKey) {
			return ErrDuplicateVerificationDocumentKey
		}
		return ErrInvalidVerificationDocumentJSON
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(payload, &root); err != nil {
		return ErrInvalidVerificationDocumentJSON
	}
	if !exactJSONKeys(root, "schema_version", "verdicts") || firstNonSpace(root["verdicts"]) != '[' {
		return ErrInvalidVerificationDocumentShape
	}
	var rawVerdicts []json.RawMessage
	if err := json.Unmarshal(root["verdicts"], &rawVerdicts); err != nil || len(rawVerdicts) > maxCandidateFindings {
		return ErrInvalidVerificationDocumentShape
	}
	var version int
	_ = json.Unmarshal(root["schema_version"], &version)
	for _, encoded := range rawVerdicts {
		var verdict map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &verdict); err != nil {
			return ErrInvalidVerificationDocumentShape
		}
		if _, checked := verdict["check"]; checked && version == 2 {
			delete(verdict, "check")
		}
		if !exactJSONKeys(verdict, "candidate_id", "outcome", "severity", "rationale", "evidence_ids") || firstNonSpace(verdict["evidence_ids"]) != '[' {
			return ErrInvalidVerificationDocumentShape
		}
	}
	var document verificationDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return ErrInvalidVerificationDocumentJSON
	}
	if document.SchemaVersion != 1 && document.SchemaVersion != 2 {
		return ErrInvalidVerificationSchemaVersion
	}
	for _, verdict := range document.Verdicts {
		if !validVerificationCandidateLabel(verdict.CandidateID) {
			return ErrVerificationCandidateNotAllowed
		}
		outcome, err := ParseVerificationOutcome(verdict.Outcome)
		if err != nil {
			return err
		}
		if !validCandidateFreeText(verdict.Rationale, maxVerificationRationaleRunes) {
			return ErrInvalidVerificationRationale
		}
		if len(verdict.EvidenceIDs) > maxCandidateEvidence {
			return ErrInvalidCandidateEvidenceSet
		}
		seen := make(map[string]struct{}, len(verdict.EvidenceIDs))
		for _, identity := range verdict.EvidenceIDs {
			if !validCandidateReference(identity) {
				return ErrInvalidCandidateReference
			}
			if _, exists := seen[identity]; exists {
				return ErrDuplicateCandidateEvidence
			}
			seen[identity] = struct{}{}
		}
		if outcome == VerificationVerified {
			if !isKnownSeverity(Severity(verdict.Severity)) || len(verdict.EvidenceIDs) == 0 {
				return ErrInvalidVerificationSeverity
			}
		} else if verdict.Severity != "none" {
			return ErrInvalidVerificationSeverity
		}
	}
	return nil
}

// ParseVerificationBatch binds strict verifier output to every exact candidate and allowed evidence item.
func ParseVerificationBatch(response provider.Response, candidates CandidateBatch, evidenceItems []evidence.EvidenceItem) (VerificationBatch, error) {
	return parseVerificationBatch(response, candidates, evidenceItems, nil)
}

// ParseContextVerificationBatch is ParseVerificationBatch against the exact
// verifier request it answers. A removed_lines source of that request may be
// cited, but never shows that a verified verdict's evidence covers the
// candidate's head lines, because its line numbers are base coordinates.
func ParseContextVerificationBatch(response provider.Response, candidates CandidateBatch, context VerificationRequestContext) (VerificationBatch, error) {
	if context.Validate() != nil || candidates.Identity() != context.CandidateBatchIdentity() {
		return VerificationBatch{}, ErrInvalidVerificationRequestContext
	}
	wire, err := decodeVerificationContextWire(context.Payload())
	if err != nil {
		return VerificationBatch{}, ErrInvalidVerificationRequestContext
	}
	baseLines := make(map[string]struct{})
	for _, source := range wire.Sources {
		if source.Stage == ContextStageRemovedLines.String() {
			baseLines[source.SourceID] = struct{}{}
		}
	}
	return parseVerificationBatch(response, candidates, context.EvidenceItems(), baseLines)
}

// VerificationBatchMatchesContext reports whether a recorded verdict batch
// records exactly the sides its verifier request implies: each result has the
// side of the candidate it answers, and each cited binding of a verdict on a
// candidate batch that records sides records base lines exactly when it names
// a removed_lines source of that request. Any other batch records no side.
// Readback therefore cannot turn cited base lines into head lines.
func VerificationBatchMatchesContext(context VerificationRequestContext, candidates CandidateBatch, batch VerificationBatch) bool {
	if context.Validate() != nil || candidates.Identity() != context.CandidateBatchIdentity() || batch.CandidateBatchIdentity() != candidates.Identity() || len(batch.results) != len(candidates.findings) {
		return false
	}
	wire, err := decodeVerificationContextWire(context.Payload())
	if err != nil {
		return false
	}
	stages := make(map[string]string, len(wire.Sources))
	for _, source := range wire.Sources {
		stages[source.SourceID] = source.Stage
	}
	for index, result := range batch.results {
		if result.side != candidates.findings[index].side {
			return false
		}
		for _, binding := range result.evidenceBindings {
			stage, exists := stages[binding.identity]
			expected := LineSideHead
			if candidates.recordsSides() && stage == ContextStageRemovedLines.String() {
				expected = LineSideBase
			}
			if !exists || binding.side != expected {
				return false
			}
		}
	}
	return true
}

func parseVerificationBatch(response provider.Response, candidates CandidateBatch, evidenceItems []evidence.EvidenceItem, baseLines map[string]struct{}) (VerificationBatch, error) {
	if err := response.Validate(); err != nil {
		return VerificationBatch{}, err
	}
	if response.Capability() != provider.CapabilityReviewV1 {
		return VerificationBatch{}, ErrInvalidVerificationResponseEnvelope
	}
	payload, err := answerDocument(response, ErrInvalidVerificationResponseEnvelope)
	if err != nil {
		return VerificationBatch{}, err
	}
	if err := candidates.Validate(); err != nil {
		return VerificationBatch{}, err
	}
	allowedEvidence, err := validateCandidateEvidenceSet(evidenceItems)
	if err != nil {
		return VerificationBatch{}, err
	}
	batch, err := parseVerificationDocument(response, payload, candidates, allowedEvidence, baseLines)
	if err != nil {
		return VerificationBatch{}, modelOutputFailure(err)
	}
	return batch, nil
}

// parseVerificationDocument admits the verifier's document against host
// inputs parseVerificationBatch has already validated, so every error it
// returns was caused by the document.
func parseVerificationDocument(response provider.Response, payload []byte, candidates CandidateBatch, allowedEvidence map[string]evidence.EvidenceItem, baseLines map[string]struct{}) (VerificationBatch, error) {
	if err := ValidateVerificationDocumentSyntax(payload); err != nil {
		return VerificationBatch{}, err
	}
	var document verificationDocument
	if err := json.Unmarshal(payload, &document); err != nil {
		return VerificationBatch{}, ErrInvalidVerificationDocumentJSON
	}
	candidateValues := candidates.Findings()
	allowedCandidates := make(map[string]CandidateFinding, len(candidateValues))
	candidateIdentities := make([]string, len(candidateValues))
	// A verdict names its candidate by the request's label; the host maps the
	// label back to the candidate identity.
	for index, candidate := range candidateValues {
		allowedCandidates[verificationCandidateLabel(index)] = candidate
		candidateIdentities[index] = candidate.Identity()
	}
	byCandidate := make(map[string]VerificationResult, len(document.Verdicts))
	for _, verdict := range document.Verdicts {
		candidate, exists := allowedCandidates[verdict.CandidateID]
		if !exists {
			return VerificationBatch{}, ErrVerificationCandidateNotAllowed
		}
		if _, exists := byCandidate[candidate.Identity()]; exists {
			return VerificationBatch{}, ErrDuplicateVerificationCandidate
		}
		result, err := newVerificationResult(response.Identity(), candidates.SnapshotIdentity(), candidate, verdict, allowedEvidence, baseLines, candidates.recordsSides())
		if err != nil {
			return VerificationBatch{}, err
		}
		byCandidate[candidate.Identity()] = result
	}
	if len(byCandidate) != len(candidateValues) {
		return VerificationBatch{}, ErrVerificationCandidateSetMismatch
	}
	results := make([]VerificationResult, len(candidateValues))
	for index, identity := range candidateIdentities {
		results[index] = byCandidate[identity]
	}
	if len(results) == 0 {
		results = nil
		candidateIdentities = nil
	}
	batch := VerificationBatch{
		responseIdentity: response.Identity(), candidateBatchIdentity: candidates.Identity(),
		snapshotIdentity: candidates.SnapshotIdentity(), candidateIdentities: candidateIdentities, results: results,
	}
	batch.identity = deriveVerificationBatchIdentity(batch)
	if err := batch.Validate(); err != nil {
		return VerificationBatch{}, err
	}
	return batch, nil
}

// newVerificationResult binds one verdict. baseLines names the removed_lines
// sources of the request; a verdict on a categorized candidate (recordSides)
// records each such citation as a base binding. Only a citation on the
// candidate's own side can cover its location; a verified verdict that cites
// none also cites the candidate's located source when that source is on the
// candidate's side, in the request and there is room for it.
func newVerificationResult(responseIdentity, snapshotIdentity string, candidate CandidateFinding, verdict verificationVerdictDocument, allowed map[string]evidence.EvidenceItem, baseLines map[string]struct{}, recordSides bool) (VerificationResult, error) {
	outcome, _ := ParseVerificationOutcome(verdict.Outcome)
	bindings := make([]candidateEvidenceBinding, 0, len(verdict.EvidenceIDs))
	sides := make(map[string]LineSide, len(verdict.EvidenceIDs))
	for _, identity := range verdict.EvidenceIDs {
		item, exists := allowed[identity]
		if !exists {
			return VerificationResult{}, ErrVerificationEvidenceNotAllowed
		}
		binding := candidateEvidenceBinding{identity: item.ID(), digest: item.Digest(), sourceRange: item.SourceRange()}
		if _, base := baseLines[identity]; base {
			sides[identity] = LineSideBase
			if recordSides {
				binding.side = LineSideBase
			}
		}
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(left, right int) bool { return bindings[left].identity < bindings[right].identity })
	severity := Severity("")
	if outcome == VerificationVerified {
		severity = Severity(verdict.Severity)
	}
	result := VerificationResult{
		responseIdentity: responseIdentity, snapshotIdentity: snapshotIdentity,
		candidateIdentity: candidate.Identity(), outcome: outcome, finalSeverity: severity,
		rationale: verdict.Rationale, sourceRange: candidate.SourceRange(), evidenceBindings: bindings, side: candidate.side,
	}
	if outcome == VerificationVerified {
		cited := false
		for _, binding := range bindings {
			if sides[binding.identity] == candidate.side {
				cited = cited || rangeContains(binding.sourceRange, candidate.SourceRange())
			}
		}
		if !cited {
			// The verdict is about the candidate, so it cites the source that
			// holds the candidate's lines even when evidence_ids leaves it out.
			item, found := allowed[candidate.SourceReferenceID()]
			_, base := baseLines[candidate.SourceReferenceID()]
			if !found || base != (candidate.side == LineSideBase) || slices.Contains(verdict.EvidenceIDs, item.ID()) || len(bindings) >= maxCandidateEvidence || !rangeContains(item.SourceRange(), candidate.SourceRange()) {
				return VerificationResult{}, ErrVerificationEvidenceRangeMismatch
			}
			binding := candidateEvidenceBinding{identity: item.ID(), digest: item.Digest(), sourceRange: item.SourceRange()}
			if base && recordSides {
				binding.side = LineSideBase
			}
			result.evidenceBindings = append(bindings, binding)
			sort.Slice(result.evidenceBindings, func(left, right int) bool {
				return result.evidenceBindings[left].identity < result.evidenceBindings[right].identity
			})
		}
	}
	result.identity = deriveVerificationResultIdentity(result)
	return result, nil
}

func deriveVerificationResultIdentity(result VerificationResult) string {
	type evidenceRecord struct {
		Identity string `json:"identity"`
		Digest   string `json:"digest"`
		Path     string `json:"path"`
		Start    int    `json:"start"`
		End      int    `json:"end"`
		// Side is present only for base lines, so head bindings keep their
		// historical preimage. The location side is bound by the candidate.
		Side string `json:"side,omitempty"`
	}
	evidenceValues := make([]evidenceRecord, len(result.evidenceBindings))
	for index, binding := range result.evidenceBindings {
		evidenceValues[index] = evidenceRecord{
			Identity: binding.identity, Digest: binding.digest, Path: binding.sourceRange.Path(),
			Start: binding.sourceRange.StartLine(), End: binding.sourceRange.EndLine(),
			Side: recordedLineSide(binding.side),
		}
	}
	rationaleDigest := sha256.Sum256([]byte(result.rationale))
	preimage := struct {
		Contract        string           `json:"contract"`
		Version         int              `json:"version"`
		Response        string           `json:"response"`
		Snapshot        string           `json:"snapshot"`
		Candidate       string           `json:"candidate"`
		Outcome         string           `json:"outcome"`
		Severity        string           `json:"severity"`
		RationaleDigest string           `json:"rationale_digest"`
		RationaleBytes  int              `json:"rationale_bytes"`
		Evidence        []evidenceRecord `json:"evidence"`
	}{
		Contract: "open-trestle/verification-result", Version: 1,
		Response: result.responseIdentity, Snapshot: result.snapshotIdentity,
		Candidate: result.candidateIdentity, Outcome: result.outcome.String(), Severity: string(result.finalSeverity),
		RationaleDigest: hex.EncodeToString(rationaleDigest[:]), RationaleBytes: len(result.rationale), Evidence: evidenceValues,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveVerificationBatchIdentity(batch VerificationBatch) string {
	resultIdentities := make([]string, len(batch.results))
	for index, result := range batch.results {
		resultIdentities[index] = result.Identity()
	}
	preimage := struct {
		Contract       string   `json:"contract"`
		Version        int      `json:"version"`
		Response       string   `json:"response"`
		CandidateBatch string   `json:"candidate_batch"`
		Snapshot       string   `json:"snapshot"`
		Candidates     []string `json:"candidates"`
		Results        []string `json:"results"`
	}{
		Contract: "open-trestle/verification-batch", Version: 1,
		Response: batch.responseIdentity, CandidateBatch: batch.candidateBatchIdentity,
		Snapshot: batch.snapshotIdentity, Candidates: batch.candidateIdentities, Results: resultIdentities,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
