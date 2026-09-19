package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
)

var (
	// ErrIndependentVerificationOutputMismatch identifies output, context, response, or artifact cross-wiring.
	ErrIndependentVerificationOutputMismatch = errors.New("independent verification output mismatch")
	// ErrIndependentVerificationRouteMismatch identifies route independence unrelated to the output attempts.
	ErrIndependentVerificationRouteMismatch = errors.New("independent verification route mismatch")
	// ErrInvalidIndependentVerificationReceipt identifies malformed result coverage or counts.
	ErrInvalidIndependentVerificationReceipt = errors.New("invalid independent verification receipt")
	// ErrInvalidIndependentVerificationReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidIndependentVerificationReceiptIdentity = errors.New("invalid independent verification receipt identity")
	// ErrVerifiedFindingBindingMismatch identifies a candidate and verdict that do not match.
	ErrVerifiedFindingBindingMismatch = errors.New("verified finding binding mismatch")
	// ErrInvalidVerifiedFindingIdentity identifies finding content inconsistent with its identity.
	ErrInvalidVerifiedFindingIdentity = errors.New("invalid verified finding identity")
	// ErrInvalidVerifiedFindingSet identifies inconsistent verified, rejected, or inconclusive accounting.
	ErrInvalidVerifiedFindingSet = errors.New("invalid verified finding set")
	// ErrInvalidVerifiedFindingSetIdentity identifies set content inconsistent with its identity.
	ErrInvalidVerifiedFindingSetIdentity = errors.New("invalid verified finding set identity")
)

// IndependentVerificationReceipt binds admitted candidates and verifier verdicts to two independent route outputs.
type IndependentVerificationReceipt struct {
	identity                    string
	reviewScopeIdentity         string
	snapshotIdentity            string
	generationContextIdentity   string
	verificationContextIdentity string
	candidateOutputIdentity     string
	verificationOutputIdentity  string
	routeIndependenceIdentity   string
	independenceLevel           gateway.RouteIndependenceLevel
	candidateBatchIdentity      string
	verificationBatchIdentity   string
	candidateIdentities         []string
	resultIdentities            []string
	verifiedCount               uint8
	rejectedCount               uint8
	inconclusiveCount           uint8
}

// IndependentVerificationArtifacts supplies the complete two-route verification lineage.
type IndependentVerificationArtifacts struct {
	GenerationContext   ContextPacket
	Candidates          CandidateBatch
	CandidateOutput     gateway.RouteOutputReceipt
	VerificationContext VerificationContextPacket
	Verification        VerificationBatch
	VerificationOutput  gateway.RouteOutputReceipt
	RouteIndependence   gateway.RouteIndependenceReceipt
}

// IndependentVerificationRecords supplies durable identity-level context and complete result records.
type IndependentVerificationRecords struct {
	ReviewScopeIdentity         string
	SnapshotIdentity            string
	GenerationContextIdentity   string
	VerificationContextIdentity string
	GenerationRequestIdentity   string
	VerificationRequestIdentity string
	Candidates                  CandidateBatch
	CandidateOutput             gateway.RouteOutputReceipt
	Verification                VerificationBatch
	VerificationOutput          gateway.RouteOutputReceipt
	RouteIndependence           gateway.RouteIndependenceReceipt
}

// NewIndependentVerificationReceiptFromRecords validates durable generation and verification lineage.
func NewIndependentVerificationReceiptFromRecords(records IndependentVerificationRecords) (IndependentVerificationReceipt, error) {
	candidates := records.Candidates
	candidateOutput := records.CandidateOutput
	verification := records.Verification
	verificationOutput := records.VerificationOutput
	independence := records.RouteIndependence
	if !validCandidateDigest(records.ReviewScopeIdentity) || !validCandidateDigest(records.SnapshotIdentity) ||
		!validCandidateDigest(records.GenerationContextIdentity) || !validCandidateDigest(records.VerificationContextIdentity) ||
		!validCandidateDigest(records.GenerationRequestIdentity) || !validCandidateDigest(records.VerificationRequestIdentity) ||
		candidates.Validate() != nil || candidateOutput.Validate() != nil || verification.Validate() != nil ||
		verificationOutput.Validate() != nil || independence.Validate() != nil {
		return IndependentVerificationReceipt{}, ErrInvalidIndependentVerificationReceipt
	}
	validCandidateOutput := candidateOutput.Kind() == gateway.RouteOutputCandidateBatch &&
		candidateOutput.ReviewScopeIdentity() == records.ReviewScopeIdentity &&
		candidateOutput.ContextIdentity() == records.GenerationContextIdentity &&
		candidateOutput.ArtifactIdentity() == candidates.Identity() &&
		candidateOutput.RequestIdentity() == records.GenerationRequestIdentity &&
		candidateOutput.ResponseIdentity() == candidates.ResponseIdentity()
	validVerificationOutput := verificationOutput.Kind() == gateway.RouteOutputVerificationBatch &&
		verificationOutput.ReviewScopeIdentity() == records.ReviewScopeIdentity &&
		verificationOutput.ContextIdentity() == records.VerificationContextIdentity &&
		verificationOutput.ArtifactIdentity() == verification.Identity() &&
		verificationOutput.RequestIdentity() == records.VerificationRequestIdentity &&
		verificationOutput.ResponseIdentity() == verification.ResponseIdentity()
	validBatches := records.SnapshotIdentity == candidates.SnapshotIdentity() &&
		verification.CandidateBatchIdentity() == candidates.Identity() &&
		verification.SnapshotIdentity() == records.SnapshotIdentity
	validRoutes := independence.ReviewScopeIdentity() == records.ReviewScopeIdentity &&
		independence.FirstAuthorizationIdentity() == candidateOutput.AuthorizationIdentity() &&
		independence.FirstOutcomeIdentity() == candidateOutput.OutcomeIdentity() &&
		independence.SecondAuthorizationIdentity() == verificationOutput.AuthorizationIdentity() &&
		independence.SecondOutcomeIdentity() == verificationOutput.OutcomeIdentity()
	if !validCandidateOutput || !validVerificationOutput || !validBatches {
		return IndependentVerificationReceipt{}, ErrIndependentVerificationOutputMismatch
	}
	if !validRoutes {
		return IndependentVerificationReceipt{}, ErrIndependentVerificationRouteMismatch
	}
	return newIndependentVerificationReceipt(
		records.ReviewScopeIdentity, records.SnapshotIdentity, records.GenerationContextIdentity,
		records.VerificationContextIdentity, candidates, candidateOutput, verification,
		verificationOutput, independence,
	)
}

func newIndependentVerificationReceipt(
	reviewScopeIdentity, snapshotIdentity, generationContextIdentity, verificationContextIdentity string,
	candidates CandidateBatch,
	candidateOutput gateway.RouteOutputReceipt,
	verification VerificationBatch,
	verificationOutput gateway.RouteOutputReceipt,
	independence gateway.RouteIndependenceReceipt,
) (IndependentVerificationReceipt, error) {
	candidateValues := candidates.Findings()
	resultValues := verification.Results()
	receipt := IndependentVerificationReceipt{
		reviewScopeIdentity: reviewScopeIdentity, snapshotIdentity: snapshotIdentity,
		generationContextIdentity: generationContextIdentity, verificationContextIdentity: verificationContextIdentity,
		candidateOutputIdentity: candidateOutput.Identity(), verificationOutputIdentity: verificationOutput.Identity(),
		routeIndependenceIdentity: independence.Identity(), independenceLevel: independence.Level(),
		candidateBatchIdentity: candidates.Identity(), verificationBatchIdentity: verification.Identity(),
		candidateIdentities: make([]string, len(candidateValues)), resultIdentities: make([]string, len(resultValues)),
	}
	for index, candidate := range candidateValues {
		receipt.candidateIdentities[index] = candidate.Identity()
		result := resultValues[index]
		receipt.resultIdentities[index] = result.Identity()
		switch result.Outcome() {
		case VerificationVerified:
			receipt.verifiedCount++
		case VerificationRejected:
			receipt.rejectedCount++
		case VerificationInconclusive:
			receipt.inconclusiveCount++
		}
	}
	if len(receipt.candidateIdentities) == 0 {
		receipt.candidateIdentities = nil
		receipt.resultIdentities = nil
	}
	receipt.identity = deriveIndependentVerificationReceiptIdentity(receipt)
	if err := receipt.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	return receipt, nil
}

// NewIndependentVerificationReceipt validates the complete generation, verification, and route lineage.
func NewIndependentVerificationReceipt(artifacts IndependentVerificationArtifacts) (IndependentVerificationReceipt, error) {
	generationContext := artifacts.GenerationContext
	candidates := artifacts.Candidates
	candidateOutput := artifacts.CandidateOutput
	verificationContext := artifacts.VerificationContext
	verification := artifacts.Verification
	verificationOutput := artifacts.VerificationOutput
	independence := artifacts.RouteIndependence
	if err := generationContext.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	if err := candidates.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	if err := candidateOutput.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	if err := verificationContext.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	if err := verification.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	if err := verificationOutput.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	if err := independence.Validate(); err != nil {
		return IndependentVerificationReceipt{}, err
	}
	generationRequest, err := generationContext.ProviderRequest()
	if err != nil {
		return IndependentVerificationReceipt{}, err
	}
	verifierRequest, err := verificationContext.ProviderRequest()
	if err != nil {
		return IndependentVerificationReceipt{}, err
	}
	validCandidateOutput := candidateOutput.Kind() == gateway.RouteOutputCandidateBatch &&
		candidateOutput.ReviewScopeIdentity() == generationContext.ReviewScopeIdentity() &&
		candidateOutput.ContextIdentity() == generationContext.Identity() &&
		candidateOutput.ArtifactIdentity() == candidates.Identity() &&
		candidateOutput.RequestIdentity() == generationRequest.Identity() &&
		candidateOutput.ResponseIdentity() == candidates.ResponseIdentity()
	if !validCandidateOutput {
		return IndependentVerificationReceipt{}, ErrIndependentVerificationOutputMismatch
	}
	validVerificationContext := verificationContext.GenerationContextIdentity() == generationContext.Identity() &&
		verificationContext.CandidateBatchIdentity() == candidates.Identity() &&
		verification.CandidateBatchIdentity() == candidates.Identity() &&
		verification.SnapshotIdentity() == candidates.SnapshotIdentity()
	if !validVerificationContext {
		return IndependentVerificationReceipt{}, ErrIndependentVerificationOutputMismatch
	}
	validVerificationOutput := verificationOutput.Kind() == gateway.RouteOutputVerificationBatch &&
		verificationOutput.ReviewScopeIdentity() == generationContext.ReviewScopeIdentity() &&
		verificationOutput.ContextIdentity() == verificationContext.Identity() &&
		verificationOutput.ArtifactIdentity() == verification.Identity() &&
		verificationOutput.RequestIdentity() == verifierRequest.Identity() &&
		verificationOutput.ResponseIdentity() == verification.ResponseIdentity()
	if !validVerificationOutput {
		return IndependentVerificationReceipt{}, ErrIndependentVerificationOutputMismatch
	}
	validFirstRoute := independence.FirstAuthorizationIdentity() == candidateOutput.AuthorizationIdentity() &&
		independence.FirstOutcomeIdentity() == candidateOutput.OutcomeIdentity()
	validSecondRoute := independence.SecondAuthorizationIdentity() == verificationOutput.AuthorizationIdentity() &&
		independence.SecondOutcomeIdentity() == verificationOutput.OutcomeIdentity()
	if independence.ReviewScopeIdentity() != generationContext.ReviewScopeIdentity() || !validFirstRoute || !validSecondRoute {
		return IndependentVerificationReceipt{}, ErrIndependentVerificationRouteMismatch
	}
	return newIndependentVerificationReceipt(
		generationContext.ReviewScopeIdentity(), candidates.SnapshotIdentity(),
		generationContext.Identity(), verificationContext.Identity(), candidates, candidateOutput,
		verification, verificationOutput, independence,
	)
}

func (r IndependentVerificationReceipt) Identity() string            { return r.identity }
func (r IndependentVerificationReceipt) ReviewScopeIdentity() string { return r.reviewScopeIdentity }
func (r IndependentVerificationReceipt) SnapshotIdentity() string    { return r.snapshotIdentity }
func (r IndependentVerificationReceipt) GenerationContextIdentity() string {
	return r.generationContextIdentity
}
func (r IndependentVerificationReceipt) VerificationContextIdentity() string {
	return r.verificationContextIdentity
}
func (r IndependentVerificationReceipt) CandidateBatchIdentity() string {
	return r.candidateBatchIdentity
}
func (r IndependentVerificationReceipt) VerificationBatchIdentity() string {
	return r.verificationBatchIdentity
}
func (r IndependentVerificationReceipt) RouteIndependenceIdentity() string {
	return r.routeIndependenceIdentity
}
func (r IndependentVerificationReceipt) IndependenceLevel() gateway.RouteIndependenceLevel {
	return r.independenceLevel
}
func (r IndependentVerificationReceipt) VerifiedCount() uint8     { return r.verifiedCount }
func (r IndependentVerificationReceipt) RejectedCount() uint8     { return r.rejectedCount }
func (r IndependentVerificationReceipt) InconclusiveCount() uint8 { return r.inconclusiveCount }
func (r IndependentVerificationReceipt) String() string           { return "independent verification receipt" }
func (r IndependentVerificationReceipt) GoString() string {
	return "review.IndependentVerificationReceipt{<redacted>}"
}
func (r IndependentVerificationReceipt) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "independent verification receipt", "review.IndependentVerificationReceipt{<redacted>}")
}

// Validate verifies exact result coverage, counts, identities, and independence level.
func (r IndependentVerificationReceipt) Validate() error {
	for _, identity := range []string{
		r.reviewScopeIdentity, r.snapshotIdentity, r.generationContextIdentity,
		r.verificationContextIdentity, r.candidateOutputIdentity, r.verificationOutputIdentity,
		r.routeIndependenceIdentity, r.candidateBatchIdentity, r.verificationBatchIdentity,
	} {
		if !validCandidateDigest(identity) {
			return ErrInvalidIndependentVerificationReceipt
		}
	}
	if err := r.independenceLevel.Validate(); err != nil {
		return err
	}
	if len(r.candidateIdentities) != len(r.resultIdentities) || len(r.candidateIdentities) > maxCandidateFindings || int(r.verifiedCount)+int(r.rejectedCount)+int(r.inconclusiveCount) != len(r.candidateIdentities) {
		return ErrInvalidIndependentVerificationReceipt
	}
	seenCandidates := make(map[string]struct{}, len(r.candidateIdentities))
	seenResults := make(map[string]struct{}, len(r.resultIdentities))
	for index, candidateIdentity := range r.candidateIdentities {
		resultIdentity := r.resultIdentities[index]
		if !validCandidateDigest(candidateIdentity) || !validCandidateDigest(resultIdentity) {
			return ErrInvalidIndependentVerificationReceipt
		}
		if _, exists := seenCandidates[candidateIdentity]; exists {
			return ErrInvalidIndependentVerificationReceipt
		}
		if _, exists := seenResults[resultIdentity]; exists {
			return ErrInvalidIndependentVerificationReceipt
		}
		seenCandidates[candidateIdentity] = struct{}{}
		seenResults[resultIdentity] = struct{}{}
	}
	if r.identity != deriveIndependentVerificationReceiptIdentity(r) {
		return ErrInvalidIndependentVerificationReceiptIdentity
	}
	return nil
}

// VerifiedFinding is an independently accepted model candidate with exact source evidence.
type VerifiedFinding struct {
	identity                   string
	fingerprint                string
	independentReceiptIdentity string
	snapshotIdentity           string
	candidateIdentity          string
	verificationIdentity       string
	title                      string
	claim                      string
	severity                   Severity
	sourceRange                evidence.SourceRange
	evidenceBindings           []candidateEvidenceBinding
}

func (f VerifiedFinding) Identity() string                  { return f.identity }
func (f VerifiedFinding) Fingerprint() string               { return f.fingerprint }
func (f VerifiedFinding) CandidateIdentity() string         { return f.candidateIdentity }
func (f VerifiedFinding) VerificationIdentity() string      { return f.verificationIdentity }
func (f VerifiedFinding) Title() string                     { return f.title }
func (f VerifiedFinding) Claim() string                     { return f.claim }
func (f VerifiedFinding) Severity() Severity                { return f.severity }
func (f VerifiedFinding) SourceRange() evidence.SourceRange { return f.sourceRange }
func (f VerifiedFinding) EvidenceIDs() []string {
	identities := make([]string, len(f.evidenceBindings))
	for index, binding := range f.evidenceBindings {
		identities[index] = binding.identity
	}
	return identities
}
func (f VerifiedFinding) String() string   { return "verified finding" }
func (f VerifiedFinding) GoString() string { return "review.VerifiedFinding{<redacted>}" }
func (f VerifiedFinding) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "verified finding", "review.VerifiedFinding{<redacted>}")
}

// Validate verifies independent lineage, exact evidence, severity, fingerprint, and identity.
func (f VerifiedFinding) Validate() error {
	for _, identity := range []string{f.independentReceiptIdentity, f.snapshotIdentity, f.candidateIdentity, f.verificationIdentity, f.fingerprint} {
		if !validCandidateDigest(identity) {
			return ErrVerifiedFindingBindingMismatch
		}
	}
	if !validCandidateTitle(f.title) || !validCandidateClaim(f.claim) || !isKnownSeverity(f.severity) || !validCandidateSourceRange(f.sourceRange) || len(f.evidenceBindings) == 0 || len(f.evidenceBindings) > maxCandidateEvidence {
		return ErrVerifiedFindingBindingMismatch
	}
	previous := ""
	cited := false
	for _, binding := range f.evidenceBindings {
		if !validCandidateReference(binding.identity) || !validCandidateDigest(binding.digest) || !validCandidateSourceRange(binding.sourceRange) || previous != "" && binding.identity <= previous {
			return ErrVerifiedFindingBindingMismatch
		}
		cited = cited || rangeContains(binding.sourceRange, f.sourceRange)
		previous = binding.identity
	}
	if !cited || f.fingerprint != deriveVerifiedFindingFingerprint(f) {
		return ErrVerifiedFindingBindingMismatch
	}
	if f.identity != deriveVerifiedFindingIdentity(f) {
		return ErrInvalidVerifiedFindingIdentity
	}
	return nil
}

// VerifiedFindingSet preserves accepted findings and explicit non-acceptance counts.
type VerifiedFindingSet struct {
	identity                   string
	independentReceiptIdentity string
	candidateBatchIdentity     string
	verificationBatchIdentity  string
	snapshotIdentity           string
	candidateCount             uint8
	rejectedCount              uint8
	inconclusiveCount          uint8
	findings                   []VerifiedFinding
}

// PromoteVerifiedCandidates creates publishable inputs only from independently verified verdicts.
func PromoteVerifiedCandidates(receipt IndependentVerificationReceipt, candidates CandidateBatch, verification VerificationBatch) (VerifiedFindingSet, error) {
	if err := receipt.Validate(); err != nil {
		return VerifiedFindingSet{}, err
	}
	if err := candidates.Validate(); err != nil {
		return VerifiedFindingSet{}, err
	}
	if err := verification.Validate(); err != nil {
		return VerifiedFindingSet{}, err
	}
	matchingBatches := receipt.CandidateBatchIdentity() == candidates.Identity() &&
		receipt.VerificationBatchIdentity() == verification.Identity() &&
		verification.CandidateBatchIdentity() == candidates.Identity()
	if !matchingBatches || candidates.SnapshotIdentity() != verification.SnapshotIdentity() {
		return VerifiedFindingSet{}, ErrVerifiedFindingBindingMismatch
	}
	candidateValues := candidates.Findings()
	resultValues := verification.Results()
	findings := make([]VerifiedFinding, 0, receipt.VerifiedCount())
	for index, candidate := range candidateValues {
		result := resultValues[index]
		if result.CandidateIdentity() != candidate.Identity() {
			return VerifiedFindingSet{}, ErrVerifiedFindingBindingMismatch
		}
		if result.Outcome() != VerificationVerified {
			continue
		}
		finding := VerifiedFinding{
			independentReceiptIdentity: receipt.Identity(), snapshotIdentity: candidates.SnapshotIdentity(),
			candidateIdentity: candidate.Identity(), verificationIdentity: result.Identity(),
			title: candidate.Title(), claim: candidate.Claim(), severity: result.FinalSeverity(),
			sourceRange: candidate.SourceRange(), evidenceBindings: append([]candidateEvidenceBinding(nil), result.evidenceBindings...),
		}
		finding.fingerprint = deriveVerifiedFindingFingerprint(finding)
		finding.identity = deriveVerifiedFindingIdentity(finding)
		if err := finding.Validate(); err != nil {
			return VerifiedFindingSet{}, err
		}
		findings = append(findings, finding)
	}
	if len(findings) == 0 {
		findings = nil
	}
	set := VerifiedFindingSet{
		independentReceiptIdentity: receipt.Identity(), candidateBatchIdentity: candidates.Identity(),
		verificationBatchIdentity: verification.Identity(), snapshotIdentity: candidates.SnapshotIdentity(),
		candidateCount: uint8(len(candidateValues)), rejectedCount: receipt.RejectedCount(),
		inconclusiveCount: receipt.InconclusiveCount(), findings: findings,
	}
	set.identity = deriveVerifiedFindingSetIdentity(set)
	if err := set.Validate(); err != nil {
		return VerifiedFindingSet{}, err
	}
	return set, nil
}

func (s VerifiedFindingSet) Identity() string                   { return s.identity }
func (s VerifiedFindingSet) IndependentReceiptIdentity() string { return s.independentReceiptIdentity }
func (s VerifiedFindingSet) SnapshotIdentity() string           { return s.snapshotIdentity }
func (s VerifiedFindingSet) CandidateCount() uint8              { return s.candidateCount }
func (s VerifiedFindingSet) VerifiedCount() uint8               { return uint8(len(s.findings)) }
func (s VerifiedFindingSet) RejectedCount() uint8               { return s.rejectedCount }
func (s VerifiedFindingSet) InconclusiveCount() uint8           { return s.inconclusiveCount }
func (s VerifiedFindingSet) Findings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), s.findings...)
}
func (s VerifiedFindingSet) String() string   { return "verified finding set" }
func (s VerifiedFindingSet) GoString() string { return "review.VerifiedFindingSet{<redacted>}" }
func (s VerifiedFindingSet) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "verified finding set", "review.VerifiedFindingSet{<redacted>}")
}

// Validate verifies finding coverage, non-acceptance counts, uniqueness, and identity.
func (s VerifiedFindingSet) Validate() error {
	for _, identity := range []string{s.independentReceiptIdentity, s.candidateBatchIdentity, s.verificationBatchIdentity, s.snapshotIdentity} {
		if !validCandidateDigest(identity) {
			return ErrInvalidVerifiedFindingSet
		}
	}
	if int(s.VerifiedCount())+int(s.rejectedCount)+int(s.inconclusiveCount) != int(s.candidateCount) || len(s.findings) > maxCandidateFindings {
		return ErrInvalidVerifiedFindingSet
	}
	seenFingerprints := make(map[string]struct{}, len(s.findings))
	for _, finding := range s.findings {
		if err := finding.Validate(); err != nil {
			return err
		}
		if finding.independentReceiptIdentity != s.independentReceiptIdentity || finding.snapshotIdentity != s.snapshotIdentity {
			return ErrInvalidVerifiedFindingSet
		}
		if _, exists := seenFingerprints[finding.Fingerprint()]; exists {
			return ErrInvalidVerifiedFindingSet
		}
		seenFingerprints[finding.Fingerprint()] = struct{}{}
	}
	if s.identity != deriveVerifiedFindingSetIdentity(s) {
		return ErrInvalidVerifiedFindingSetIdentity
	}
	return nil
}

func deriveIndependentVerificationReceiptIdentity(receipt IndependentVerificationReceipt) string {
	preimage := struct {
		Contract            string   `json:"contract"`
		Version             int      `json:"version"`
		Scope               string   `json:"scope"`
		Snapshot            string   `json:"snapshot"`
		GenerationContext   string   `json:"generation_context"`
		VerificationContext string   `json:"verification_context"`
		CandidateOutput     string   `json:"candidate_output"`
		VerificationOutput  string   `json:"verification_output"`
		Independence        string   `json:"independence"`
		IndependenceLevel   string   `json:"independence_level"`
		CandidateBatch      string   `json:"candidate_batch"`
		VerificationBatch   string   `json:"verification_batch"`
		Candidates          []string `json:"candidates"`
		Results             []string `json:"results"`
		Verified            uint8    `json:"verified"`
		Rejected            uint8    `json:"rejected"`
		Inconclusive        uint8    `json:"inconclusive"`
	}{
		Contract: "open-trestle/independent-verification-receipt", Version: 1,
		Scope: receipt.reviewScopeIdentity, Snapshot: receipt.snapshotIdentity,
		GenerationContext: receipt.generationContextIdentity, VerificationContext: receipt.verificationContextIdentity,
		CandidateOutput: receipt.candidateOutputIdentity, VerificationOutput: receipt.verificationOutputIdentity,
		Independence: receipt.routeIndependenceIdentity, IndependenceLevel: receipt.independenceLevel.String(),
		CandidateBatch: receipt.candidateBatchIdentity, VerificationBatch: receipt.verificationBatchIdentity,
		Candidates: receipt.candidateIdentities, Results: receipt.resultIdentities,
		Verified: receipt.verifiedCount, Rejected: receipt.rejectedCount, Inconclusive: receipt.inconclusiveCount,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveVerifiedFindingFingerprint(finding VerifiedFinding) string {
	preimage := struct {
		Snapshot string `json:"snapshot"`
		Path     string `json:"path"`
		Start    int    `json:"start"`
		End      int    `json:"end"`
		Title    string `json:"title"`
		Claim    string `json:"claim"`
	}{
		Snapshot: finding.snapshotIdentity, Path: finding.sourceRange.Path(),
		Start: finding.sourceRange.StartLine(), End: finding.sourceRange.EndLine(),
		Title: finding.title, Claim: finding.claim,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveVerifiedFindingIdentity(finding VerifiedFinding) string {
	preimage := struct {
		Contract     string   `json:"contract"`
		Version      int      `json:"version"`
		Receipt      string   `json:"receipt"`
		Fingerprint  string   `json:"fingerprint"`
		Candidate    string   `json:"candidate"`
		Verification string   `json:"verification"`
		Severity     string   `json:"severity"`
		Evidence     []string `json:"evidence"`
	}{
		Contract: "open-trestle/verified-finding", Version: 1,
		Receipt: finding.independentReceiptIdentity, Fingerprint: finding.fingerprint,
		Candidate: finding.candidateIdentity, Verification: finding.verificationIdentity,
		Severity: string(finding.severity), Evidence: finding.EvidenceIDs(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func deriveVerifiedFindingSetIdentity(set VerifiedFindingSet) string {
	identities := make([]string, len(set.findings))
	for index, finding := range set.findings {
		identities[index] = finding.Identity()
	}
	preimage := struct {
		Contract          string   `json:"contract"`
		Version           int      `json:"version"`
		Receipt           string   `json:"receipt"`
		CandidateBatch    string   `json:"candidate_batch"`
		VerificationBatch string   `json:"verification_batch"`
		Snapshot          string   `json:"snapshot"`
		CandidateCount    uint8    `json:"candidate_count"`
		Rejected          uint8    `json:"rejected"`
		Inconclusive      uint8    `json:"inconclusive"`
		Findings          []string `json:"findings"`
	}{
		Contract: "open-trestle/verified-finding-set", Version: 1,
		Receipt: set.independentReceiptIdentity, CandidateBatch: set.candidateBatchIdentity,
		VerificationBatch: set.verificationBatchIdentity, Snapshot: set.snapshotIdentity,
		CandidateCount: set.candidateCount, Rejected: set.rejectedCount,
		Inconclusive: set.inconclusiveCount, Findings: identities,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
