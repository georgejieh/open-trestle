package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maximumEncodedVerifiedFindingSetBytes = 2 << 20

var (
	// ErrInvalidVerifiedFindingSetEncoding identifies malformed or noncanonical promoted findings.
	ErrInvalidVerifiedFindingSetEncoding = errors.New("invalid verified finding set encoding")
)

type encodedVerifiedFindingSetWire struct {
	Contract                   string                       `json:"contract"`
	SchemaVersion              int                          `json:"schema_version"`
	Identity                   string                       `json:"identity"`
	IndependentReceiptIdentity string                       `json:"independent_receipt_identity"`
	CandidateBatchIdentity     string                       `json:"candidate_batch_identity"`
	VerificationBatchIdentity  string                       `json:"verification_batch_identity"`
	SnapshotIdentity           string                       `json:"snapshot_identity"`
	CandidateCount             uint8                        `json:"candidate_count"`
	RejectedCount              uint8                        `json:"rejected_count"`
	InconclusiveCount          uint8                        `json:"inconclusive_count"`
	Findings                   []encodedVerifiedFindingWire `json:"findings"`
}
type encodedVerifiedFindingWire struct {
	Identity             string                         `json:"identity"`
	Fingerprint          string                         `json:"fingerprint"`
	CandidateIdentity    string                         `json:"candidate_identity"`
	VerificationIdentity string                         `json:"verification_identity"`
	Title                string                         `json:"title"`
	Claim                string                         `json:"claim"`
	Severity             string                         `json:"severity"`
	Path                 string                         `json:"path"`
	StartLine            int                            `json:"start_line"`
	EndLine              int                            `json:"end_line"`
	Evidence             []encodedCandidateEvidenceWire `json:"evidence"`
}

// EncodeVerifiedFindingSet returns the canonical durable form of promoted findings.
func EncodeVerifiedFindingSet(set VerifiedFindingSet) ([]byte, error) {
	if err := set.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(encodedVerifiedFindingSetWireValue(set))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEncodedVerifiedFindingSetBytes {
		return nil, ErrInvalidVerifiedFindingSetEncoding
	}
	return encoded, nil
}

// ParseEncodedVerifiedFindingSet accepts only a canonical promoted finding set.
func ParseEncodedVerifiedFindingSet(encoded []byte) (VerifiedFindingSet, error) {
	if len(encoded) == 0 || len(encoded) > maximumEncodedVerifiedFindingSetBytes {
		return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire encodedVerifiedFindingSetWire
	if err := decoder.Decode(&wire); err != nil {
		return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/verified-finding-set" ||
		wire.SchemaVersion != 1 || len(wire.Findings) > maxCandidateFindings {
		return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
	}
	findings := make([]VerifiedFinding, len(wire.Findings))
	for index, value := range wire.Findings {
		finding, err := parseEncodedVerifiedFinding(wire, value)
		if err != nil {
			return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
		}
		findings[index] = finding
	}
	if len(findings) == 0 {
		findings = nil
	}
	set := VerifiedFindingSet{
		identity: wire.Identity, independentReceiptIdentity: wire.IndependentReceiptIdentity,
		candidateBatchIdentity:    wire.CandidateBatchIdentity,
		verificationBatchIdentity: wire.VerificationBatchIdentity, snapshotIdentity: wire.SnapshotIdentity,
		candidateCount: wire.CandidateCount, rejectedCount: wire.RejectedCount,
		inconclusiveCount: wire.InconclusiveCount, findings: findings,
	}
	if err := set.Validate(); err != nil {
		return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
	}
	reencoded, err := EncodeVerifiedFindingSet(set)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return VerifiedFindingSet{}, ErrInvalidVerifiedFindingSetEncoding
	}
	return set, nil
}

func parseEncodedVerifiedFinding(
	set encodedVerifiedFindingSetWire,
	wire encodedVerifiedFindingWire,
) (VerifiedFinding, error) {
	sourceRange, err := evidence.NewSourceRange(wire.Path, wire.StartLine, wire.EndLine)
	if err != nil {
		return VerifiedFinding{}, err
	}
	bindings := make([]candidateEvidenceBinding, len(wire.Evidence))
	for index, encodedBinding := range wire.Evidence {
		bindingRange, err := evidence.NewSourceRange(
			encodedBinding.Path, encodedBinding.StartLine, encodedBinding.EndLine,
		)
		if err != nil {
			return VerifiedFinding{}, err
		}
		bindings[index] = candidateEvidenceBinding{
			identity: encodedBinding.Identity, digest: encodedBinding.Digest,
			sourceRange: bindingRange,
		}
	}
	finding := VerifiedFinding{
		identity: wire.Identity, fingerprint: wire.Fingerprint,
		independentReceiptIdentity: set.IndependentReceiptIdentity,
		snapshotIdentity:           set.SnapshotIdentity, candidateIdentity: wire.CandidateIdentity,
		verificationIdentity: wire.VerificationIdentity, title: wire.Title, claim: wire.Claim,
		severity: Severity(wire.Severity), sourceRange: sourceRange, evidenceBindings: bindings,
	}
	if err := finding.Validate(); err != nil {
		return VerifiedFinding{}, err
	}
	return finding, nil
}

func encodedVerifiedFindingSetWireValue(set VerifiedFindingSet) encodedVerifiedFindingSetWire {
	findings := make([]encodedVerifiedFindingWire, len(set.findings))
	for index, finding := range set.findings {
		bindings := make([]encodedCandidateEvidenceWire, len(finding.evidenceBindings))
		for bindingIndex, binding := range finding.evidenceBindings {
			bindings[bindingIndex] = encodedCandidateEvidenceWire{
				Identity: binding.identity, Digest: binding.digest, Path: binding.sourceRange.Path(),
				StartLine: binding.sourceRange.StartLine(), EndLine: binding.sourceRange.EndLine(),
			}
		}
		findings[index] = encodedVerifiedFindingWire{
			Identity: finding.Identity(), Fingerprint: finding.Fingerprint(),
			CandidateIdentity: finding.CandidateIdentity(), VerificationIdentity: finding.VerificationIdentity(),
			Title: finding.Title(), Claim: finding.Claim(), Severity: string(finding.Severity()),
			Path: finding.SourceRange().Path(), StartLine: finding.SourceRange().StartLine(),
			EndLine: finding.SourceRange().EndLine(), Evidence: bindings,
		}
	}
	return encodedVerifiedFindingSetWire{
		Contract: "open-trestle/verified-finding-set", SchemaVersion: 1, Identity: set.Identity(),
		IndependentReceiptIdentity: set.IndependentReceiptIdentity(),
		CandidateBatchIdentity:     set.candidateBatchIdentity,
		VerificationBatchIdentity:  set.verificationBatchIdentity, SnapshotIdentity: set.SnapshotIdentity(),
		CandidateCount: set.CandidateCount(), RejectedCount: set.RejectedCount(),
		InconclusiveCount: set.InconclusiveCount(), Findings: findings,
	}
}
