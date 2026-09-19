package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maximumEncodedVerificationBatchBytes = 2 << 20

var (
	// ErrInvalidVerificationBatchEncoding identifies malformed or noncanonical admitted verdict data.
	ErrInvalidVerificationBatchEncoding = errors.New("invalid verification batch encoding")
)

type encodedVerificationBatchWire struct {
	Contract               string                          `json:"contract"`
	SchemaVersion          int                             `json:"schema_version"`
	Identity               string                          `json:"identity"`
	ResponseIdentity       string                          `json:"response_identity"`
	CandidateBatchIdentity string                          `json:"candidate_batch_identity"`
	SnapshotIdentity       string                          `json:"snapshot_identity"`
	CandidateIdentities    []string                        `json:"candidate_identities"`
	Results                []encodedVerificationResultWire `json:"results"`
}
type encodedVerificationResultWire struct {
	Identity          string                         `json:"identity"`
	CandidateIdentity string                         `json:"candidate_identity"`
	Outcome           string                         `json:"outcome"`
	FinalSeverity     string                         `json:"final_severity"`
	Rationale         string                         `json:"rationale"`
	Path              string                         `json:"path"`
	StartLine         int                            `json:"start_line"`
	EndLine           int                            `json:"end_line"`
	Evidence          []encodedCandidateEvidenceWire `json:"evidence"`
}

// EncodeVerificationBatch returns the canonical durable form of admitted verifier verdicts.
func EncodeVerificationBatch(batch VerificationBatch) ([]byte, error) {
	if err := batch.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(encodedVerificationBatchWireValue(batch))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEncodedVerificationBatchBytes {
		return nil, ErrInvalidVerificationBatchEncoding
	}
	return encoded, nil
}

// ParseEncodedVerificationBatch accepts only a canonical previously admitted verdict set.
func ParseEncodedVerificationBatch(encoded []byte) (VerificationBatch, error) {
	if len(encoded) == 0 || len(encoded) > maximumEncodedVerificationBatchBytes {
		return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire encodedVerificationBatchWire
	if err := decoder.Decode(&wire); err != nil {
		return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/verification-batch" ||
		wire.SchemaVersion != 1 || len(wire.CandidateIdentities) > maxCandidateFindings ||
		len(wire.Results) != len(wire.CandidateIdentities) {
		return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
	}
	results := make([]VerificationResult, len(wire.Results))
	for index, encodedResult := range wire.Results {
		result, err := parseEncodedVerificationResult(
			wire.ResponseIdentity, wire.SnapshotIdentity, encodedResult,
		)
		if err != nil || result.CandidateIdentity() != wire.CandidateIdentities[index] {
			return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
		}
		results[index] = result
	}
	candidateIdentities := append([]string(nil), wire.CandidateIdentities...)
	if len(results) == 0 {
		results = nil
		candidateIdentities = nil
	}
	batch := VerificationBatch{
		identity: wire.Identity, responseIdentity: wire.ResponseIdentity,
		candidateBatchIdentity: wire.CandidateBatchIdentity, snapshotIdentity: wire.SnapshotIdentity,
		candidateIdentities: candidateIdentities, results: results,
	}
	if err := batch.Validate(); err != nil {
		return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
	}
	reencoded, err := EncodeVerificationBatch(batch)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return VerificationBatch{}, ErrInvalidVerificationBatchEncoding
	}
	return batch, nil
}

func parseEncodedVerificationResult(
	responseIdentity, snapshotIdentity string,
	wire encodedVerificationResultWire,
) (VerificationResult, error) {
	outcome, err := ParseVerificationOutcome(wire.Outcome)
	if err != nil {
		return VerificationResult{}, err
	}
	sourceRange, err := evidence.NewSourceRange(wire.Path, wire.StartLine, wire.EndLine)
	if err != nil {
		return VerificationResult{}, err
	}
	bindings := make([]candidateEvidenceBinding, len(wire.Evidence))
	for index, encodedBinding := range wire.Evidence {
		bindingRange, err := evidence.NewSourceRange(
			encodedBinding.Path, encodedBinding.StartLine, encodedBinding.EndLine,
		)
		if err != nil {
			return VerificationResult{}, err
		}
		bindings[index] = candidateEvidenceBinding{
			identity: encodedBinding.Identity, digest: encodedBinding.Digest,
			sourceRange: bindingRange,
		}
	}
	result := VerificationResult{
		identity: wire.Identity, responseIdentity: responseIdentity,
		snapshotIdentity: snapshotIdentity, candidateIdentity: wire.CandidateIdentity,
		outcome: outcome, finalSeverity: Severity(wire.FinalSeverity), rationale: wire.Rationale,
		sourceRange: sourceRange, evidenceBindings: bindings,
	}
	if err := result.Validate(); err != nil {
		return VerificationResult{}, err
	}
	return result, nil
}

func encodedVerificationBatchWireValue(batch VerificationBatch) encodedVerificationBatchWire {
	candidateIdentities := append([]string(nil), batch.candidateIdentities...)
	if candidateIdentities == nil {
		candidateIdentities = make([]string, 0)
	}
	results := make([]encodedVerificationResultWire, len(batch.results))
	for index, result := range batch.results {
		bindings := make([]encodedCandidateEvidenceWire, len(result.evidenceBindings))
		for bindingIndex, binding := range result.evidenceBindings {
			bindings[bindingIndex] = encodedCandidateEvidenceWire{
				Identity: binding.identity, Digest: binding.digest, Path: binding.sourceRange.Path(),
				StartLine: binding.sourceRange.StartLine(), EndLine: binding.sourceRange.EndLine(),
			}
		}
		results[index] = encodedVerificationResultWire{
			Identity: result.Identity(), CandidateIdentity: result.CandidateIdentity(),
			Outcome: result.Outcome().String(), FinalSeverity: string(result.FinalSeverity()),
			Rationale: result.Rationale(), Path: result.sourceRange.Path(),
			StartLine: result.sourceRange.StartLine(), EndLine: result.sourceRange.EndLine(),
			Evidence: bindings,
		}
	}
	return encodedVerificationBatchWire{
		Contract: "open-trestle/verification-batch", SchemaVersion: 1,
		Identity: batch.Identity(), ResponseIdentity: batch.ResponseIdentity(),
		CandidateBatchIdentity: batch.CandidateBatchIdentity(), SnapshotIdentity: batch.SnapshotIdentity(),
		CandidateIdentities: candidateIdentities, Results: results,
	}
}
