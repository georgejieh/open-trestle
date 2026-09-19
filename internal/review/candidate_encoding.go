package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maximumEncodedCandidateBatchBytes = 2 << 20

var (
	// ErrInvalidCandidateBatchEncoding identifies malformed or noncanonical admitted-candidate data.
	ErrInvalidCandidateBatchEncoding = errors.New("invalid candidate batch encoding")
)

type encodedCandidateBatchWire struct {
	Contract         string                        `json:"contract"`
	SchemaVersion    int                           `json:"schema_version"`
	Identity         string                        `json:"identity"`
	ResponseIdentity string                        `json:"response_identity"`
	SnapshotIdentity string                        `json:"snapshot_identity"`
	Findings         []encodedCandidateFindingWire `json:"findings"`
}

type encodedCandidateFindingWire struct {
	Identity          string                         `json:"identity"`
	Ordinal           uint8                          `json:"ordinal"`
	Title             string                         `json:"title"`
	Claim             string                         `json:"claim"`
	SeverityHint      string                         `json:"severity_hint"`
	SourceReferenceID string                         `json:"source_reference_id"`
	Path              string                         `json:"path"`
	StartLine         int                            `json:"start_line"`
	EndLine           int                            `json:"end_line"`
	Evidence          []encodedCandidateEvidenceWire `json:"evidence"`
}

type encodedCandidateEvidenceWire struct {
	Identity  string `json:"identity"`
	Digest    string `json:"digest"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// EncodeCandidateBatch returns the canonical durable form of strictly admitted candidates.
func EncodeCandidateBatch(batch CandidateBatch) ([]byte, error) {
	if err := batch.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(encodedCandidateBatchWireValue(batch))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumEncodedCandidateBatchBytes {
		return nil, ErrInvalidCandidateBatchEncoding
	}
	return encoded, nil
}

// ParseEncodedCandidateBatch accepts only a canonical previously admitted candidate set.
func ParseEncodedCandidateBatch(encoded []byte) (CandidateBatch, error) {
	if len(encoded) == 0 || len(encoded) > maximumEncodedCandidateBatchBytes {
		return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire encodedCandidateBatchWire
	if err := decoder.Decode(&wire); err != nil {
		return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) ||
		wire.Contract != "open-trestle/candidate-batch" || wire.SchemaVersion != 1 ||
		len(wire.Findings) > maxCandidateFindings {
		return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
	}
	findings := make([]CandidateFinding, len(wire.Findings))
	for index, encodedFinding := range wire.Findings {
		finding, err := parseEncodedCandidateFinding(
			wire.ResponseIdentity, wire.SnapshotIdentity, encodedFinding,
		)
		if err != nil || finding.Ordinal() != uint8(index+1) {
			return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
		}
		findings[index] = finding
	}
	if len(findings) == 0 {
		findings = nil
	}
	batch := CandidateBatch{
		identity: wire.Identity, responseIdentity: wire.ResponseIdentity,
		snapshotIdentity: wire.SnapshotIdentity, findings: findings,
	}
	if err := batch.Validate(); err != nil {
		return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
	}
	reencoded, err := EncodeCandidateBatch(batch)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return CandidateBatch{}, ErrInvalidCandidateBatchEncoding
	}
	return batch, nil
}

func parseEncodedCandidateFinding(
	responseIdentity, snapshotIdentity string,
	wire encodedCandidateFindingWire,
) (CandidateFinding, error) {
	sourceRange, err := evidence.NewSourceRange(wire.Path, wire.StartLine, wire.EndLine)
	if err != nil {
		return CandidateFinding{}, err
	}
	bindings := make([]candidateEvidenceBinding, len(wire.Evidence))
	for index, encodedBinding := range wire.Evidence {
		bindingRange, err := evidence.NewSourceRange(
			encodedBinding.Path, encodedBinding.StartLine, encodedBinding.EndLine,
		)
		if err != nil {
			return CandidateFinding{}, err
		}
		bindings[index] = candidateEvidenceBinding{
			identity: encodedBinding.Identity, digest: encodedBinding.Digest,
			sourceRange: bindingRange,
		}
	}
	finding := CandidateFinding{
		identity: wire.Identity, responseIdentity: responseIdentity,
		snapshotIdentity: snapshotIdentity, ordinal: wire.Ordinal,
		title: wire.Title, claim: wire.Claim, severityHint: Severity(wire.SeverityHint),
		sourceReferenceID: wire.SourceReferenceID, sourceRange: sourceRange,
		evidenceBindings: bindings,
	}
	if err := finding.Validate(); err != nil {
		return CandidateFinding{}, err
	}
	return finding, nil
}

func encodedCandidateBatchWireValue(batch CandidateBatch) encodedCandidateBatchWire {
	findings := make([]encodedCandidateFindingWire, len(batch.findings))
	for index, finding := range batch.findings {
		bindings := make([]encodedCandidateEvidenceWire, len(finding.evidenceBindings))
		for bindingIndex, binding := range finding.evidenceBindings {
			bindings[bindingIndex] = encodedCandidateEvidenceWire{
				Identity: binding.identity, Digest: binding.digest,
				Path: binding.sourceRange.Path(), StartLine: binding.sourceRange.StartLine(),
				EndLine: binding.sourceRange.EndLine(),
			}
		}
		findings[index] = encodedCandidateFindingWire{
			Identity: finding.Identity(), Ordinal: finding.Ordinal(),
			Title: finding.Title(), Claim: finding.Claim(), SeverityHint: string(finding.SeverityHint()),
			SourceReferenceID: finding.SourceReferenceID(), Path: finding.SourceRange().Path(),
			StartLine: finding.SourceRange().StartLine(), EndLine: finding.SourceRange().EndLine(),
			Evidence: bindings,
		}
	}
	return encodedCandidateBatchWire{
		Contract: "open-trestle/candidate-batch", SchemaVersion: 1,
		Identity: batch.Identity(), ResponseIdentity: batch.ResponseIdentity(),
		SnapshotIdentity: batch.SnapshotIdentity(), Findings: findings,
	}
}
