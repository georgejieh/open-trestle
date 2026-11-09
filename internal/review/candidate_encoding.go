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
	// RepositoryContextOmitted counts v2 proposals dropped for naming a
	// repository_context source; omitted when zero.
	RepositoryContextOmitted uint8 `json:"repository_context_anchor_omitted,omitempty"`
}

type encodedCandidateFindingWire struct {
	Identity          string `json:"identity"`
	Ordinal           uint8  `json:"ordinal"`
	Title             string `json:"title"`
	Claim             string `json:"claim"`
	Category          string `json:"category,omitempty"`
	Fix               string `json:"fix,omitempty"`
	SeverityHint      string `json:"severity_hint"`
	SourceReferenceID string `json:"source_reference_id"`
	Path              string `json:"path"`
	StartLine         int    `json:"start_line"`
	EndLine           int    `json:"end_line"`
	// Side is "base" for a location on removed base lines; it is absent for
	// head lines and never present in a version 1 batch. HeadLine is the head
	// line of a base-side location's deletion point.
	Side     string                         `json:"side,omitempty"`
	HeadLine int                            `json:"head_line,omitempty"`
	Evidence []encodedCandidateEvidenceWire `json:"evidence"`
}

// encodedCandidateEvidenceWire is one recorded evidence binding of a candidate,
// verdict, or verified finding. Side is "base" for a cited removed_lines source
// of a categorized (v2) record and absent otherwise.
type encodedCandidateEvidenceWire struct {
	Identity  string `json:"identity"`
	Digest    string `json:"digest"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Side      string `json:"side,omitempty"`
}

// parseEncodedEvidenceBindings rebuilds recorded evidence bindings, accepting
// only an absent side or "base".
func parseEncodedEvidenceBindings(values []encodedCandidateEvidenceWire) ([]candidateEvidenceBinding, error) {
	bindings := make([]candidateEvidenceBinding, len(values))
	for index, value := range values {
		bindingRange, err := evidence.NewSourceRange(value.Path, value.StartLine, value.EndLine)
		if err != nil {
			return nil, err
		}
		side, ok := parseRecordedLineSide(value.Side)
		if !ok {
			return nil, ErrInvalidCandidateEvidenceSet
		}
		bindings[index] = candidateEvidenceBinding{identity: value.Identity, digest: value.Digest, sourceRange: bindingRange, side: side}
	}
	return bindings, nil
}

// encodedEvidenceBindings returns the recorded form of evidence bindings.
func encodedEvidenceBindings(bindings []candidateEvidenceBinding) []encodedCandidateEvidenceWire {
	values := make([]encodedCandidateEvidenceWire, len(bindings))
	for index, binding := range bindings {
		values[index] = encodedCandidateEvidenceWire{
			Identity: binding.identity, Digest: binding.digest,
			Path: binding.sourceRange.Path(), StartLine: binding.sourceRange.StartLine(),
			EndLine: binding.sourceRange.EndLine(), Side: recordedLineSide(binding.side),
		}
	}
	return values
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
// Schema version 1 carries v1 candidates; version 2 carries categorized v2
// candidates with optional fix guidance and, for base lines of a removed_lines
// source, a recorded side on the location and on each such evidence binding.
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
		wire.Contract != "open-trestle/candidate-batch" || (wire.SchemaVersion != 1 && wire.SchemaVersion != 2) ||
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
		snapshotIdentity: wire.SnapshotIdentity, findings: findings, categorized: wire.SchemaVersion == 2,
		repositoryContextOmitted: wire.RepositoryContextOmitted,
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
	bindings, err := parseEncodedEvidenceBindings(wire.Evidence)
	if err != nil {
		return CandidateFinding{}, err
	}
	side, ok := parseRecordedLineSide(wire.Side)
	if !ok {
		return CandidateFinding{}, ErrCandidateRangeNotSupported
	}
	finding := CandidateFinding{
		identity: wire.Identity, responseIdentity: responseIdentity,
		snapshotIdentity: snapshotIdentity, ordinal: wire.Ordinal,
		title: wire.Title, claim: wire.Claim, severityHint: Severity(wire.SeverityHint),
		sourceReferenceID: wire.SourceReferenceID, sourceRange: sourceRange,
		evidenceBindings: bindings, category: CandidateCategory(wire.Category), fix: wire.Fix, side: side, headLine: wire.HeadLine,
	}
	if err := finding.Validate(); err != nil {
		return CandidateFinding{}, err
	}
	return finding, nil
}

func encodedCandidateBatchWireValue(batch CandidateBatch) encodedCandidateBatchWire {
	findings := make([]encodedCandidateFindingWire, len(batch.findings))
	for index, finding := range batch.findings {
		findings[index] = encodedCandidateFindingWire{
			Identity: finding.Identity(), Ordinal: finding.Ordinal(),
			Title: finding.Title(), Claim: finding.Claim(), Category: string(finding.Category()), Fix: finding.Fix(),
			SeverityHint:      string(finding.SeverityHint()),
			SourceReferenceID: finding.SourceReferenceID(), Path: finding.SourceRange().Path(),
			StartLine: finding.SourceRange().StartLine(), EndLine: finding.SourceRange().EndLine(),
			Side: recordedLineSide(finding.side), HeadLine: finding.headLine, Evidence: encodedEvidenceBindings(finding.evidenceBindings),
		}
	}
	return encodedCandidateBatchWire{
		Contract: "open-trestle/candidate-batch", SchemaVersion: batch.SchemaVersion(),
		Identity: batch.Identity(), ResponseIdentity: batch.ResponseIdentity(),
		SnapshotIdentity: batch.SnapshotIdentity(), Findings: findings,
		RepositoryContextOmitted: batch.repositoryContextOmitted,
	}
}
