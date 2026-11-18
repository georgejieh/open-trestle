package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const maximumPublicationContentScanReceiptBytes = 256 << 10

type publicationContentScannerWire struct {
	WorkerProtocol   int    `json:"worker_protocol"`
	Scanner          string `json:"scanner"`
	ScannerVersion   string `json:"scanner_version"`
	ScannerCommit    string `json:"scanner_commit"`
	RulesetIdentity  string `json:"ruleset_identity"`
	RulesetRuleCount int    `json:"ruleset_rule_count"`
	BuildProfile     string `json:"build_profile"`
	HelperSHA256     string `json:"helper_sha256"`
}
type publicationScanCompletionWire struct {
	Complete         bool `json:"complete"`
	FieldCount       int  `json:"field_count"`
	ScannedByteCount int  `json:"scanned_byte_count"`
	MatchCount       int  `json:"match_count"`
}
type publicationScannedFieldWire struct {
	Kind             string `json:"kind"`
	Ordinal          int    `json:"ordinal"`
	FindingIdentity  string `json:"finding_identity"`
	ScannedByteCount int    `json:"scanned_byte_count"`
}
type publicationRiskFieldWire struct {
	Kind            string `json:"kind"`
	Ordinal         int    `json:"ordinal"`
	FindingIdentity string `json:"finding_identity"`
}
type publicationContentScanReceiptWire struct {
	Contract                    string                        `json:"contract"`
	SchemaVersion               int                           `json:"schema_version"`
	Identity                    string                        `json:"identity"`
	ReviewScopeIdentity         string                        `json:"review_scope_identity"`
	VerifiedFindingSetIdentity  string                        `json:"verified_finding_set_identity"`
	SelectionIdentity           string                        `json:"selection_identity"`
	PublicationPolicyIdentity   string                        `json:"publication_policy_identity"`
	VerificationContextIdentity string                        `json:"verification_context_identity"`
	ScannerAuthorityIdentity    string                        `json:"scanner_authority_identity"`
	Scanner                     publicationContentScannerWire `json:"scanner"`
	Initial                     publicationScanCompletionWire `json:"initial"`
	Residual                    publicationScanCompletionWire `json:"residual"`
	Fields                      []publicationScannedFieldWire `json:"fields"`
	InstructionRiskEvidence     []string                      `json:"instruction_risk_evidence"`
	InstructionRiskFields       []publicationRiskFieldWire    `json:"instruction_risk_fields"`
}

func EncodePublicationContentScanReceipt(receipt PublicationContentScanReceipt) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrInvalidPublicationContentScan
	}
	encoded, err := json.Marshal(publicationContentScanReceiptWireValue(receipt))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPublicationContentScanReceiptBytes {
		return nil, ErrInvalidPublicationContentScan
	}
	return encoded, nil
}

func ParsePublicationContentScanReceipt(encoded []byte) (PublicationContentScanReceipt, error) {
	if len(encoded) == 0 || len(encoded) > maximumPublicationContentScanReceiptBytes {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire publicationContentScanReceiptWire
	if decoder.Decode(&wire) != nil || func() bool { err := decoder.Decode(&struct{}{}); return errors.Is(err, io.EOF) }() == false {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/publication-content-scan-receipt" || wire.SchemaVersion != 1 {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	scanner := wire.Scanner
	initial, residual := wire.Initial, wire.Residual
	fields := make([]PublicationScannedField, len(wire.Fields))
	for index, field := range wire.Fields {
		kind, err := parsePublicationFieldKind(field.Kind)
		if err != nil {
			return PublicationContentScanReceipt{}, err
		}
		fields[index] = PublicationScannedField{Kind: kind, Ordinal: field.Ordinal, FindingIdentity: field.FindingIdentity, ScannedByteCount: field.ScannedByteCount}
	}
	riskFields := make([]PublicationRiskField, len(wire.InstructionRiskFields))
	for index, field := range wire.InstructionRiskFields {
		kind, err := parsePublicationFieldKind(field.Kind)
		if err != nil {
			return PublicationContentScanReceipt{}, err
		}
		riskFields[index] = PublicationRiskField{Kind: kind, Ordinal: field.Ordinal, FindingIdentity: field.FindingIdentity}
	}
	receipt := PublicationContentScanReceipt{
		identity: wire.Identity, reviewScopeIdentity: wire.ReviewScopeIdentity,
		verifiedFindingSetIdentity: wire.VerifiedFindingSetIdentity, selectionIdentity: wire.SelectionIdentity, publicationPolicyIdentity: wire.PublicationPolicyIdentity, verificationContextIdentity: wire.VerificationContextIdentity, scannerAuthorityIdentity: wire.ScannerAuthorityIdentity,
		scanner:  ScannerProfile{WorkerProtocol: scanner.WorkerProtocol, Scanner: scanner.Scanner, ScannerVersion: scanner.ScannerVersion, ScannerCommit: scanner.ScannerCommit, RulesetIdentity: scanner.RulesetIdentity, RulesetRuleCount: scanner.RulesetRuleCount, BuildProfile: scanner.BuildProfile, HelperSHA256: scanner.HelperSHA256},
		initial:  ScanCompletion{Complete: initial.Complete, FieldCount: initial.FieldCount, ScannedByteCount: initial.ScannedByteCount, MatchCount: initial.MatchCount},
		residual: ScanCompletion{Complete: residual.Complete, FieldCount: residual.FieldCount, ScannedByteCount: residual.ScannedByteCount, MatchCount: residual.MatchCount},
		fields:   fields, instructionRiskEvidence: append([]string(nil), wire.InstructionRiskEvidence...), instructionRiskFields: riskFields,
	}
	if receipt.Validate() != nil {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	reencoded, err := EncodePublicationContentScanReceipt(receipt)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return PublicationContentScanReceipt{}, ErrInvalidPublicationContentScan
	}
	return receipt, nil
}

func parsePublicationFieldKind(value string) (PublicationFieldKind, error) {
	for kind := PublicationFieldTitle; kind <= PublicationFieldPath; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, ErrUnclassifiedPublishableField
}

func publicationContentScanReceiptWireValue(receipt PublicationContentScanReceipt) publicationContentScanReceiptWire {
	scanner := receipt.Scanner()
	initial, residual := receipt.Initial(), receipt.Residual()
	fields := make([]publicationScannedFieldWire, len(receipt.fields))
	for index, field := range receipt.fields {
		fields[index] = publicationScannedFieldWire{field.Kind.String(), field.Ordinal, field.FindingIdentity, field.ScannedByteCount}
	}
	riskFields := make([]publicationRiskFieldWire, len(receipt.instructionRiskFields))
	for index, field := range receipt.instructionRiskFields {
		riskFields[index] = publicationRiskFieldWire{field.Kind.String(), field.Ordinal, field.FindingIdentity}
	}
	return publicationContentScanReceiptWire{
		Contract: "open-trestle/publication-content-scan-receipt", SchemaVersion: 1, Identity: receipt.Identity(),
		ReviewScopeIdentity: receipt.ReviewScopeIdentity(), VerifiedFindingSetIdentity: receipt.VerifiedFindingSetIdentity(), SelectionIdentity: receipt.SelectionIdentity(), PublicationPolicyIdentity: receipt.PolicyIdentity(), VerificationContextIdentity: receipt.VerificationContextIdentity(), ScannerAuthorityIdentity: receipt.ScannerAuthorityIdentity(),
		Scanner: publicationContentScannerWire{scanner.WorkerProtocol, scanner.Scanner, scanner.ScannerVersion, scanner.ScannerCommit, scanner.RulesetIdentity, scanner.RulesetRuleCount, scanner.BuildProfile, scanner.HelperSHA256},
		Initial: publicationScanCompletionWire{initial.Complete, initial.FieldCount, initial.ScannedByteCount, initial.MatchCount}, Residual: publicationScanCompletionWire{residual.Complete, residual.FieldCount, residual.ScannedByteCount, residual.MatchCount},
		Fields: fields, InstructionRiskEvidence: receipt.InstructionRiskEvidence(), InstructionRiskFields: riskFields,
	}
}
