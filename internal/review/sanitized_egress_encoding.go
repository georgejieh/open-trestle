package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

type sanitizedModelRequestWire struct {
	Contract                   string `json:"contract"`
	SchemaVersion              int    `json:"schema_version"`
	Identity                   string `json:"identity"`
	ReviewScopeIdentity        string `json:"review_scope_identity"`
	RawRequestIdentity         string `json:"raw_request_identity"`
	SanitizationPolicyIdentity string `json:"sanitization_policy_identity"`
	Capability                 string `json:"capability"`
	MediaType                  string `json:"media_type"`
	Payload                    []byte `json:"payload"`
}

func EncodeSanitizedModelRequest(value SanitizedModelRequest) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalidSanitizedModelRequest
	}
	return encodeSanitizedModelRequestUnchecked(value)
}

func encodeSanitizedModelRequestUnchecked(value SanitizedModelRequest) ([]byte, error) {
	wire := sanitizedModelRequestWire{"open-trestle/sanitized-model-request", 1, value.identity, value.reviewScopeIdentity, value.rawRequestIdentity, SanitizationPolicyIdentity, value.request.Capability().String(), value.request.MediaType(), value.request.Payload()}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSanitizedModelRequestBytes {
		return nil, ErrInvalidSanitizedModelRequest
	}
	return encoded, nil
}

func ParseSanitizedModelRequest(encoded []byte) (SanitizedModelRequest, error) {
	if len(encoded) == 0 || len(encoded) > maximumSanitizedModelRequestBytes || rejectAmbiguousModelRequestJSON(encoded) != nil {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	var wire sanitizedModelRequestWire
	if decodeCanonicalSanitizedJSON(encoded, &wire) != nil || wire.Contract != "open-trestle/sanitized-model-request" || wire.SchemaVersion != 1 || wire.SanitizationPolicyIdentity != SanitizationPolicyIdentity {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	capability, err := provider.ParseCapability(wire.Capability)
	if err != nil {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	request, err := provider.NewRequest(capability, wire.MediaType, wire.Payload)
	if err != nil {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	value := SanitizedModelRequest{identity: wire.Identity, reviewScopeIdentity: wire.ReviewScopeIdentity, rawRequestIdentity: wire.RawRequestIdentity, request: request}
	if value.Validate() != nil {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	reencoded, err := EncodeSanitizedModelRequest(value)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	return value, nil
}

type scannerProfileWire struct {
	WorkerProtocol   int    `json:"worker_protocol"`
	Scanner          string `json:"scanner"`
	ScannerVersion   string `json:"scanner_version"`
	ScannerCommit    string `json:"scanner_commit"`
	RulesetIdentity  string `json:"ruleset_identity"`
	RulesetRuleCount int    `json:"ruleset_rule_count"`
	BuildProfile     string `json:"build_profile"`
	HelperSHA256     string `json:"helper_sha256"`
}
type scanCompletionWire struct {
	Complete         bool `json:"complete"`
	FieldCount       int  `json:"field_count"`
	ScannedByteCount int  `json:"scanned_byte_count"`
	MatchCount       int  `json:"match_count"`
}
type receiptMatchWire struct {
	RuleID           string `json:"rule_id"`
	StartByte        int    `json:"start_byte"`
	EndByteExclusive int    `json:"end_byte_exclusive"`
	OccurrenceID     string `json:"occurrence_id"`
}
type sanitizedFieldWire struct {
	Role              string             `json:"role"`
	Ordinal           int                `json:"ordinal"`
	ScannedByteCount  int                `json:"scanned_byte_count"`
	RedactedByteCount int                `json:"redacted_byte_count"`
	Matches           []receiptMatchWire `json:"matches"`
}
type sanitizedEgressReceiptWire struct {
	Contract                   string               `json:"contract"`
	SchemaVersion              int                  `json:"schema_version"`
	Identity                   string               `json:"identity"`
	ReviewScopeIdentity        string               `json:"review_scope_identity"`
	RawRequestIdentity         string               `json:"raw_request_identity"`
	SanitizedRequestIdentity   string               `json:"sanitized_request_identity"`
	SanitizationPolicyIdentity string               `json:"sanitization_policy_identity"`
	Scanner                    scannerProfileWire   `json:"scanner"`
	FieldCount                 int                  `json:"field_count"`
	ScannedByteCount           int                  `json:"scanned_byte_count"`
	MatchCount                 int                  `json:"match_count"`
	RedactedByteCount          int                  `json:"redacted_byte_count"`
	Initial                    scanCompletionWire   `json:"initial_scan"`
	Residual                   scanCompletionWire   `json:"residual_scan"`
	Fields                     []sanitizedFieldWire `json:"fields"`
}

func EncodeSanitizedEgressReceipt(value SanitizedEgressReceipt) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalidSanitizedEgressReceipt
	}
	encoded, err := json.Marshal(receiptWireValue(value))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSanitizedEgressReceiptBytes {
		return nil, ErrInvalidSanitizedEgressReceipt
	}
	return encoded, nil
}

func ParseSanitizedEgressReceipt(encoded []byte) (SanitizedEgressReceipt, error) {
	if len(encoded) == 0 || len(encoded) > maximumSanitizedEgressReceiptBytes || rejectAmbiguousModelRequestJSON(encoded) != nil {
		return SanitizedEgressReceipt{}, ErrInvalidSanitizedEgressReceipt
	}
	var wire sanitizedEgressReceiptWire
	if decodeCanonicalSanitizedJSON(encoded, &wire) != nil || wire.Contract != "open-trestle/sanitized-egress-receipt" || wire.SchemaVersion != 1 || wire.SanitizationPolicyIdentity != SanitizationPolicyIdentity {
		return SanitizedEgressReceipt{}, ErrInvalidSanitizedEgressReceipt
	}
	fields := make([]SanitizedField, len(wire.Fields))
	for index, field := range wire.Fields {
		matches := make([]secretscan.Match, len(field.Matches))
		for matchIndex, match := range field.Matches {
			matches[matchIndex] = secretscan.Match{SourceOrdinal: field.Ordinal, RuleID: match.RuleID, StartByte: match.StartByte, EndByteExclusive: match.EndByteExclusive, OccurrenceID: match.OccurrenceID}
		}
		fields[index] = SanitizedField{Role: FieldRole(field.Role), Ordinal: field.Ordinal, ScannedByteCount: field.ScannedByteCount, RedactedByteCount: field.RedactedByteCount, Matches: matches}
	}
	value := SanitizedEgressReceipt{identity: wire.Identity, reviewScopeIdentity: wire.ReviewScopeIdentity, rawRequestIdentity: wire.RawRequestIdentity, sanitizedRequestIdentity: wire.SanitizedRequestIdentity, scanner: scannerProfileFromWire(wire.Scanner), initial: scanCompletionFromWire(wire.Initial), residual: scanCompletionFromWire(wire.Residual), redactedByteCount: wire.RedactedByteCount, fields: fields}
	if wire.FieldCount != value.initial.FieldCount || wire.ScannedByteCount != value.initial.ScannedByteCount || wire.MatchCount != value.initial.MatchCount || value.Validate() != nil {
		return SanitizedEgressReceipt{}, ErrInvalidSanitizedEgressReceipt
	}
	reencoded, err := EncodeSanitizedEgressReceipt(value)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return SanitizedEgressReceipt{}, ErrInvalidSanitizedEgressReceipt
	}
	return value, nil
}

func receiptWireValue(value SanitizedEgressReceipt) sanitizedEgressReceiptWire {
	fields := make([]sanitizedFieldWire, len(value.fields))
	for index, field := range value.fields {
		matches := make([]receiptMatchWire, len(field.Matches))
		for matchIndex, match := range field.Matches {
			matches[matchIndex] = receiptMatchWire{match.RuleID, match.StartByte, match.EndByteExclusive, match.OccurrenceID}
		}
		fields[index] = sanitizedFieldWire{string(field.Role), field.Ordinal, field.ScannedByteCount, field.RedactedByteCount, matches}
	}
	return sanitizedEgressReceiptWire{
		Contract: "open-trestle/sanitized-egress-receipt", SchemaVersion: 1, Identity: value.identity,
		ReviewScopeIdentity: value.reviewScopeIdentity, RawRequestIdentity: value.rawRequestIdentity, SanitizedRequestIdentity: value.sanitizedRequestIdentity, SanitizationPolicyIdentity: SanitizationPolicyIdentity,
		Scanner: scannerProfileToWire(value.scanner), FieldCount: value.initial.FieldCount, ScannedByteCount: value.initial.ScannedByteCount, MatchCount: value.initial.MatchCount, RedactedByteCount: value.redactedByteCount,
		Initial: scanCompletionToWire(value.initial), Residual: scanCompletionToWire(value.residual), Fields: fields,
	}
}
func scannerProfileToWire(value ScannerProfile) scannerProfileWire {
	return scannerProfileWire{value.WorkerProtocol, value.Scanner, value.ScannerVersion, value.ScannerCommit, value.RulesetIdentity, value.RulesetRuleCount, value.BuildProfile, value.HelperSHA256}
}
func scannerProfileFromWire(value scannerProfileWire) ScannerProfile {
	return ScannerProfile{value.WorkerProtocol, value.Scanner, value.ScannerVersion, value.ScannerCommit, value.RulesetIdentity, value.RulesetRuleCount, value.BuildProfile, value.HelperSHA256}
}
func scanCompletionToWire(value ScanCompletion) scanCompletionWire {
	return scanCompletionWire{value.Complete, value.FieldCount, value.ScannedByteCount, value.MatchCount}
}
func scanCompletionFromWire(value scanCompletionWire) ScanCompletion {
	return ScanCompletion{value.Complete, value.FieldCount, value.ScannedByteCount, value.MatchCount}
}

func decodeCanonicalSanitizedJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidSanitizedEgressReceipt
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ErrInvalidSanitizedEgressReceipt
	}
	return nil
}
