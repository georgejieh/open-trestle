package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

const (
	SanitizationPolicyIdentity         = "4397ca6dd6c89759aa20fd780d587df19dd415f18a36c2e084e072ed2f78e696"
	maximumSanitizedModelRequestBytes  = (11 << 20)
	maximumSanitizedEgressReceiptBytes = (4 << 20)
	maximumSanitizedFields             = 256
	maximumSanitizedMatches            = 8192
	maximumSanitizedFieldBytes         = 256 << 10
	maximumSanitizedAggregateBytes     = 2 << 20
)

var (
	ErrInvalidSanitizedModelRequest    = errors.New("invalid sanitized model request")
	ErrInvalidSanitizedEgressReceipt   = errors.New("invalid sanitized egress receipt")
	ErrInvalidSanitizedEgressArtifacts = errors.New("invalid sanitized egress artifacts")
)

type FieldRole string

const (
	FieldRoleSourcePath         FieldRole = "source_path"
	FieldRoleSourceContent      FieldRole = "source_content"
	FieldRoleSourceOmissionPath FieldRole = "source_omission_path"
	FieldRoleMemoryPath         FieldRole = "memory_path"
	FieldRoleMemorySymbol       FieldRole = "memory_symbol"
	FieldRoleMemoryText         FieldRole = "memory_text"
	FieldRoleCandidateTitle     FieldRole = "candidate_title"
	FieldRoleCandidateClaim     FieldRole = "candidate_claim"
	FieldRoleCandidatePath      FieldRole = "candidate_path"
)

func (role FieldRole) valid() bool {
	switch role {
	case FieldRoleSourcePath, FieldRoleSourceContent, FieldRoleSourceOmissionPath,
		FieldRoleMemoryPath, FieldRoleMemorySymbol, FieldRoleMemoryText,
		FieldRoleCandidateTitle, FieldRoleCandidateClaim, FieldRoleCandidatePath:
		return true
	default:
		return false
	}
}

type SanitizedModelRequest struct {
	identity            string
	reviewScopeIdentity string
	rawRequestIdentity  string
	request             provider.Request
}

func NewSanitizedModelRequest(reviewScopeIdentity string, raw, sanitized provider.Request) (SanitizedModelRequest, error) {
	value := SanitizedModelRequest{reviewScopeIdentity: reviewScopeIdentity, rawRequestIdentity: raw.Identity(), request: sanitized}
	if raw.Validate() != nil || sanitized.Validate() != nil || raw.Capability() != sanitized.Capability() || raw.MediaType() != "application/json" || sanitized.MediaType() != "application/json" || !validSanitizedPayload(raw.Payload()) || !validSanitizedPayload(sanitized.Payload()) || !validCandidateDigest(reviewScopeIdentity) || !validCandidateDigest(value.rawRequestIdentity) {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	value.identity = deriveSanitizedModelRequestIdentity(value)
	if value.Validate() != nil {
		return SanitizedModelRequest{}, ErrInvalidSanitizedModelRequest
	}
	return value, nil
}

func (value SanitizedModelRequest) Identity() string            { return value.identity }
func (value SanitizedModelRequest) ReviewScopeIdentity() string { return value.reviewScopeIdentity }
func (value SanitizedModelRequest) RawRequestIdentity() string  { return value.rawRequestIdentity }
func (value SanitizedModelRequest) SanitizedRequestIdentity() string {
	request, err := value.providerRequest()
	if err != nil {
		return ""
	}
	return request.Identity()
}
func (value SanitizedModelRequest) SanitizationPolicyIdentity() string {
	return SanitizationPolicyIdentity
}
func (value SanitizedModelRequest) ProviderRequest() (provider.Request, error) {
	if value.Validate() != nil {
		return provider.Request{}, ErrInvalidSanitizedModelRequest
	}
	return value.providerRequest()
}

func (value SanitizedModelRequest) providerRequest() (provider.Request, error) {
	encoded, err := encodeSanitizedModelRequestUnchecked(value)
	if err != nil {
		return provider.Request{}, ErrInvalidSanitizedModelRequest
	}
	return provider.NewRequest(value.request.Capability(), value.request.MediaType(), encoded)
}
func (value SanitizedModelRequest) Validate() error {
	if !validCandidateDigest(value.identity) || !validCandidateDigest(value.reviewScopeIdentity) || !validCandidateDigest(value.rawRequestIdentity) || value.request.Validate() != nil || value.request.Capability() != provider.CapabilityReviewV1 || value.request.MediaType() != "application/json" || !validSanitizedPayload(value.request.Payload()) || !validCandidateDigest(value.request.Identity()) || value.identity != deriveSanitizedModelRequestIdentity(value) {
		return ErrInvalidSanitizedModelRequest
	}
	request, err := value.providerRequest()
	if err != nil || request.Identity() == value.rawRequestIdentity {
		return ErrInvalidSanitizedModelRequest
	}
	return nil
}
func validSanitizedPayload(payload []byte) bool {
	return len(payload) >= 2 && payload[0] == '{' && payload[len(payload)-1] == '}' && rejectAmbiguousModelRequestJSON(payload) == nil
}

func (value SanitizedModelRequest) String() string { return "sanitized model request" }
func (value SanitizedModelRequest) GoString() string {
	return "review.SanitizedModelRequest{<redacted>}"
}
func (value SanitizedModelRequest) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, value.String(), value.GoString())
}

func deriveSanitizedModelRequestIdentity(value SanitizedModelRequest) string {
	digest := sha256.Sum256(mustJSON(struct {
		Contract                   string `json:"contract"`
		SchemaVersion              int    `json:"schema_version"`
		ReviewScopeIdentity        string `json:"review_scope_identity"`
		RawRequestIdentity         string `json:"raw_request_identity"`
		SanitizationPolicyIdentity string `json:"sanitization_policy_identity"`
		Capability                 string `json:"capability"`
		MediaType                  string `json:"media_type"`
		Payload                    []byte `json:"payload"`
	}{"open-trestle/sanitized-model-request", 1, value.reviewScopeIdentity, value.rawRequestIdentity, SanitizationPolicyIdentity, value.request.Capability().String(), value.request.MediaType(), value.request.Payload()}))
	return hex.EncodeToString(digest[:])
}

type ScannerBinaryDigests struct {
	LauncherSHA256 string
	WorkerSHA256   string
}

func (value ScannerBinaryDigests) validate() bool {
	return validNonzeroDigest(value.LauncherSHA256) && validNonzeroDigest(value.WorkerSHA256)
}

type ScannerProfile struct {
	WorkerProtocol   int
	Scanner          string
	ScannerVersion   string
	ScannerCommit    string
	RulesetIdentity  string
	RulesetRuleCount int
	BuildProfile     string
	LauncherSHA256   string
	WorkerSHA256     string
}

type ScanCompletion struct {
	Complete         bool
	FieldCount       int
	ScannedByteCount int
	MatchCount       int
}

type SanitizedField struct {
	Role              FieldRole
	Ordinal           int
	ScannedByteCount  int
	RedactedByteCount int
	Matches           []secretscan.Match
}

type SanitizedEgressReceiptInput struct {
	ReviewScopeIdentity      string
	RawRequestIdentity       string
	SanitizedRequestIdentity string
	Scanner                  ScannerProfile
	Initial                  ScanCompletion
	Residual                 ScanCompletion
	RedactedByteCount        int
	Fields                   []SanitizedField
}

type SanitizedEgressReceipt struct {
	identity                 string
	reviewScopeIdentity      string
	rawRequestIdentity       string
	sanitizedRequestIdentity string
	scanner                  ScannerProfile
	initial                  ScanCompletion
	residual                 ScanCompletion
	redactedByteCount        int
	fields                   []SanitizedField
}

func NewSanitizedEgressReceipt(input SanitizedEgressReceiptInput) (SanitizedEgressReceipt, error) {
	value := SanitizedEgressReceipt{reviewScopeIdentity: input.ReviewScopeIdentity, rawRequestIdentity: input.RawRequestIdentity, sanitizedRequestIdentity: input.SanitizedRequestIdentity, scanner: input.Scanner, initial: input.Initial, residual: input.Residual, redactedByteCount: input.RedactedByteCount, fields: copySanitizedFields(input.Fields)}
	value.identity = deriveSanitizedEgressReceiptIdentity(value)
	if value.Validate() != nil {
		return SanitizedEgressReceipt{}, ErrInvalidSanitizedEgressReceipt
	}
	return value, nil
}
func (value SanitizedEgressReceipt) Identity() string            { return value.identity }
func (value SanitizedEgressReceipt) ReviewScopeIdentity() string { return value.reviewScopeIdentity }
func (value SanitizedEgressReceipt) RawRequestIdentity() string  { return value.rawRequestIdentity }
func (value SanitizedEgressReceipt) SanitizedRequestIdentity() string {
	return value.sanitizedRequestIdentity
}
func (value SanitizedEgressReceipt) SanitizationPolicyIdentity() string {
	return SanitizationPolicyIdentity
}
func (value SanitizedEgressReceipt) Scanner() ScannerProfile  { return value.scanner }
func (value SanitizedEgressReceipt) Initial() ScanCompletion  { return value.initial }
func (value SanitizedEgressReceipt) Residual() ScanCompletion { return value.residual }
func (value SanitizedEgressReceipt) RedactedByteCount() int   { return value.redactedByteCount }
func (value SanitizedEgressReceipt) Fields() []SanitizedField {
	return copySanitizedFields(value.fields)
}
func (value SanitizedEgressReceipt) String() string { return "sanitized egress receipt" }
func (value SanitizedEgressReceipt) GoString() string {
	return "review.SanitizedEgressReceipt{<redacted>}"
}
func (value SanitizedEgressReceipt) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, value.String(), value.GoString())
}

func (value SanitizedEgressReceipt) Validate() error {
	if !validCandidateDigest(value.identity) || !validCandidateDigest(value.reviewScopeIdentity) || !validCandidateDigest(value.rawRequestIdentity) || !validCandidateDigest(value.sanitizedRequestIdentity) || value.rawRequestIdentity == value.sanitizedRequestIdentity || !validScannerProfile(value.scanner) || len(value.fields) < 1 || len(value.fields) > maximumSanitizedFields || value.redactedByteCount < 0 {
		return ErrInvalidSanitizedEgressReceipt
	}
	totalBytes, totalRedacted, totalMatches := 0, 0, 0
	for index, field := range value.fields {
		if field.Ordinal != index || !field.Role.valid() || field.ScannedByteCount < 0 || field.ScannedByteCount > maximumSanitizedFieldBytes || field.RedactedByteCount < 0 || field.RedactedByteCount > field.ScannedByteCount || field.Matches == nil {
			return ErrInvalidSanitizedEgressReceipt
		}
		totalBytes += field.ScannedByteCount
		totalRedacted += field.RedactedByteCount
		totalMatches += len(field.Matches)
		if totalBytes > maximumSanitizedAggregateBytes || totalMatches > maximumSanitizedMatches {
			return ErrInvalidSanitizedEgressReceipt
		}
		previous := secretscan.Match{}
		coveredBytes, coveredEnd := 0, 0
		for matchIndex, match := range field.Matches {
			if match.SourceOrdinal != field.Ordinal || !secretscan.KnownRuleID(match.RuleID) || match.StartByte < 0 || match.EndByteExclusive <= match.StartByte || match.EndByteExclusive > field.ScannedByteCount || match.OccurrenceID != secretscan.OccurrenceID(match) || matchIndex > 0 && compareReceiptMatches(previous, match) >= 0 {
				return ErrInvalidSanitizedEgressReceipt
			}
			if matchIndex == 0 || match.StartByte > coveredEnd {
				coveredBytes += match.EndByteExclusive - match.StartByte
				coveredEnd = match.EndByteExclusive
			} else if match.EndByteExclusive > coveredEnd {
				coveredBytes += match.EndByteExclusive - coveredEnd
				coveredEnd = match.EndByteExclusive
			}
			previous = match
		}
		if field.RedactedByteCount > coveredBytes || len(field.Matches) == 0 && field.RedactedByteCount != 0 {
			return ErrInvalidSanitizedEgressReceipt
		}
	}
	if !value.initial.Complete || !value.residual.Complete || value.initial.FieldCount != len(value.fields) || value.residual.FieldCount != len(value.fields) || value.initial.ScannedByteCount != totalBytes || value.residual.ScannedByteCount != totalBytes || value.initial.MatchCount != totalMatches || value.residual.MatchCount != 0 || value.redactedByteCount != totalRedacted || value.identity != deriveSanitizedEgressReceiptIdentity(value) {
		return ErrInvalidSanitizedEgressReceipt
	}
	return nil
}

func validScannerProfile(profile ScannerProfile) bool {
	return profile.WorkerProtocol == 1 && profile.Scanner == secretscan.ScannerName && profile.ScannerVersion == secretscan.ScannerVersion && profile.ScannerCommit == secretscan.ScannerCommit && profile.RulesetIdentity == secretscan.RulesetIdentity && profile.RulesetRuleCount == secretscan.RulesetRuleCount && secretscan.KnownBuildProfile(profile.BuildProfile) && validNonzeroDigest(profile.LauncherSHA256) && validNonzeroDigest(profile.WorkerSHA256)
}
func validNonzeroDigest(value string) bool {
	return validCandidateDigest(value) && value != strings.Repeat("0", 64)
}
func compareReceiptMatches(left, right secretscan.Match) int {
	if left.StartByte != right.StartByte {
		if left.StartByte < right.StartByte {
			return -1
		}
		return 1
	}
	if left.EndByteExclusive != right.EndByteExclusive {
		if left.EndByteExclusive < right.EndByteExclusive {
			return -1
		}
		return 1
	}
	if left.RuleID != right.RuleID {
		if left.RuleID < right.RuleID {
			return -1
		}
		return 1
	}
	return strings.Compare(left.OccurrenceID, right.OccurrenceID)
}
func copySanitizedFields(fields []SanitizedField) []SanitizedField {
	if fields == nil {
		return nil
	}
	copied := make([]SanitizedField, len(fields))
	for index, field := range fields {
		copied[index] = field
		if field.Matches != nil {
			copied[index].Matches = make([]secretscan.Match, len(field.Matches))
			copy(copied[index].Matches, field.Matches)
		}
	}
	return copied
}
func deriveSanitizedEgressReceiptIdentity(value SanitizedEgressReceipt) string {
	wire := receiptWireValue(value)
	wire.Identity = ""
	digest := sha256.Sum256(mustJSON(wire))
	return hex.EncodeToString(digest[:])
}
func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return encoded
}
