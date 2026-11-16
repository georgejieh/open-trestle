package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

var ErrSanitizedEgressUnavailable = errors.New("sanitized egress unavailable")

type sanitizedEgressError struct{ failure secretscan.FailureClass }

func (value sanitizedEgressError) Error() string { return ErrSanitizedEgressUnavailable.Error() }
func (value sanitizedEgressError) Unwrap() error { return ErrSanitizedEgressUnavailable }

func SanitizedEgressFailure(err error) secretscan.FailureClass {
	var failure sanitizedEgressError
	if errors.As(err, &failure) {
		return failure.failure
	}
	return secretscan.FailurePolicy
}

func sanitizationError(failure secretscan.FailureClass) error {
	if failure == secretscan.FailureNone {
		failure = secretscan.FailurePolicy
	}
	return sanitizedEgressError{failure: failure}
}

// GenerationRequestSanitizer creates the closed generation egress authority.
type GenerationRequestSanitizer interface {
	Identity() string
	ExpectedBinaryDigests() ScannerBinaryDigests
	SanitizeGeneration(context.Context, provider.Request, string) (SanitizedModelRequest, SanitizedEgressReceipt, error)
}

type sanitizedScanProjection interface {
	Complete() bool
	Failure() secretscan.FailureClass
	Sources() [][]byte
	Matches() []secretscan.Match
	Initial() secretscan.ScanMetadata
	Residual() secretscan.ScanMetadata
	MaskedByteCount() int
}

type sanitizedScanClient interface {
	Sanitize(context.Context, [][]byte) sanitizedScanProjection
	BinaryDigests() (string, string)
}

type fixedSecretScanClient struct{ client *secretscan.Client }

func (value fixedSecretScanClient) Sanitize(ctx context.Context, sources [][]byte) sanitizedScanProjection {
	return value.client.Sanitize(ctx, sources)
}
func (value fixedSecretScanClient) BinaryDigests() (string, string) {
	return value.client.BinaryDigests()
}

type FixedGenerationRequestSanitizer struct {
	client   sanitizedScanClient
	identity string
}

func NewFixedGenerationRequestSanitizer() *FixedGenerationRequestSanitizer {
	return newFixedGenerationRequestSanitizer(fixedSecretScanClient{client: secretscan.NewClient()})
}

func newFixedGenerationRequestSanitizer(client sanitizedScanClient) *FixedGenerationRequestSanitizer {
	value := &FixedGenerationRequestSanitizer{client: client}
	value.identity = deriveGenerationRequestSanitizerIdentity(value.ExpectedBinaryDigests())
	return value
}

func (value *FixedGenerationRequestSanitizer) Identity() string {
	if value == nil {
		return ""
	}
	return value.identity
}

func (value *FixedGenerationRequestSanitizer) ExpectedBinaryDigests() ScannerBinaryDigests {
	if value == nil || value.client == nil {
		return ScannerBinaryDigests{}
	}
	launcher, worker := value.client.BinaryDigests()
	return ScannerBinaryDigests{LauncherSHA256: launcher, WorkerSHA256: worker}
}

func (value *FixedGenerationRequestSanitizer) SanitizeGeneration(ctx context.Context, raw provider.Request, reviewScopeIdentity string) (SanitizedModelRequest, SanitizedEgressReceipt, error) {
	if value == nil || value.client == nil || value.identity != deriveGenerationRequestSanitizerIdentity(value.ExpectedBinaryDigests()) || ctx == nil || ctx.Err() != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, sanitizationError(secretscan.FailurePolicy)
	}
	document, err := parseSanitizableRequest(raw, reviewScopeIdentity)
	if err != nil || document.generation == nil || document.verification != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, sanitizationError(secretscan.FailurePolicy)
	}
	if !sanitizableFieldBounds(document) {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, sanitizationError(secretscan.FailureResourceLimit)
	}
	sources := make([][]byte, len(document.fields))
	defer clearSanitizerSources(sources)
	for index, field := range document.fields {
		sources[index] = []byte(*field.value)
	}
	projection := value.client.Sanitize(ctx, sources)
	if !projection.Complete() {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, sanitizationError(projection.Failure())
	}
	return closeSanitizedProjection(raw, reviewScopeIdentity, document, projection, value.ExpectedBinaryDigests())
}

func sanitizableFieldBounds(document sanitizedRequestDocument) bool {
	if len(document.fields) < 1 || len(document.fields) > maximumSanitizedFields {
		return false
	}
	total := 0
	for _, field := range document.fields {
		if field.value == nil || !utf8.ValidString(*field.value) || len(*field.value) > maximumSanitizedFieldBytes || total > maximumSanitizedAggregateBytes-len(*field.value) {
			return false
		}
		total += len(*field.value)
	}
	return true
}

func closeSanitizedProjection(raw provider.Request, reviewScopeIdentity string, document sanitizedRequestDocument, projection sanitizedScanProjection, expected ScannerBinaryDigests) (SanitizedModelRequest, SanitizedEgressReceipt, error) {
	initial, residual := projection.Initial(), projection.Residual()
	if !expected.validate() || !validProjectionMetadata(initial, expected, len(document.fields)) || !validProjectionMetadata(residual, expected, len(document.fields)) || initial.ScannedByteCount != residual.ScannedByteCount || residual.MatchCount != 0 {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	matchesByField := make([][]secretscan.Match, len(document.fields))
	for index := range matchesByField {
		matchesByField[index] = []secretscan.Match{}
	}
	for _, match := range projection.Matches() {
		if match.SourceOrdinal < 0 || match.SourceOrdinal >= len(matchesByField) {
			return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
		}
		matchesByField[match.SourceOrdinal] = append(matchesByField[match.SourceOrdinal], match)
	}
	fields := make([]SanitizedField, len(document.fields))
	totalRedacted := 0
	for index, reference := range document.fields {
		original := []byte(*reference.value)
		_, redacted, ok := sanitizeReceiptField(original, matchesByField[index])
		if !ok {
			return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
		}
		fields[index] = SanitizedField{Role: reference.role, Ordinal: index, ScannedByteCount: len(original), RedactedByteCount: redacted, Matches: matchesByField[index]}
		totalRedacted += redacted
	}
	if totalRedacted != projection.MaskedByteCount() {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	payload, err := projectSanitizedRequestPayload(raw, reviewScopeIdentity, fields)
	if err != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	projectedSources := projection.Sources()
	defer clearSanitizerSources(projectedSources)
	projectedDocument, err := parseSanitizablePayload(payload, raw.Capability(), reviewScopeIdentity)
	if err != nil || len(projectedDocument.fields) != len(projectedSources) {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	for index, field := range projectedDocument.fields {
		if !bytes.Equal([]byte(*field.value), projectedSources[index]) {
			return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
		}
	}
	inner, err := provider.NewRequest(raw.Capability(), raw.MediaType(), payload)
	if err != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	request, err := NewSanitizedModelRequest(reviewScopeIdentity, raw, inner)
	if err != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	receipt, err := NewSanitizedEgressReceipt(SanitizedEgressReceiptInput{
		ReviewScopeIdentity: reviewScopeIdentity, RawRequestIdentity: raw.Identity(), SanitizedRequestIdentity: request.SanitizedRequestIdentity(),
		Scanner:           ScannerProfile{WorkerProtocol: 1, Scanner: initial.Scanner, ScannerVersion: initial.ScannerVersion, ScannerCommit: initial.ScannerCommit, RulesetIdentity: initial.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: initial.BuildProfile, LauncherSHA256: initial.LauncherSHA256, WorkerSHA256: initial.WorkerSHA256},
		Initial:           ScanCompletion{Complete: true, FieldCount: initial.SourceCount, ScannedByteCount: initial.ScannedByteCount, MatchCount: initial.MatchCount},
		Residual:          ScanCompletion{Complete: true, FieldCount: residual.SourceCount, ScannedByteCount: residual.ScannedByteCount, MatchCount: residual.MatchCount},
		RedactedByteCount: totalRedacted, Fields: fields,
	})
	if err != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, ErrSanitizedEgressUnavailable
	}
	return request, receipt, nil
}

func parseSanitizablePayload(payload []byte, capability provider.Capability, reviewScopeIdentity string) (sanitizedRequestDocument, error) {
	request, err := provider.NewRequest(capability, "application/json", payload)
	if err != nil {
		return sanitizedRequestDocument{}, err
	}
	return parseSanitizableRequest(request, reviewScopeIdentity)
}

func validProjectionMetadata(metadata secretscan.ScanMetadata, expected ScannerBinaryDigests, sourceCount int) bool {
	return metadata.Scanner == secretscan.ScannerName && metadata.ScannerVersion == secretscan.ScannerVersion && metadata.ScannerCommit == secretscan.ScannerCommit && metadata.RulesetIdentity == secretscan.RulesetIdentity && metadata.BuildProfile == secretscan.BuildProfile && metadata.LauncherSHA256 == expected.LauncherSHA256 && metadata.WorkerSHA256 == expected.WorkerSHA256 && metadata.SourceCount == sourceCount && metadata.ScannedByteCount >= 0 && metadata.MatchCount >= 0
}

func deriveGenerationRequestSanitizerIdentity(expected ScannerBinaryDigests) string {
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Policy   string `json:"policy"`
		Scanner  string `json:"scanner"`
		Profile  string `json:"profile"`
		Launcher string `json:"launcher"`
		Worker   string `json:"worker"`
	}{"open-trestle/generation-request-sanitizer", 1, SanitizationPolicyIdentity, secretscan.ScannerName, secretscan.BuildProfile, expected.LauncherSHA256, expected.WorkerSHA256})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func clearSanitizerSources(sources [][]byte) {
	for index := range sources {
		clear(sources[index])
	}
	clear(sources)
}
