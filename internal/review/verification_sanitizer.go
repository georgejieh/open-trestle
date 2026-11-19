package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// VerificationRequestSanitizer creates independent verifier egress authority.
type VerificationRequestSanitizer interface {
	Identity() string
	ExpectedBinaryDigests() ScannerBinaryDigests
	SanitizeVerification(context.Context, provider.Request, string) (SanitizedModelRequest, SanitizedEgressReceipt, error)
}

type FixedVerificationRequestSanitizer struct {
	client   sanitizedScanClient
	identity string
}

// NewFixedVerificationRequestSanitizer returns the verification sanitizer
// that scans through sanitizer. A nil sanitizer refuses every request.
func NewFixedVerificationRequestSanitizer(sanitizer secretscan.Sanitizer) *FixedVerificationRequestSanitizer {
	return newFixedVerificationRequestSanitizer(newHelperScanClient(sanitizer))
}

func newFixedVerificationRequestSanitizer(client sanitizedScanClient) *FixedVerificationRequestSanitizer {
	value := &FixedVerificationRequestSanitizer{client: client}
	value.identity = deriveVerificationRequestSanitizerIdentity(value.ExpectedBinaryDigests())
	return value
}

func (value *FixedVerificationRequestSanitizer) Identity() string {
	if value == nil {
		return ""
	}
	return value.identity
}

func (value *FixedVerificationRequestSanitizer) ExpectedBinaryDigests() ScannerBinaryDigests {
	if value == nil || value.client == nil {
		return ScannerBinaryDigests{}
	}
	return ScannerBinaryDigests{HelperSHA256: value.client.HelperSHA256()}
}

func (value *FixedVerificationRequestSanitizer) SanitizeVerification(ctx context.Context, raw provider.Request, reviewScopeIdentity string) (SanitizedModelRequest, SanitizedEgressReceipt, error) {
	if value == nil || value.client == nil || value.identity != deriveVerificationRequestSanitizerIdentity(value.ExpectedBinaryDigests()) || ctx == nil || ctx.Err() != nil {
		return SanitizedModelRequest{}, SanitizedEgressReceipt{}, sanitizationError(secretscan.FailurePolicy)
	}
	document, err := parseSanitizableRequest(raw, reviewScopeIdentity)
	if err != nil || document.verification == nil || document.generation != nil {
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

func deriveVerificationRequestSanitizerIdentity(expected ScannerBinaryDigests) string {
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Policy   string `json:"policy"`
		Scanner  string `json:"scanner"`
		Profile  string `json:"profile"`
		Helper   string `json:"helper"`
	}{"open-trestle/verification-request-sanitizer", 1, SanitizationPolicyIdentity, secretscan.ScannerName, secretscan.BuildProfile, expected.HelperSHA256})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
