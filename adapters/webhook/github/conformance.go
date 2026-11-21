package github

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/georgejieh/open-trestle/webhook"
)

const (
	runtimeWebhookSecretEncodedBytes   = 64
	runtimeWebhookSecretMinimumSymbols = 12
	runtimeWebhookSecretMaximumPeriod  = 32
)

var (
	// ErrInvalidWebhookConformance identifies an invalid scope or webhook key identifier.
	ErrInvalidWebhookConformance = errors.New("invalid GitHub webhook conformance input")
)

func productionWebhookAllowlist() map[string][]string {
	return map[string][]string{"pull_request": {"opened", "ready_for_review", "reopened", "synchronize"}}
}

// VerifierConfigurationIdentity binds the runtime verifier scope, secret key identifier, and fixed allowlist.
func VerifierConfigurationIdentity(scope webhook.RepositoryScope, keyID string) (string, error) {
	if scope.Validate() != nil || !validWebhookKeyID(keyID) {
		return "", ErrInvalidWebhookConformance
	}
	encoded, err := json.Marshal(struct {
		Contract      string              `json:"contract"`
		SchemaVersion int                 `json:"schema_version"`
		ScopeIdentity string              `json:"scope_identity"`
		TenantID      string              `json:"tenant_id"`
		RepositoryID  string              `json:"repository_id"`
		KeyID         string              `json:"key_id"`
		Algorithm     string              `json:"algorithm"`
		Allowed       map[string][]string `json:"allowed"`
	}{"open-trestle/github-webhook-verifier-configuration", 1, scope.Identity(), scope.TenantID(), scope.RepositoryID(), keyID, "hmac-sha256", productionWebhookAllowlist()})
	if err != nil {
		return "", ErrInvalidWebhookConformance
	}
	return digestWebhookConformance(encoded), nil
}

// ValidateRuntimeSecret enforces the canonical encoded-key policy used by the daemon.
// It validates capacity and rejects trivial structure; entropy provenance remains an operator responsibility.
func ValidateRuntimeSecret(secret []byte) error {
	if len(secret) != runtimeWebhookSecretEncodedBytes {
		return ErrInvalidVerifier
	}
	var seen [16]bool
	distinct := 0
	for _, candidate := range secret {
		index := -1
		switch {
		case candidate >= '0' && candidate <= '9':
			index = int(candidate - '0')
		case candidate >= 'a' && candidate <= 'f':
			index = int(candidate-'a') + 10
		default:
			return ErrInvalidVerifier
		}
		if !seen[index] {
			seen[index] = true
			distinct++
		}
	}
	if distinct < runtimeWebhookSecretMinimumSymbols {
		return ErrInvalidVerifier
	}
	for period := 1; period <= runtimeWebhookSecretMaximumPeriod; period++ {
		repeated := true
		for index := period; index < len(secret); index++ {
			if secret[index] != secret[index%period] {
				repeated = false
				break
			}
		}
		if repeated {
			return ErrInvalidVerifier
		}
	}
	return nil
}

// NewRuntimeVerifier constructs the exact production GitHub allowlist for one repository scope.
func NewRuntimeVerifier(secret []byte, scope webhook.RepositoryScope, keyID string) (*Verifier, error) {
	if ValidateRuntimeSecret(secret) != nil {
		return nil, ErrInvalidVerifier
	}
	identity, err := VerifierConfigurationIdentity(scope, keyID)
	if err != nil {
		return nil, ErrInvalidVerifier
	}
	return NewVerifier(secret, identity, productionWebhookAllowlist())
}

func digestWebhookConformance(value []byte) string {
	digest := sha256.Sum256(append([]byte("open-trestle/github-webhook-conformance/v1\x00"), value...))
	return hex.EncodeToString(digest[:])
}
func validWebhookKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate > 0x7e {
			return false
		}
	}
	return true
}
