// Package github verifies and filters GitHub webhook deliveries.
package github

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/webhook"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	minWebhookSecretBytes = 32
	maxWebhookSecretBytes = 512
	maxAllowedEvents      = 64
	maxAllowedActions     = 64
	maxGitHubPayloadBytes = 1 << 20
)

var (
	// ErrInvalidVerifier identifies unsafe secret, identity, or allowlist configuration.
	ErrInvalidVerifier = errors.New("invalid GitHub webhook verifier")
	// ErrInvalidSignature identifies a malformed HMAC-SHA-256 header.
	ErrInvalidSignature = errors.New("invalid GitHub webhook signature")
	// ErrSignatureMismatch identifies payload bytes without configured authority.
	ErrSignatureMismatch = errors.New("GitHub webhook signature mismatch")
	// ErrEventNotAllowed identifies an event outside the configured minimum subscription.
	ErrEventNotAllowed = errors.New("GitHub webhook event not allowed")
	// ErrActionNotAllowed identifies an event action outside the allowlist.
	ErrActionNotAllowed = errors.New("GitHub webhook action not allowed")
	// ErrInvalidPayload identifies malformed or ambiguous action JSON.
	ErrInvalidPayload = errors.New("invalid GitHub webhook payload")
)

// Verifier authenticates exact payload bytes and applies a closed event/action allowlist.
type Verifier struct {
	mu       sync.RWMutex
	secret   []byte
	identity string
	allowed  map[string][]string
	closed   bool
}

func NewVerifier(secret []byte, identity string, allowed map[string][]string) (*Verifier, error) {
	if len(secret) < minWebhookSecretBytes || len(secret) > maxWebhookSecretBytes || !validDigest(identity) || len(allowed) == 0 || len(allowed) > maxAllowedEvents {
		return nil, ErrInvalidVerifier
	}
	canonical := make(map[string][]string, len(allowed))
	for event, actions := range allowed {
		if !validName(event, false) || len(actions) == 0 || len(actions) > maxAllowedActions {
			return nil, ErrInvalidVerifier
		}
		values := append([]string(nil), actions...)
		sort.Strings(values)
		for index, action := range values {
			if !validName(action, true) || index > 0 && action == values[index-1] {
				return nil, ErrInvalidVerifier
			}
		}
		canonical[event] = values
	}
	return &Verifier{secret: append([]byte(nil), secret...), identity: identity, allowed: canonical}, nil
}
func (v *Verifier) Identity() string {
	if v == nil {
		return ""
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return ""
	}
	return v.identity
}

// Close clears the retained webhook secret and permanently disables verification.
func (v *Verifier) Close() error {
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	clear(v.secret)
	v.closed = true
	return nil
}
func (v *Verifier) Verify(scope webhook.RepositoryScope, deliveryID, eventType, signature string, payload []byte, receivedAt time.Time) (webhook.VerifiedDelivery, error) {
	if v == nil {
		return webhook.VerifiedDelivery{}, ErrInvalidVerifier
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return webhook.VerifiedDelivery{}, ErrInvalidVerifier
	}
	if len(payload) == 0 || len(payload) > maxGitHubPayloadBytes {
		return webhook.VerifiedDelivery{}, ErrInvalidPayload
	}
	if err := verifySignature(v.secret, signature, payload); err != nil {
		return webhook.VerifiedDelivery{}, err
	}
	actions, allowed := v.allowed[eventType]
	if !allowed {
		return webhook.VerifiedDelivery{}, ErrEventNotAllowed
	}
	action := ""
	needsAction := len(actions) != 1 || actions[0] != ""
	if needsAction {
		extracted, extractErr := extractAction(payload)
		if extractErr != nil {
			return webhook.VerifiedDelivery{}, extractErr
		}
		action = extracted
	}
	index := sort.SearchStrings(actions, action)
	if index == len(actions) || actions[index] != action {
		return webhook.VerifiedDelivery{}, ErrActionNotAllowed
	}
	return webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, deliveryID, eventType, action, v.identity, payload, receivedAt)
}
func (v *Verifier) String() string   { return "GitHub webhook verifier" }
func (v *Verifier) GoString() string { return "github.Verifier{<redacted>}" }
func (v *Verifier) Format(state fmt.State, verb rune) {
	formatted := "GitHub webhook verifier"
	if verb == 'q' {
		formatted = `"GitHub webhook verifier"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "github.Verifier{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
func verifySignature(secret []byte, signature string, payload []byte) error {
	provided, err := parseSignature(signature)
	if err != nil {
		return err
	}
	expected := hmac.New(sha256.New, secret)
	_, _ = expected.Write(payload)
	if !hmac.Equal(provided, expected.Sum(nil)) {
		return ErrSignatureMismatch
	}
	return nil
}

func parseSignature(value string) ([]byte, error) {
	if len(value) != len("sha256=")+sha256.Size*2 || !strings.HasPrefix(value, "sha256=") {
		return nil, ErrInvalidSignature
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256="))
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrInvalidSignature
	}
	return decoded, nil
}
func extractAction(payload []byte) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "", ErrInvalidPayload
	}
	found := false
	action := ""
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		key, ok := keyToken.(string)
		if tokenErr != nil || !ok {
			return "", ErrInvalidPayload
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return "", ErrInvalidPayload
		}
		if key == "action" {
			if found {
				return "", ErrInvalidPayload
			}
			if err := json.Unmarshal(value, &action); err != nil || !validName(action, false) {
				return "", ErrInvalidPayload
			}
			found = true
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !found {
		return "", ErrInvalidPayload
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", ErrInvalidPayload
	}
	return action, nil
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return false
	}
	nonzero := byte(0)
	for _, candidate := range decoded {
		nonzero |= candidate
	}
	return nonzero != 0
}
func validName(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > 64 {
		return false
	}
	for _, candidate := range value {
		if candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '_' || candidate == '-' {
			continue
		}
		return false
	}
	return true
}
