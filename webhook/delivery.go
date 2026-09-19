// Package webhook provides verified, deduplicated, crash-safe webhook ingestion contracts.
package webhook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxWebhookPayloadBytes     = 1 << 20
	maxWebhookIdentifierBytes  = 128
	maxWebhookUnixMilliseconds = int64(253_402_300_799_999)
)

var (
	// ErrInvalidRepositoryScope identifies an unsafe tenant or repository boundary.
	ErrInvalidRepositoryScope = errors.New("invalid webhook repository scope")
	// ErrInvalidVerifiedDelivery identifies malformed or unbound verified input.
	ErrInvalidVerifiedDelivery = errors.New("invalid verified webhook delivery")
	// ErrInvalidVerifiedDeliveryIdentity identifies delivery content inconsistent with its identity.
	ErrInvalidVerifiedDeliveryIdentity = errors.New("invalid verified webhook delivery identity")
)

// Source identifies a closed forge webhook protocol.
type Source uint8

const (
	SourceGitHub Source = iota + 1
	SourceGitLab
	SourceBitbucketCloud
	SourceGitea
	SourceForgejo
)

func (s Source) String() string {
	switch s {
	case SourceGitHub:
		return "github"
	case SourceGitLab:
		return "gitlab"
	case SourceBitbucketCloud:
		return "bitbucket_cloud"
	case SourceGitea:
		return "gitea"
	case SourceForgejo:
		return "forgejo"
	default:
		return ""
	}
}
func (s Source) Validate() error {
	if s.String() == "" {
		return ErrInvalidVerifiedDelivery
	}
	return nil
}

// RepositoryScope is the tenant-owned repository boundary before a review run exists.
type RepositoryScope struct{ identity, tenantID, repositoryID string }

func NewRepositoryScope(tenantID, repositoryID string) (RepositoryScope, error) {
	if _, err := audit.NewReviewScope(tenantID, repositoryID, "webhook-scope"); err != nil {
		return RepositoryScope{}, ErrInvalidRepositoryScope
	}
	scope := RepositoryScope{tenantID: strings.Clone(tenantID), repositoryID: strings.Clone(repositoryID)}
	scope.identity = hashWebhookValue(struct {
		TenantID     string `json:"tenant_id"`
		RepositoryID string `json:"repository_id"`
	}{tenantID, repositoryID})
	return scope, nil
}
func (s RepositoryScope) Identity() string     { return s.identity }
func (s RepositoryScope) TenantID() string     { return s.tenantID }
func (s RepositoryScope) RepositoryID() string { return s.repositoryID }
func (s RepositoryScope) Validate() error {
	rebuilt, err := NewRepositoryScope(s.tenantID, s.repositoryID)
	if err != nil {
		return err
	}
	if rebuilt.identity != s.identity {
		return ErrInvalidRepositoryScope
	}
	return nil
}
func (s RepositoryScope) String() string   { return "webhook repository scope" }
func (s RepositoryScope) GoString() string { return "webhook.RepositoryScope{<redacted>}" }

// VerifiedDelivery is immutable payload data admitted by one named signature verifier.
type VerifiedDelivery struct {
	identity, deduplicationKey                                  string
	scope                                                       RepositoryScope
	source                                                      Source
	deliveryID, eventType, action, verifierIdentity, bodyDigest string
	payload                                                     []byte
	receivedAtMillis                                            int64
}

func NewVerifiedDelivery(scope RepositoryScope, source Source, deliveryID, eventType, action, verifierIdentity string, payload []byte, receivedAt time.Time) (VerifiedDelivery, error) {
	receivedAtMillis := receivedAt.UnixMilli()
	validAuthority := scope.Validate() == nil && source.Validate() == nil && validWebhookDigest(verifierIdentity)
	validEvent := validDeliveryIdentifier(deliveryID) && validEventIdentifier(eventType) && validOptionalEventIdentifier(action)
	validPayload := len(payload) > 0 && len(payload) <= maxWebhookPayloadBytes
	validTime := receivedAtMillis > 0 && receivedAtMillis <= maxWebhookUnixMilliseconds
	if !validAuthority || !validEvent || !validPayload || !validTime {
		return VerifiedDelivery{}, firstDeliveryError(scope)
	}
	bodyDigest := hashWebhookBytes(payload)
	delivery := VerifiedDelivery{
		scope: scope, source: source, deliveryID: strings.Clone(deliveryID),
		eventType: strings.Clone(eventType), action: strings.Clone(action),
		verifierIdentity: verifierIdentity, bodyDigest: bodyDigest,
		payload: bytesClone(payload), receivedAtMillis: receivedAtMillis,
	}
	delivery.deduplicationKey = deriveDeduplicationKey(delivery)
	delivery.identity = deriveDeliveryIdentity(delivery)
	return delivery, nil
}
func (d VerifiedDelivery) Identity() string         { return d.identity }
func (d VerifiedDelivery) DeduplicationKey() string { return d.deduplicationKey }
func (d VerifiedDelivery) Scope() RepositoryScope   { return d.scope }
func (d VerifiedDelivery) Source() Source           { return d.source }
func (d VerifiedDelivery) DeliveryID() string       { return d.deliveryID }
func (d VerifiedDelivery) EventType() string        { return d.eventType }
func (d VerifiedDelivery) Action() string           { return d.action }
func (d VerifiedDelivery) VerifierIdentity() string { return d.verifierIdentity }
func (d VerifiedDelivery) BodyDigest() string       { return d.bodyDigest }
func (d VerifiedDelivery) Payload() []byte          { return bytesClone(d.payload) }
func (d VerifiedDelivery) ReceivedAt() time.Time    { return time.UnixMilli(d.receivedAtMillis).UTC() }
func (d VerifiedDelivery) Validate() error {
	rebuilt, err := NewVerifiedDelivery(d.scope, d.source, d.deliveryID, d.eventType, d.action, d.verifierIdentity, d.payload, time.UnixMilli(d.receivedAtMillis))
	if err != nil {
		return err
	}
	if rebuilt.deduplicationKey != d.deduplicationKey || rebuilt.bodyDigest != d.bodyDigest || rebuilt.identity != d.identity {
		return ErrInvalidVerifiedDeliveryIdentity
	}
	return nil
}

// SameContent reports whether two valid observations bind the same delivery content and authority.
// Local receive time is not part of redelivery equivalence.
func (d VerifiedDelivery) SameContent(other VerifiedDelivery) bool {
	if d.Validate() != nil || other.Validate() != nil {
		return false
	}
	return d.scope == other.scope && d.source == other.source && d.deliveryID == other.deliveryID &&
		d.eventType == other.eventType && d.action == other.action &&
		d.verifierIdentity == other.verifierIdentity && d.bodyDigest == other.bodyDigest
}

func (d VerifiedDelivery) String() string   { return "verified webhook delivery" }
func (d VerifiedDelivery) GoString() string { return "webhook.VerifiedDelivery{<redacted>}" }
func (d VerifiedDelivery) Format(state fmt.State, verb rune) {
	formatted := "verified webhook delivery"
	if verb == 'q' {
		formatted = `"verified webhook delivery"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "webhook.VerifiedDelivery{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
func firstDeliveryError(scope RepositoryScope) error {
	if scope.Validate() != nil {
		return ErrInvalidRepositoryScope
	}
	return ErrInvalidVerifiedDelivery
}
func deriveDeduplicationKey(d VerifiedDelivery) string {
	return hashWebhookValue(struct {
		ScopeIdentity string `json:"scope_identity"`
		Source        string `json:"source"`
		DeliveryID    string `json:"delivery_id"`
	}{d.scope.Identity(), d.source.String(), d.deliveryID})
}
func deriveDeliveryIdentity(d VerifiedDelivery) string {
	return hashWebhookValue(struct {
		DeduplicationKey       string `json:"deduplication_key"`
		EventType              string `json:"event_type"`
		Action                 string `json:"action"`
		VerifierIdentity       string `json:"verifier_identity"`
		BodyDigest             string `json:"body_digest"`
		ReceivedAtMilliseconds int64  `json:"received_at_milliseconds"`
	}{d.deduplicationKey, d.eventType, d.action, d.verifierIdentity, d.bodyDigest, d.receivedAtMillis})
}
func validDeliveryIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxWebhookIdentifierBytes || !utf8.ValidString(value) {
		return false
	}
	for index, candidate := range value {
		alphaNumeric := candidate >= 'a' && candidate <= 'z' || candidate >= 'A' && candidate <= 'Z' || candidate >= '0' && candidate <= '9'
		separator := strings.ContainsRune("-_.:", candidate)
		if !alphaNumeric && !(separator && index > 0 && index < len(value)-1) {
			return false
		}
	}
	return true
}
func validEventIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	return validOptionalEventIdentifier(value)
}
func validOptionalEventIdentifier(value string) bool {
	if len(value) > 64 || !utf8.ValidString(value) {
		return false
	}
	for index, candidate := range value {
		alphaNumeric := candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9'
		separator := candidate == '_' || candidate == '-'
		if !alphaNumeric && !(separator && index > 0 && index < len(value)-1) {
			return false
		}
	}
	return true
}
func validWebhookDigest(value string) bool {
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
func hashWebhookBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func hashWebhookValue(value any) string {
	encoded, _ := json.Marshal(value)
	return hashWebhookBytes(encoded)
}
func bytesClone(value []byte) []byte { return append([]byte(nil), value...) }
