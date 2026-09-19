// Package artifact defines scoped, content-addressed runtime objects for durable task exchange.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"mime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxPayloadBytes             = 16 << 20
	maxProvenance               = 32
	maxArtifactUnixMilliseconds = int64(253_402_300_799_999)
	maxRetentionDuration        = 10 * 365 * 24 * time.Hour
)

var (
	// ErrInvalidArtifact identifies malformed scope, metadata, retention, or payload.
	ErrInvalidArtifact = errors.New("invalid runtime artifact")
	// ErrInvalidArtifactIdentity identifies content inconsistent with its identity.
	ErrInvalidArtifactIdentity = errors.New("invalid runtime artifact identity")
)

// Kind identifies one closed task-exchange object class.
type Kind uint8

const (
	KindSourceSnapshot Kind = iota + 1
	KindChangeModel
	KindDeterministicEvidence
	KindRetrievalResult
	KindContextPacket
	KindCandidateBatch
	KindVerificationBatch
	KindVerifiedFindingSet
	KindPublicationPlan
	KindRunExport
	KindTaskInput
	KindWebhookDelivery
	KindSourceFile
	KindPublicationReceipt
	KindInvestigationTurn
	KindInvestigationToolResult
)

func (k Kind) String() string {
	switch k {
	case KindSourceSnapshot:
		return "source_snapshot"
	case KindChangeModel:
		return "change_model"
	case KindDeterministicEvidence:
		return "deterministic_evidence"
	case KindRetrievalResult:
		return "retrieval_result"
	case KindContextPacket:
		return "context_packet"
	case KindCandidateBatch:
		return "candidate_batch"
	case KindVerificationBatch:
		return "verification_batch"
	case KindVerifiedFindingSet:
		return "verified_finding_set"
	case KindPublicationPlan:
		return "publication_plan"
	case KindRunExport:
		return "run_export"
	case KindTaskInput:
		return "task_input"
	case KindWebhookDelivery:
		return "webhook_delivery"
	case KindSourceFile:
		return "source_file"
	case KindPublicationReceipt:
		return "publication_receipt"
	case KindInvestigationTurn:
		return "investigation_turn"
	case KindInvestigationToolResult:
		return "investigation_tool_result"
	default:
		return ""
	}
}

// Classification identifies handling policy without inferring authority from content.
type Classification uint8

const (
	ClassificationPublic Classification = iota + 1
	ClassificationInternal
	ClassificationConfidential
	ClassificationRestricted
)

func (c Classification) String() string {
	switch c {
	case ClassificationPublic:
		return "public"
	case ClassificationInternal:
		return "internal"
	case ClassificationConfidential:
		return "confidential"
	case ClassificationRestricted:
		return "restricted"
	default:
		return ""
	}
}

// Origin identifies the trust boundary that produced an artifact.
type Origin uint8

const (
	OriginHost Origin = iota + 1
	OriginRepository
	OriginDeterministicTool
	OriginModel
	OriginIndependentVerifier
	OriginPolicy
	OriginMemory
)

func (o Origin) String() string {
	switch o {
	case OriginHost:
		return "host"
	case OriginRepository:
		return "repository"
	case OriginDeterministicTool:
		return "deterministic_tool"
	case OriginModel:
		return "model"
	case OriginIndependentVerifier:
		return "independent_verifier"
	case OriginPolicy:
		return "policy"
	case OriginMemory:
		return "memory"
	default:
		return ""
	}
}

// Protection identifies the storage adapter's declared at-rest protection.
type Protection uint8

const (
	ProtectionProcessPrivate Protection = iota + 1
	ProtectionEnvelopeEncrypted
)

func (p Protection) String() string {
	switch p {
	case ProtectionProcessPrivate:
		return "process_private"
	case ProtectionEnvelopeEncrypted:
		return "envelope_encrypted"
	default:
		return ""
	}
}

// Artifact is immutable payload plus bounded tenant and provenance metadata.
type Artifact struct {
	identity, payloadDigest, mediaType string
	scope                              audit.ReviewScope
	kind                               Kind
	classification                     Classification
	origin                             Origin
	protection                         Protection
	provenance                         []string
	payload                            []byte
	createdAtMillis, expiresAtMillis   int64
}

func New(
	scope audit.ReviewScope,
	kind Kind,
	mediaType string,
	classification Classification,
	origin Origin,
	protection Protection,
	provenance []string,
	payload []byte,
	createdAt, expiresAt time.Time,
) (Artifact, error) {
	createdMillis, expiresMillis := createdAt.UnixMilli(), expiresAt.UnixMilli()
	canonicalProvenance := append([]string(nil), provenance...)
	sort.Strings(canonicalProvenance)
	validMetadata := scope.Validate() == nil && kind.String() != "" && validMediaType(mediaType) && classification.String() != "" && origin.String() != "" && protection.String() != ""
	validPayload := len(payload) > 0 && len(payload) <= maxPayloadBytes
	validTime := createdMillis > 0 && expiresMillis > createdMillis && expiresMillis <= maxArtifactUnixMilliseconds && expiresAt.Sub(createdAt) <= maxRetentionDuration
	if !validMetadata || !validPayload || !validTime || len(canonicalProvenance) == 0 || len(canonicalProvenance) > maxProvenance {
		return Artifact{}, ErrInvalidArtifact
	}
	for index, value := range canonicalProvenance {
		if !validDigest(value) || index > 0 && value == canonicalProvenance[index-1] {
			return Artifact{}, ErrInvalidArtifact
		}
	}
	artifact := Artifact{
		scope: scope, kind: kind, mediaType: mediaType,
		classification: classification, origin: origin, protection: protection,
		provenance: canonicalProvenance, payload: append([]byte(nil), payload...),
		payloadDigest: hashBytes(payload), createdAtMillis: createdMillis, expiresAtMillis: expiresMillis,
	}
	artifact.identity = deriveIdentity(artifact)
	return artifact, nil
}
func (a Artifact) Identity() string               { return a.identity }
func (a Artifact) Scope() audit.ReviewScope       { return a.scope }
func (a Artifact) Kind() Kind                     { return a.kind }
func (a Artifact) MediaType() string              { return a.mediaType }
func (a Artifact) Classification() Classification { return a.classification }
func (a Artifact) Origin() Origin                 { return a.origin }
func (a Artifact) Protection() Protection         { return a.protection }
func (a Artifact) Provenance() []string           { return append([]string(nil), a.provenance...) }
func (a Artifact) PayloadDigest() string          { return a.payloadDigest }
func (a Artifact) Payload() []byte                { return append([]byte(nil), a.payload...) }
func (a Artifact) CreatedAt() time.Time           { return time.UnixMilli(a.createdAtMillis).UTC() }
func (a Artifact) ExpiresAt() time.Time           { return time.UnixMilli(a.expiresAtMillis).UTC() }
func (a Artifact) Validate() error {
	rebuilt, err := New(a.scope, a.kind, a.mediaType, a.classification, a.origin, a.protection, a.provenance, a.payload, time.UnixMilli(a.createdAtMillis), time.UnixMilli(a.expiresAtMillis))
	if err != nil {
		return err
	}
	if rebuilt.payloadDigest != a.payloadDigest || rebuilt.identity != a.identity {
		return ErrInvalidArtifactIdentity
	}
	return nil
}
func (a Artifact) String() string   { return "runtime artifact" }
func (a Artifact) GoString() string { return "artifact.Artifact{<redacted>}" }
func (a Artifact) Format(state fmt.State, verb rune) {
	value := "runtime artifact"
	if verb == 'q' {
		value = `"runtime artifact"`
	} else if verb == 'v' && state.Flag('#') {
		value = "artifact.Artifact{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}
func deriveIdentity(a Artifact) string {
	return hashValue(struct {
		ScopeIdentity         string   `json:"scope_identity"`
		Kind                  string   `json:"kind"`
		MediaType             string   `json:"media_type"`
		Classification        string   `json:"classification"`
		Origin                string   `json:"origin"`
		Protection            string   `json:"protection"`
		Provenance            []string `json:"provenance"`
		PayloadDigest         string   `json:"payload_digest"`
		CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
		ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
	}{a.scope.Identity(), a.kind.String(), a.mediaType, a.classification.String(), a.origin.String(), a.protection.String(), a.provenance, a.payloadDigest, a.createdAtMillis, a.expiresAtMillis})
}
func validMediaType(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	parsed, parameters, err := mime.ParseMediaType(value)
	return err == nil && len(parameters) == 0 && parsed == value && strings.Contains(value, "/")
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value && strings.Trim(value, "0") != ""
}
func hashBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
func hashValue(value any) string { encoded, _ := json.Marshal(value); return hashBytes(encoded) }
