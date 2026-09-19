package artifact

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

var (
	// ErrInvalidErasureContract identifies malformed or noncanonical metadata.
	ErrInvalidErasureContract = errors.New("invalid erasure contract")
	// ErrErasureIdentityMismatch identifies well-shaped metadata with a wrong identity.
	ErrErasureIdentityMismatch = errors.New("erasure identity mismatch")
)

// StorageNamespace is immutable storage namespace metadata, not storage authority.
// Its zero value is invalid.
type StorageNamespace struct {
	identity                     string
	backendConfigurationIdentity string
	prefix                       string
	namespaceEpochIdentity       string
}

func NewStorageNamespace(backendConfigurationIdentity, prefix, namespaceEpochIdentity string) (StorageNamespace, error) {
	if !validDigest(backendConfigurationIdentity) || !validStoragePrefix(prefix) || !validDigest(namespaceEpochIdentity) {
		return StorageNamespace{}, ErrInvalidErasureContract
	}
	value := StorageNamespace{
		backendConfigurationIdentity: strings.Clone(backendConfigurationIdentity),
		prefix:                       strings.Clone(prefix),
		namespaceEpochIdentity:       strings.Clone(namespaceEpochIdentity),
	}
	value.identity = deriveStorageNamespaceIdentity(value)
	return value, nil
}

func (n StorageNamespace) Identity() string { return n.identity }
func (n StorageNamespace) BackendConfigurationIdentity() string {
	return n.backendConfigurationIdentity
}
func (n StorageNamespace) Prefix() string                 { return n.prefix }
func (n StorageNamespace) NamespaceEpochIdentity() string { return n.namespaceEpochIdentity }

func (n StorageNamespace) Validate() error {
	if !n.validFields() || !validDigest(n.identity) {
		return ErrInvalidErasureContract
	}
	if n.identity != deriveStorageNamespaceIdentity(n) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (n StorageNamespace) validFields() bool {
	return validDigest(n.backendConfigurationIdentity) && validDigest(n.namespaceEpochIdentity) && validStoragePrefix(n.prefix)
}

func validStoragePrefix(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > 128 || prefix[0] == '/' || prefix[len(prefix)-1] == '/' {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c == '/' {
			if i > 0 && prefix[i-1] == '/' {
				return false
			}
		} else if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (n StorageNamespace) String() string   { return "artifact storage namespace" }
func (n StorageNamespace) GoString() string { return "artifact.StorageNamespace{<redacted>}" }
func (n StorageNamespace) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, n.String(), n.GoString())
}

// ArtifactAdmission is immutable metadata shape, not journal acceptance, custody,
// a dispatch permit, protected authority, or erasure proof. It contains no payload.
// Its zero value is invalid.
type ArtifactAdmission struct {
	identity, namespaceIdentity, artifactIdentity      string
	scope                                              audit.ReviewScope
	kind                                               Kind
	mediaType                                          string
	classification                                     Classification
	origin                                             Origin
	protection                                         Protection
	provenance                                         []string
	payloadDigest                                      string
	createdAtMillis, expiresAtMillis, admittedAtMillis int64
}

// NewArtifactAdmission validates the actual artifact once, then copies only metadata.
// The supplied instant must have zero UTC offset and exact millisecond precision.
func NewArtifactAdmission(value Artifact, namespaceIdentity string, at time.Time) (ArtifactAdmission, error) {
	if err := value.Validate(); err != nil {
		return ArtifactAdmission{}, ErrInvalidArtifact
	}
	_, offset := at.Zone()
	// Bound the calendar before UnixMilli, which can overflow for extreme times.
	if !validDigest(namespaceIdentity) || offset != 0 || at.Year() < 1970 || at.Year() > 9999 || at.Nanosecond()%int(time.Millisecond) != 0 {
		return ArtifactAdmission{}, ErrInvalidErasureContract
	}
	admission := ArtifactAdmission{
		namespaceIdentity: strings.Clone(namespaceIdentity), artifactIdentity: value.Identity(),
		scope: value.Scope(), kind: value.Kind(), mediaType: value.MediaType(),
		classification: value.Classification(), origin: value.Origin(), protection: value.Protection(),
		provenance: value.Provenance(), payloadDigest: value.PayloadDigest(),
		createdAtMillis: value.CreatedAt().UnixMilli(), expiresAtMillis: value.ExpiresAt().UnixMilli(),
		admittedAtMillis: at.UnixMilli(),
	}
	if err := admission.validateFields(); err != nil {
		return ArtifactAdmission{}, err
	}
	admission.identity = deriveArtifactAdmissionIdentity(admission)
	if err := admission.Validate(); err != nil {
		return ArtifactAdmission{}, err
	}
	return admission, nil
}

func (a ArtifactAdmission) Identity() string               { return a.identity }
func (a ArtifactAdmission) NamespaceIdentity() string      { return a.namespaceIdentity }
func (a ArtifactAdmission) Scope() audit.ReviewScope       { return a.scope }
func (a ArtifactAdmission) ArtifactIdentity() string       { return a.artifactIdentity }
func (a ArtifactAdmission) Kind() Kind                     { return a.kind }
func (a ArtifactAdmission) MediaType() string              { return a.mediaType }
func (a ArtifactAdmission) Classification() Classification { return a.classification }
func (a ArtifactAdmission) Origin() Origin                 { return a.origin }
func (a ArtifactAdmission) Protection() Protection         { return a.protection }
func (a ArtifactAdmission) Provenance() []string           { return append([]string(nil), a.provenance...) }
func (a ArtifactAdmission) PayloadDigest() string          { return a.payloadDigest }
func (a ArtifactAdmission) CreatedAt() time.Time           { return erasureValueTime(a.createdAtMillis) }
func (a ArtifactAdmission) ExpiresAt() time.Time           { return erasureValueTime(a.expiresAtMillis) }
func (a ArtifactAdmission) AdmittedAt() time.Time          { return erasureValueTime(a.admittedAtMillis) }

func erasureValueTime(milliseconds int64) time.Time {
	if milliseconds == 0 {
		return time.Time{}
	}
	return time.UnixMilli(milliseconds).UTC()
}

// Validate checks persisted metadata relationships without sampling the clock.
func (a ArtifactAdmission) Validate() error {
	if err := a.validateFields(); err != nil {
		return err
	}
	if !validDigest(a.identity) {
		return ErrInvalidErasureContract
	}
	if a.scope.Validate() != nil || a.artifactIdentity != deriveAdmissionOriginalIdentity(a) || a.identity != deriveArtifactAdmissionIdentity(a) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (a ArtifactAdmission) validateFields() error {
	if !validDigest(a.namespaceIdentity) || !validDigest(a.artifactIdentity) || !validDigest(a.scope.Identity()) || !validDigest(a.payloadDigest) ||
		a.kind.String() == "" || !validMediaType(a.mediaType) || a.classification.String() == "" || a.origin.String() == "" || a.protection.String() == "" ||
		len(a.provenance) == 0 || len(a.provenance) > maxProvenance {
		return ErrInvalidErasureContract
	}
	if _, err := audit.NewReviewScope(a.scope.TenantID(), a.scope.RepositoryID(), a.scope.ReviewRunID()); err != nil {
		return ErrInvalidErasureContract
	}
	for i, identity := range a.provenance {
		if !validDigest(identity) || i > 0 && identity <= a.provenance[i-1] {
			return ErrInvalidErasureContract
		}
	}
	// Check each bound before subtraction; do not multiply untrusted milliseconds.
	if a.createdAtMillis <= 0 || a.createdAtMillis > maxArtifactUnixMilliseconds ||
		a.expiresAtMillis <= 0 || a.expiresAtMillis > maxArtifactUnixMilliseconds ||
		a.admittedAtMillis <= 0 || a.admittedAtMillis > maxArtifactUnixMilliseconds {
		return ErrInvalidErasureContract
	}
	if a.expiresAtMillis <= a.createdAtMillis || a.expiresAtMillis-a.createdAtMillis > maxRetentionDuration.Milliseconds() ||
		a.admittedAtMillis < a.createdAtMillis || a.admittedAtMillis >= a.expiresAtMillis {
		return ErrInvalidErasureContract
	}
	return nil
}

func (a ArtifactAdmission) String() string   { return "artifact admission" }
func (a ArtifactAdmission) GoString() string { return "artifact.ArtifactAdmission{<redacted>}" }
func (a ArtifactAdmission) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, a.String(), a.GoString())
}

func formatErasureValue(state fmt.State, verb rune, value, goValue string) {
	if verb == 'q' {
		value = `"` + value + `"`
	} else if verb == 'v' && state.Flag('#') {
		value = goValue
	}
	_, _ = state.Write([]byte(value))
}
