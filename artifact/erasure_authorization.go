package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/erasureauthority"
)

var (
	// ErrErasureAuthorityRequired identifies missing or invalid protected snapshots.
	ErrErasureAuthorityRequired = errors.New("erasure authority required")
	// ErrErasureBindingMismatch identifies inconsistent authorization or policy bindings.
	ErrErasureBindingMismatch = errors.New("erasure binding mismatch")
	// ErrErasureLegacyInventoryRequired refuses legacy lineage without inventory authority.
	ErrErasureLegacyInventoryRequired = errors.New("erasure legacy inventory required")
)

const erasureAuthorizationV2Ownership = "all_versions_at_exact_key"

// ProtectedErasurePolicy is an immutable configured-local policy snapshot.
// It does not prove live provider configuration or permission for an effect.
type ProtectedErasurePolicy = erasureauthority.Policy

// LoadProtectedErasurePolicy delegates to the protected loader for an explicit path.
func LoadProtectedErasurePolicy(ctx context.Context, path string) (ProtectedErasurePolicy, error) {
	policy, err := erasureauthority.LoadPolicy(ctx, path)
	if err != nil {
		return ProtectedErasurePolicy{}, ErrErasureAuthorityRequired
	}
	return policy, nil
}

// ErasureAuthorizationV2Options describes canonical metadata, not protected authority.
type ErasureAuthorizationV2Options struct {
	Scope                        audit.ReviewScope
	NamespaceIdentity            string
	ArtifactIdentity             string
	AdmissionIdentity            string
	PolicyIdentity               string
	PrincipalIdentity            string
	HoldClearanceIdentity        string
	FenceRetentionPolicyIdentity string
	LegacyReceiptIdentity        string
	Reason                       DeletionReason
	IssuedAt                     time.Time
	ExpiresAt                    time.Time
}

// ErasureAuthorizationV2 is immutable authorization metadata. Only a protected
// document load attaches a witness. Its zero value is invalid. Neither shape
// nor witness is journal acceptance, custody, or permission to perform an effect.
type ErasureAuthorizationV2 struct {
	identity, namespaceIdentity, artifactIdentity, admissionIdentity string
	policyIdentity, principalIdentity, holdClearanceIdentity         string
	ownership, fenceRetentionPolicyIdentity, legacyReceiptIdentity   string
	scope                                                            audit.ReviewScope
	reason                                                           DeletionReason
	issuedAtMillis, expiresAtMillis                                  int64
	witness                                                          *erasureAuthorizationV2Witness
}

// Only LoadErasureAuthorizationV2 constructs this witness. The protected
// Document and all bindings are immutable and retain no pathname authority.
type erasureAuthorizationV2Witness struct {
	document              erasureauthority.Document
	documentDigest        string
	policyIdentity        string
	authorizationIdentity string
}

// NewErasureAuthorizationV2 copies validated shape without minting a witness.
func NewErasureAuthorizationV2(options ErasureAuthorizationV2Options) (ErasureAuthorizationV2, error) {
	if !validErasureAuthorizationV2Time(options.IssuedAt) || !validErasureAuthorizationV2Time(options.ExpiresAt) {
		return ErasureAuthorizationV2{}, ErrInvalidErasureContract
	}
	value := ErasureAuthorizationV2{
		scope: options.Scope, namespaceIdentity: options.NamespaceIdentity,
		artifactIdentity: options.ArtifactIdentity, admissionIdentity: options.AdmissionIdentity,
		policyIdentity: options.PolicyIdentity, principalIdentity: options.PrincipalIdentity,
		holdClearanceIdentity: options.HoldClearanceIdentity, ownership: erasureAuthorizationV2Ownership,
		fenceRetentionPolicyIdentity: options.FenceRetentionPolicyIdentity, legacyReceiptIdentity: options.LegacyReceiptIdentity,
		reason: options.Reason, issuedAtMillis: options.IssuedAt.UnixMilli(), expiresAtMillis: options.ExpiresAt.UnixMilli(),
	}
	if err := value.validateFields(); err != nil {
		return ErasureAuthorizationV2{}, err
	}
	if value.scope.Validate() != nil {
		return ErasureAuthorizationV2{}, ErrErasureIdentityMismatch
	}
	// ReviewScope's constructor clones its strings; all remaining caller strings
	// are copied only after their bounds have been checked.
	scope, err := audit.NewReviewScope(value.scope.TenantID(), value.scope.RepositoryID(), value.scope.ReviewRunID())
	if err != nil {
		return ErasureAuthorizationV2{}, ErrInvalidErasureContract
	}
	value.scope = scope
	value.namespaceIdentity = strings.Clone(value.namespaceIdentity)
	value.artifactIdentity = strings.Clone(value.artifactIdentity)
	value.admissionIdentity = strings.Clone(value.admissionIdentity)
	value.policyIdentity = strings.Clone(value.policyIdentity)
	value.principalIdentity = strings.Clone(value.principalIdentity)
	value.holdClearanceIdentity = strings.Clone(value.holdClearanceIdentity)
	value.fenceRetentionPolicyIdentity = strings.Clone(value.fenceRetentionPolicyIdentity)
	value.legacyReceiptIdentity = strings.Clone(value.legacyReceiptIdentity)
	value.identity = deriveErasureAuthorizationV2Identity(value)
	return value, nil
}

func validErasureAuthorizationV2Time(instant time.Time) bool {
	_, offset := instant.Zone()
	// Bound the calendar before UnixMilli, which can overflow for extreme times.
	if offset != 0 || instant.Year() < 1970 || instant.Year() > 9999 || instant.Nanosecond()%int(time.Millisecond) != 0 {
		return false
	}
	milliseconds := instant.UnixMilli()
	return milliseconds > 0 && milliseconds <= maxArtifactUnixMilliseconds
}

func (a ErasureAuthorizationV2) Identity() string              { return a.identity }
func (a ErasureAuthorizationV2) Scope() audit.ReviewScope      { return a.scope }
func (a ErasureAuthorizationV2) NamespaceIdentity() string     { return a.namespaceIdentity }
func (a ErasureAuthorizationV2) ArtifactIdentity() string      { return a.artifactIdentity }
func (a ErasureAuthorizationV2) AdmissionIdentity() string     { return a.admissionIdentity }
func (a ErasureAuthorizationV2) PolicyIdentity() string        { return a.policyIdentity }
func (a ErasureAuthorizationV2) PrincipalIdentity() string     { return a.principalIdentity }
func (a ErasureAuthorizationV2) HoldClearanceIdentity() string { return a.holdClearanceIdentity }
func (a ErasureAuthorizationV2) Ownership() string             { return a.ownership }
func (a ErasureAuthorizationV2) FenceRetentionPolicyIdentity() string {
	return a.fenceRetentionPolicyIdentity
}
func (a ErasureAuthorizationV2) LegacyReceiptIdentity() string { return a.legacyReceiptIdentity }
func (a ErasureAuthorizationV2) Reason() DeletionReason        { return a.reason }
func (a ErasureAuthorizationV2) IssuedAt() time.Time           { return erasureValueTime(a.issuedAtMillis) }
func (a ErasureAuthorizationV2) ExpiresAt() time.Time          { return erasureValueTime(a.expiresAtMillis) }

// Validate checks historical shape and identities, never the clock or protected permission.
func (a ErasureAuthorizationV2) Validate() error {
	if err := a.validateFields(); err != nil {
		return err
	}
	if !validDigest(a.identity) {
		return ErrInvalidErasureContract
	}
	if a.scope.Validate() != nil || a.identity != deriveErasureAuthorizationV2Identity(a) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func (a ErasureAuthorizationV2) validateFields() error {
	for _, identity := range [...]string{
		a.namespaceIdentity, a.scope.Identity(), a.artifactIdentity, a.admissionIdentity,
		a.policyIdentity, a.principalIdentity, a.holdClearanceIdentity, a.fenceRetentionPolicyIdentity,
	} {
		if !validDigest(identity) {
			return ErrInvalidErasureContract
		}
	}
	if a.legacyReceiptIdentity != "" && !validDigest(a.legacyReceiptIdentity) ||
		a.ownership != erasureAuthorizationV2Ownership || a.reason.String() == "" {
		return ErrInvalidErasureContract
	}
	if _, err := audit.NewReviewScope(a.scope.TenantID(), a.scope.RepositoryID(), a.scope.ReviewRunID()); err != nil {
		return ErrInvalidErasureContract
	}
	// Bound both integers before subtraction; no duration multiplication is needed.
	if a.issuedAtMillis <= 0 || a.issuedAtMillis > maxArtifactUnixMilliseconds ||
		a.expiresAtMillis <= 0 || a.expiresAtMillis > maxArtifactUnixMilliseconds {
		return ErrInvalidErasureContract
	}
	if a.expiresAtMillis <= a.issuedAtMillis || a.expiresAtMillis-a.issuedAtMillis > maxDeletionAuthorizationLifetime.Milliseconds() {
		return ErrInvalidErasureContract
	}
	return nil
}

// AllowsAdmission is only a metadata/time predicate, including for unminted
// shapes. Effect callers must separately ValidateProtected and check policy.AllowsAt
// at their captured instant. This method does not infer hold or provider clearance.
func (a ErasureAuthorizationV2) AllowsAdmission(admission ArtifactAdmission, at time.Time) bool {
	if a.Validate() != nil || admission.Validate() != nil || a.scope != admission.Scope() ||
		a.namespaceIdentity != admission.NamespaceIdentity() || a.artifactIdentity != admission.ArtifactIdentity() ||
		a.admissionIdentity != admission.Identity() || admission.Protection() != ProtectionEnvelopeEncrypted {
		return false
	}
	if at.Before(a.IssuedAt()) || !at.Before(a.ExpiresAt()) {
		return false
	}
	return a.reason != DeletionExpired || !at.Before(admission.ExpiresAt())
}

// LoadErasureAuthorizationV2 loads an explicit protected grant snapshot, without
// sampling time or requiring overlap with the policy's separate validity window.
func LoadErasureAuthorizationV2(ctx context.Context, path string, policy ProtectedErasurePolicy) (ErasureAuthorizationV2, error) {
	if ctx == nil || ctx.Err() != nil || policy.Validate() != nil {
		return ErasureAuthorizationV2{}, ErrErasureAuthorityRequired
	}
	document, err := erasureauthority.LoadDocument(ctx, path)
	if err != nil {
		return ErasureAuthorizationV2{}, ErrErasureAuthorityRequired
	}
	encoded := document.Bytes()
	// The protected raw document's 16 KiB bound is not the authorization bound.
	if len(encoded) > maxEncodedErasureAuthorizationV2Bytes {
		return ErasureAuthorizationV2{}, ErrInvalidErasureContract
	}
	value, err := ParseErasureAuthorizationV2(encoded)
	if err != nil {
		return ErasureAuthorizationV2{}, err
	}
	if !value.matchesProtectedPolicy(policy) {
		return ErasureAuthorizationV2{}, ErrErasureBindingMismatch
	}
	if value.legacyReceiptIdentity != "" {
		return ErasureAuthorizationV2{}, ErrErasureLegacyInventoryRequired
	}
	value.witness = &erasureAuthorizationV2Witness{
		document: document, documentDigest: document.Digest(),
		policyIdentity: policy.Identity(), authorizationIdentity: value.identity,
	}
	if ctx.Err() != nil {
		return ErasureAuthorizationV2{}, ErrErasureAuthorityRequired
	}
	return value, nil
}

func (a ErasureAuthorizationV2) matchesProtectedPolicy(policy ProtectedErasurePolicy) bool {
	return a.namespaceIdentity == policy.NamespaceIdentity() && a.policyIdentity == policy.ErasurePolicyIdentity() &&
		a.fenceRetentionPolicyIdentity == policy.FenceRetentionPolicyIdentity() &&
		policy.BackendKind() == "aws_s3_general_purpose" && policy.NamespaceMode() == "protected_new_nonnull" &&
		policy.Protocol() == "same-key-fence-v2" && policy.Ownership() == erasureAuthorizationV2Ownership &&
		a.ownership == policy.Ownership()
}

// ValidateProtected verifies an existing witness against the exact valid loaded
// policy snapshot. It never opens a file, checks the clock, or mints or rebinds.
func (a ErasureAuthorizationV2) ValidateProtected(policy ProtectedErasurePolicy) error {
	if a.witness == nil || policy.Validate() != nil || a.witness.document.Validate() != nil {
		return ErrErasureAuthorityRequired
	}
	if a.witness.policyIdentity != policy.Identity() || !a.matchesProtectedPolicy(policy) || a.legacyReceiptIdentity != "" {
		return ErrErasureBindingMismatch
	}
	encoded, err := EncodeErasureAuthorizationV2(a)
	if err != nil || a.witness.authorizationIdentity != a.identity ||
		a.witness.documentDigest != a.witness.document.Digest() ||
		!bytes.Equal(encoded, a.witness.document.Bytes()) {
		return ErrErasureBindingMismatch
	}
	return nil
}

func (a ErasureAuthorizationV2) ProtectedPolicyIdentity() string {
	if a.witness == nil {
		return ""
	}
	return a.witness.policyIdentity
}

func (a ErasureAuthorizationV2) ProtectedDocumentDigest() string {
	if a.witness == nil {
		return ""
	}
	return a.witness.documentDigest
}

func (a ErasureAuthorizationV2) String() string { return "artifact erasure authorization" }
func (a ErasureAuthorizationV2) GoString() string {
	return "artifact.ErasureAuthorizationV2{<redacted>}"
}
func (a ErasureAuthorizationV2) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, a.String(), a.GoString())
}
