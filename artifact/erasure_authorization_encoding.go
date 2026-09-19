package artifact

import (
	"encoding/json"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	erasureAuthorizationV2Contract        = "open-trestle/artifact-erasure-authorization"
	maxEncodedErasureAuthorizationV2Bytes = 8192
)

// Identity is omitted only for the unsigned preimage. The legacy key is always
// present, even when empty. Protected witness data has no wire representation.
type erasureAuthorizationV2Record struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	Identity                     string `json:"identity,omitempty"`
	NamespaceIdentity            string `json:"namespace_identity"`
	ScopeIdentity                string `json:"scope_identity"`
	TenantID                     string `json:"tenant_id"`
	RepositoryID                 string `json:"repository_id"`
	ReviewRunID                  string `json:"review_run_id"`
	ArtifactIdentity             string `json:"artifact_identity"`
	AdmissionIdentity            string `json:"admission_identity"`
	PolicyIdentity               string `json:"policy_identity"`
	PrincipalIdentity            string `json:"principal_identity"`
	HoldClearanceIdentity        string `json:"hold_clearance_identity"`
	Ownership                    string `json:"ownership"`
	FenceRetentionPolicyIdentity string `json:"fence_retention_policy_identity"`
	Reason                       string `json:"reason"`
	IssuedAtMilliseconds         int64  `json:"issued_at_milliseconds"`
	ExpiresAtMilliseconds        int64  `json:"expires_at_milliseconds"`
	LegacyReceiptIdentity        string `json:"legacy_receipt_identity"`
}

// EncodeErasureAuthorizationV2 returns independent canonical shape bytes only.
// Roundtripping a loaded value retains its identity but loses its witness.
func EncodeErasureAuthorizationV2(value ErasureAuthorizationV2) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(erasureAuthorizationV2RecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedErasureAuthorizationV2Bytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseErasureAuthorizationV2 accepts only bounded canonical v2 shape. It does
// not mint protected permission or convert a historical v1 authorization.
func ParseErasureAuthorizationV2(encoded []byte) (ErasureAuthorizationV2, error) {
	var record erasureAuthorizationV2Record
	if !canonicalErasureRecord(encoded, maxEncodedErasureAuthorizationV2Bytes, &record) ||
		record.Contract != erasureAuthorizationV2Contract || record.SchemaVersion != 2 ||
		!validDigest(record.Identity) || !validDigest(record.ScopeIdentity) {
		return ErasureAuthorizationV2{}, ErrInvalidErasureContract
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return ErasureAuthorizationV2{}, ErrInvalidErasureContract
	}
	value := ErasureAuthorizationV2{
		identity: record.Identity, scope: scope, namespaceIdentity: record.NamespaceIdentity,
		artifactIdentity: record.ArtifactIdentity, admissionIdentity: record.AdmissionIdentity,
		policyIdentity: record.PolicyIdentity, principalIdentity: record.PrincipalIdentity,
		holdClearanceIdentity: record.HoldClearanceIdentity, ownership: record.Ownership,
		fenceRetentionPolicyIdentity: record.FenceRetentionPolicyIdentity, legacyReceiptIdentity: record.LegacyReceiptIdentity,
		reason: parseDeletionReason(record.Reason), issuedAtMillis: record.IssuedAtMilliseconds, expiresAtMillis: record.ExpiresAtMilliseconds,
	}
	// Structural errors take priority over otherwise well-shaped identity errors.
	if err := value.validateFields(); err != nil {
		return ErasureAuthorizationV2{}, err
	}
	if scope.Identity() != record.ScopeIdentity {
		return ErasureAuthorizationV2{}, ErrErasureIdentityMismatch
	}
	if err := value.Validate(); err != nil {
		return ErasureAuthorizationV2{}, err
	}
	return value, nil
}

func erasureAuthorizationV2RecordFromValue(value ErasureAuthorizationV2) erasureAuthorizationV2Record {
	return erasureAuthorizationV2Record{
		Contract: erasureAuthorizationV2Contract, SchemaVersion: 2, Identity: value.identity,
		NamespaceIdentity: value.namespaceIdentity, ScopeIdentity: value.scope.Identity(),
		TenantID: value.scope.TenantID(), RepositoryID: value.scope.RepositoryID(), ReviewRunID: value.scope.ReviewRunID(),
		ArtifactIdentity: value.artifactIdentity, AdmissionIdentity: value.admissionIdentity,
		PolicyIdentity: value.policyIdentity, PrincipalIdentity: value.principalIdentity,
		HoldClearanceIdentity: value.holdClearanceIdentity, Ownership: value.ownership,
		FenceRetentionPolicyIdentity: value.fenceRetentionPolicyIdentity, Reason: value.reason.String(),
		IssuedAtMilliseconds: value.issuedAtMillis, ExpiresAtMilliseconds: value.expiresAtMillis,
		LegacyReceiptIdentity: value.legacyReceiptIdentity,
	}
}

func deriveErasureAuthorizationV2Identity(value ErasureAuthorizationV2) string {
	record := erasureAuthorizationV2RecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return hashBytes(append([]byte(erasureAuthorizationV2Contract+"/v2\x00"), encoded...))
}
