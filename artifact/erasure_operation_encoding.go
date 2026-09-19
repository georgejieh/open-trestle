package artifact

import (
	"bytes"
	"encoding/json"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	erasureOperationContract        = "open-trestle/artifact-erasure-operation"
	erasureFenceContract            = "open-trestle/artifact-erasure-fence"
	erasureFenceMagic               = "OTAF0001"
	maxEncodedErasureOperationBytes = 16384
	maxEncodedErasureFenceBytes     = 4096
)

// Only identity is omitted from hash preimages. The optional legacy value's
// key is always present. Raw scope and protected witnesses have no wire fields.
type erasureOperationRecord struct {
	Contract                      string `json:"contract"`
	SchemaVersion                 int    `json:"schema_version"`
	Identity                      string `json:"identity,omitempty"`
	NamespaceIdentity             string `json:"namespace_identity"`
	ScopeIdentity                 string `json:"scope_identity"`
	ArtifactIdentity              string `json:"artifact_identity"`
	AdmissionIdentity             string `json:"admission_identity"`
	OriginalAuthorizationIdentity string `json:"original_authorization_identity"`
	AuthorizationDocumentDigest   string `json:"authorization_document_digest"`
	PolicyIdentity                string `json:"policy_identity"`
	ProtectedPolicyIdentity       string `json:"protected_policy_identity"`
	Ownership                     string `json:"ownership"`
	PreparedAtMilliseconds        int64  `json:"prepared_at_milliseconds"`
	ErasureProtocol               string `json:"erasure_protocol"`
	LegacyReceiptIdentity         string `json:"legacy_receipt_identity"`
}

type erasureFenceRecord struct {
	Contract               string `json:"contract"`
	SchemaVersion          int    `json:"schema_version"`
	Identity               string `json:"identity,omitempty"`
	ErasureProtocol        string `json:"erasure_protocol"`
	NamespaceIdentity      string `json:"namespace_identity"`
	ScopeIdentity          string `json:"scope_identity"`
	ArtifactIdentity       string `json:"artifact_identity"`
	OperationIdentity      string `json:"operation_identity"`
	PreparedAtMilliseconds int64  `json:"prepared_at_milliseconds"`
}

// EncodeErasureOperation returns independent canonical metadata bytes.
func EncodeErasureOperation(value ErasureOperation) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(erasureOperationRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedErasureOperationBytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseErasureOperation requires the caller's full valid scope because the wire
// retains only its hash. Parsing restores neither protected nor DB authority.
func ParseErasureOperation(encoded []byte, scope audit.ReviewScope) (ErasureOperation, error) {
	if scope.Validate() != nil {
		return ErasureOperation{}, ErrInvalidErasureContract
	}
	var record erasureOperationRecord
	if !canonicalErasureRecord(encoded, maxEncodedErasureOperationBytes, &record) ||
		record.Contract != erasureOperationContract || record.SchemaVersion != 2 ||
		!validDigest(record.Identity) || !validDigest(record.ScopeIdentity) {
		return ErasureOperation{}, ErrInvalidErasureContract
	}
	value := ErasureOperation{
		identity: record.Identity, scope: scope, namespaceIdentity: record.NamespaceIdentity,
		artifactIdentity: record.ArtifactIdentity, admissionIdentity: record.AdmissionIdentity,
		originalAuthorizationIdentity: record.OriginalAuthorizationIdentity, authorizationDocumentDigest: record.AuthorizationDocumentDigest,
		policyIdentity: record.PolicyIdentity, protectedPolicyIdentity: record.ProtectedPolicyIdentity,
		ownership: record.Ownership, preparedAtMillis: record.PreparedAtMilliseconds,
		erasureProtocol: record.ErasureProtocol, legacyReceiptIdentity: record.LegacyReceiptIdentity,
	}
	// Structural errors precede well-shaped identity or scope binding errors.
	if err := value.validateFields(); err != nil {
		return ErasureOperation{}, err
	}
	if scope.Identity() != record.ScopeIdentity {
		return ErasureOperation{}, ErrErasureIdentityMismatch
	}
	if err := value.Validate(); err != nil {
		return ErasureOperation{}, err
	}
	return value, nil
}

// EncodeErasureFence returns independent bytes with eight-byte magic followed
// immediately by canonical JSON. The total bound includes the magic.
func EncodeErasureFence(value ErasureFence) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(erasureFenceRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedErasureFenceBytes-len(erasureFenceMagic) {
		return nil, ErrInvalidErasureContract
	}
	return append([]byte(erasureFenceMagic), encoded...), nil
}

// ParseErasureFence checks framed content only, never backend state or permission.
func ParseErasureFence(encoded []byte) (ErasureFence, error) {
	if len(encoded) > maxEncodedErasureFenceBytes || !bytes.HasPrefix(encoded, []byte(erasureFenceMagic)) {
		return ErasureFence{}, ErrInvalidErasureContract
	}
	var record erasureFenceRecord
	if !canonicalErasureRecord(encoded[len(erasureFenceMagic):], maxEncodedErasureFenceBytes-len(erasureFenceMagic), &record) ||
		record.Contract != erasureFenceContract || record.SchemaVersion != 1 {
		return ErasureFence{}, ErrInvalidErasureContract
	}
	value := ErasureFence{
		identity: record.Identity, erasureProtocol: record.ErasureProtocol,
		namespaceIdentity: record.NamespaceIdentity, scopeIdentity: record.ScopeIdentity,
		artifactIdentity: record.ArtifactIdentity, operationIdentity: record.OperationIdentity,
		preparedAtMillis: record.PreparedAtMilliseconds,
	}
	if err := value.Validate(); err != nil {
		return ErasureFence{}, err
	}
	return value, nil
}

func erasureOperationRecordFromValue(value ErasureOperation) erasureOperationRecord {
	return erasureOperationRecord{
		Contract: erasureOperationContract, SchemaVersion: 2, Identity: value.identity,
		NamespaceIdentity: value.namespaceIdentity, ScopeIdentity: value.scope.Identity(),
		ArtifactIdentity: value.artifactIdentity, AdmissionIdentity: value.admissionIdentity,
		OriginalAuthorizationIdentity: value.originalAuthorizationIdentity, AuthorizationDocumentDigest: value.authorizationDocumentDigest,
		PolicyIdentity: value.policyIdentity, ProtectedPolicyIdentity: value.protectedPolicyIdentity,
		Ownership: value.ownership, PreparedAtMilliseconds: value.preparedAtMillis,
		ErasureProtocol: value.erasureProtocol, LegacyReceiptIdentity: value.legacyReceiptIdentity,
	}
}

func erasureFenceRecordFromValue(value ErasureFence) erasureFenceRecord {
	return erasureFenceRecord{
		Contract: erasureFenceContract, SchemaVersion: 1, Identity: value.identity,
		ErasureProtocol: value.erasureProtocol, NamespaceIdentity: value.namespaceIdentity,
		ScopeIdentity: value.scopeIdentity, ArtifactIdentity: value.artifactIdentity,
		OperationIdentity: value.operationIdentity, PreparedAtMilliseconds: value.preparedAtMillis,
	}
}

func deriveErasureOperationIdentity(value ErasureOperation) string {
	record := erasureOperationRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return hashBytes(append([]byte(erasureOperationContract+"/v2\x00"), encoded...))
}

func deriveErasureFenceIdentity(value ErasureFence) string {
	record := erasureFenceRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	// The existing v1 helper includes the domain's actual NUL, not the magic.
	return erasureRecordIdentity(erasureFenceContract, encoded)
}
