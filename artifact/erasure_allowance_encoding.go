package artifact

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	resumeAllowanceContract        = "open-trestle/artifact-erasure-resume-allowance"
	maxEncodedResumeAllowanceBytes = 4096
)

// Only identity is omitted for the hash preimage. Every other field is always
// present, including zero budget dimensions. Scope and witnesses stay off wire.
type resumeAllowanceRecord struct {
	Contract                      string             `json:"contract"`
	SchemaVersion                 int                `json:"schema_version"`
	Identity                      string             `json:"identity,omitempty"`
	NamespaceIdentity             string             `json:"namespace_identity"`
	ScopeIdentity                 string             `json:"scope_identity"`
	ArtifactIdentity              string             `json:"artifact_identity"`
	AdmissionIdentity             string             `json:"admission_identity"`
	OperationIdentity             string             `json:"operation_identity"`
	OriginalAuthorizationIdentity string             `json:"original_authorization_identity"`
	AuthorizationDocumentDigest   string             `json:"authorization_document_digest"`
	RecoveryPolicyIdentity        string             `json:"recovery_policy_identity"`
	ProtectedPolicyIdentity       string             `json:"protected_policy_identity"`
	PrincipalIdentity             string             `json:"principal_identity"`
	IssuanceIdentity              string             `json:"issuance_identity"`
	ExpectedBucketOwner           string             `json:"expected_bucket_owner"`
	NotBeforeMilliseconds         int64              `json:"not_before_milliseconds"`
	NotAfterMilliseconds          int64              `json:"not_after_milliseconds"`
	Maximum                       resumeBudgetRecord `json:"maximum"`
}

type resumeBudgetRecord struct {
	Requests      uint32 `json:"requests"`
	Mutations     uint32 `json:"mutations"`
	Reads         uint32 `json:"reads"`
	Lists         uint32 `json:"lists"`
	Creates       uint32 `json:"creates"`
	Deletes       uint32 `json:"deletes"`
	Pages         uint32 `json:"pages"`
	Versions      uint32 `json:"versions"`
	ResponseBytes uint64 `json:"response_bytes"`
	ListBytes     uint64 `json:"list_bytes"`
	WriteBytes    uint64 `json:"write_bytes"`
}

// EncodeResumeAllowance returns independent canonical metadata bytes. Witnesses
// have no encoding; parsing these bytes cannot restore protected authority.
func EncodeResumeAllowance(value ResumeAllowance) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(resumeAllowanceRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedResumeAllowanceBytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseResumeAllowance requires a valid explicit full scope. A digest does not
// reconstruct scope or mint protected authority. Decoding is bounded before JSON.
func ParseResumeAllowance(encoded []byte, scope audit.ReviewScope) (ResumeAllowance, error) {
	if scope.Validate() != nil || len(encoded) == 0 || len(encoded) > maxEncodedResumeAllowanceBytes || !utf8.Valid(encoded) {
		return ResumeAllowance{}, ErrInvalidErasureContract
	}
	var record resumeAllowanceRecord
	// Fixed-field byte-equal re-encoding rejects duplicates, aliases, unknown or
	// missing fields, nulls, escapes, ordering, whitespace and alternate numbers.
	if !canonicalErasureRecord(encoded, maxEncodedResumeAllowanceBytes, &record) ||
		record.Contract != resumeAllowanceContract || record.SchemaVersion != 1 ||
		!validDigest(record.Identity) || !validDigest(record.ScopeIdentity) {
		return ResumeAllowance{}, ErrInvalidErasureContract
	}
	value := ResumeAllowance{
		identity: record.Identity, scope: scope, namespaceIdentity: record.NamespaceIdentity,
		artifactIdentity: record.ArtifactIdentity, admissionIdentity: record.AdmissionIdentity,
		operationIdentity: record.OperationIdentity, originalAuthorizationIdentity: record.OriginalAuthorizationIdentity,
		authorizationDocumentDigest: record.AuthorizationDocumentDigest,
		recoveryPolicyIdentity:      record.RecoveryPolicyIdentity, protectedPolicyIdentity: record.ProtectedPolicyIdentity,
		principalIdentity: record.PrincipalIdentity, issuanceIdentity: record.IssuanceIdentity,
		expectedBucketOwner: record.ExpectedBucketOwner,
		notBeforeMillis:     record.NotBeforeMilliseconds, notAfterMillis: record.NotAfterMilliseconds,
		maximum: ResumeBudget{
			Requests: record.Maximum.Requests, Mutations: record.Maximum.Mutations, Reads: record.Maximum.Reads,
			Lists: record.Maximum.Lists, Creates: record.Maximum.Creates, Deletes: record.Maximum.Deletes,
			Pages: record.Maximum.Pages, Versions: record.Maximum.Versions, ResponseBytes: record.Maximum.ResponseBytes,
			ListBytes: record.Maximum.ListBytes, WriteBytes: record.Maximum.WriteBytes,
		},
	}
	// Structural errors precede otherwise well-shaped scope or identity errors.
	if err := value.validateFields(); err != nil {
		return ResumeAllowance{}, err
	}
	if scope.Identity() != record.ScopeIdentity {
		return ResumeAllowance{}, ErrErasureIdentityMismatch
	}
	if err := value.Validate(); err != nil {
		return ResumeAllowance{}, err
	}
	return value, nil
}

func resumeAllowanceRecordFromValue(value ResumeAllowance) resumeAllowanceRecord {
	return resumeAllowanceRecord{
		Contract: resumeAllowanceContract, SchemaVersion: 1, Identity: value.identity,
		NamespaceIdentity: value.namespaceIdentity, ScopeIdentity: value.scope.Identity(),
		ArtifactIdentity: value.artifactIdentity, AdmissionIdentity: value.admissionIdentity,
		OperationIdentity: value.operationIdentity, OriginalAuthorizationIdentity: value.originalAuthorizationIdentity,
		AuthorizationDocumentDigest: value.authorizationDocumentDigest,
		RecoveryPolicyIdentity:      value.recoveryPolicyIdentity, ProtectedPolicyIdentity: value.protectedPolicyIdentity,
		PrincipalIdentity: value.principalIdentity, IssuanceIdentity: value.issuanceIdentity,
		ExpectedBucketOwner:   value.expectedBucketOwner,
		NotBeforeMilliseconds: value.notBeforeMillis, NotAfterMilliseconds: value.notAfterMillis,
		Maximum: resumeBudgetRecord{
			Requests: value.maximum.Requests, Mutations: value.maximum.Mutations, Reads: value.maximum.Reads,
			Lists: value.maximum.Lists, Creates: value.maximum.Creates, Deletes: value.maximum.Deletes,
			Pages: value.maximum.Pages, Versions: value.maximum.Versions, ResponseBytes: value.maximum.ResponseBytes,
			ListBytes: value.maximum.ListBytes, WriteBytes: value.maximum.WriteBytes,
		},
	}
}

func deriveResumeAllowanceIdentity(value ResumeAllowance) string {
	record := resumeAllowanceRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	// The existing v1 helper hashes contract + "/v1" + NUL + unsigned JSON.
	return erasureRecordIdentity(resumeAllowanceContract, encoded)
}
