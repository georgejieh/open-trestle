package artifact

import (
	"encoding/json"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	erasureAttestationV2Contract        = "open-trestle/artifact-erasure-attestation"
	maxEncodedErasureAttestationV2Bytes = 8192
)

type erasureAttestationV2Record struct {
	Contract                      string `json:"contract"`
	SchemaVersion                 int    `json:"schema_version"`
	Identity                      string `json:"identity,omitempty"`
	NamespaceIdentity             string `json:"namespace_identity"`
	ScopeIdentity                 string `json:"scope_identity"`
	ArtifactIdentity              string `json:"artifact_identity"`
	PayloadDigest                 string `json:"payload_digest"`
	AdmissionIdentity             string `json:"admission_identity"`
	OperationIdentity             string `json:"operation_identity"`
	OriginalAuthorizationIdentity string `json:"original_authorization_identity"`
	AuthorizationDocumentDigest   string `json:"authorization_document_digest"`
	ErasureProtocol               string `json:"erasure_protocol"`
	PolicyIdentity                string `json:"policy_identity"`
	ProtectedPolicyIdentity       string `json:"protected_policy_identity"`
	ResumePolicyIdentity          string `json:"resume_policy_identity"`
	ConfigurationEvidenceIdentity string `json:"configuration_evidence_identity"`
	FenceIdentity                 string `json:"fence_identity"`
	FenceVersionIdentity          string `json:"fence_version_identity"`
	VerificationIdentity          string `json:"verification_identity"`
	PreparedAtMilliseconds        int64  `json:"prepared_at_milliseconds"`
	VerifiedAtMilliseconds        int64  `json:"verified_at_milliseconds"`
	CompletedAtMilliseconds       int64  `json:"completed_at_milliseconds"`
	ProofScope                    string `json:"proof_scope"`
	RemainingDataVersions         uint32 `json:"remaining_data_versions"`
	RemainingDeleteMarkers        uint32 `json:"remaining_delete_markers"`
	RemainingRecord               string `json:"remaining_record"`
	LegacyReceiptIdentity         string `json:"legacy_receipt_identity"`
}

func (r erasureAttestationV2Record) shape() error {
	if r.Contract != erasureAttestationV2Contract || r.SchemaVersion != 2 || r.ErasureProtocol != erasureOperationProtocol ||
		r.ProofScope != "all_versions_at_exact_key" || r.RemainingDataVersions != 1 || r.RemainingDeleteMarkers != 0 ||
		r.RemainingRecord != "content_free_fence" || r.LegacyReceiptIdentity != "" ||
		!erasureMetadataMillis(r.PreparedAtMilliseconds) || !erasureMetadataMillis(r.VerifiedAtMilliseconds) || !erasureMetadataMillis(r.CompletedAtMilliseconds) {
		return ErrInvalidErasureContract
	}
	for _, id := range [...]string{r.Identity, r.NamespaceIdentity, r.ScopeIdentity, r.ArtifactIdentity, r.PayloadDigest, r.AdmissionIdentity,
		r.OperationIdentity, r.OriginalAuthorizationIdentity, r.AuthorizationDocumentDigest, r.PolicyIdentity, r.ProtectedPolicyIdentity,
		r.ResumePolicyIdentity, r.ConfigurationEvidenceIdentity, r.FenceIdentity, r.FenceVersionIdentity, r.VerificationIdentity} {
		if !validDigest(id) {
			return ErrInvalidErasureContract
		}
	}
	return nil
}

func (r erasureAttestationV2Record) relations() error {
	if r.PreparedAtMilliseconds > r.VerifiedAtMilliseconds || r.VerifiedAtMilliseconds > r.CompletedAtMilliseconds {
		return ErrErasureBindingMismatch
	}
	return nil
}

func attestationV2RecordIdentity(r erasureAttestationV2Record) string {
	r.Identity = ""
	encoded, _ := json.Marshal(r)
	return hashBytes(append([]byte(erasureAttestationV2Contract+"/v2\x00"), encoded...))
}

func (a ErasureAttestationV2) Validate() error {
	r := a.record
	if err := r.shape(); err != nil {
		return err
	}
	if _, err := erasureMetadataEncode(r, maxEncodedErasureAttestationV2Bytes); err != nil {
		return err
	}
	if a.scope.Validate() != nil {
		return ErrInvalidErasureContract
	}
	if r.ScopeIdentity != a.scope.Identity() {
		return ErrErasureIdentityMismatch
	}
	if err := r.relations(); err != nil {
		return err
	}
	if r.Identity != attestationV2RecordIdentity(r) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func EncodeErasureAttestationV2(value ErasureAttestationV2) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return erasureMetadataEncode(value.record, maxEncodedErasureAttestationV2Bytes)
}

// ParseErasureAttestationV2 restores metadata under an explicit scope. It does
// not load policy, prove verification dependencies or certify publication.
func ParseErasureAttestationV2(encoded []byte, scope audit.ReviewScope) (ErasureAttestationV2, error) {
	var record erasureAttestationV2Record
	if !erasureMetadataDecode(encoded, maxEncodedErasureAttestationV2Bytes, &record) {
		return ErasureAttestationV2{}, ErrInvalidErasureContract
	}
	value := ErasureAttestationV2{record: record, scope: scope}
	if err := value.Validate(); err != nil {
		return ErasureAttestationV2{}, err
	}
	copied, err := cloneErasureMetadataScope(scope)
	if err != nil {
		return ErasureAttestationV2{}, err
	}
	value.scope = copied
	return value, nil
}
