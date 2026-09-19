package artifact

import "encoding/json"

const (
	erasureVerificationContract        = "open-trestle/artifact-erasure-verification"
	maxEncodedErasureVerificationBytes = 8192
)

type erasureVerificationRecord struct {
	Contract                string   `json:"contract"`
	SchemaVersion           int      `json:"schema_version"`
	Identity                string   `json:"identity,omitempty"`
	NamespaceIdentity       string   `json:"namespace_identity"`
	ScopeIdentity           string   `json:"scope_identity"`
	ArtifactIdentity        string   `json:"artifact_identity"`
	OperationIdentity       string   `json:"operation_identity"`
	FenceEvidenceIdentity   string   `json:"fence_evidence_identity"`
	FenceVersionIdentity    string   `json:"fence_version_identity"`
	ListResponseIdentities  []string `json:"list_response_identities"`
	CurrentResponseIdentity string   `json:"current_response_identity"`
	VerifiedAtMilliseconds  int64    `json:"verified_at_milliseconds"`
	CompletedAtMilliseconds int64    `json:"completed_at_milliseconds"`
}

func (r erasureVerificationRecord) shape() error {
	if r.Contract != erasureVerificationContract || r.SchemaVersion != 1 ||
		r.ListResponseIdentities == nil || len(r.ListResponseIdentities) != 1 ||
		!erasureMetadataMillis(r.VerifiedAtMilliseconds) || !erasureMetadataMillis(r.CompletedAtMilliseconds) {
		return ErrInvalidErasureContract
	}
	for _, id := range [...]string{r.Identity, r.NamespaceIdentity, r.ScopeIdentity, r.ArtifactIdentity, r.OperationIdentity,
		r.FenceEvidenceIdentity, r.FenceVersionIdentity, r.ListResponseIdentities[0], r.CurrentResponseIdentity} {
		if !validDigest(id) {
			return ErrInvalidErasureContract
		}
	}
	if r.FenceEvidenceIdentity == r.ListResponseIdentities[0] || r.FenceEvidenceIdentity == r.CurrentResponseIdentity || r.ListResponseIdentities[0] == r.CurrentResponseIdentity {
		return ErrInvalidErasureContract
	}
	return nil
}

func verificationRecordIdentity(r erasureVerificationRecord) string {
	r.Identity = ""
	encoded, _ := json.Marshal(r)
	return erasureRecordIdentity(erasureVerificationContract, encoded)
}

func (v ErasureVerification) Validate() error {
	r := v.record
	if err := r.shape(); err != nil {
		return err
	}
	if _, err := erasureMetadataEncode(r, maxEncodedErasureVerificationBytes); err != nil {
		return err
	}
	if v.ref.Validate() != nil {
		return ErrInvalidErasureContract
	}
	if r.NamespaceIdentity != v.ref.NamespaceIdentity() || r.ScopeIdentity != v.ref.Scope().Identity() || r.OperationIdentity != v.ref.OperationIdentity() {
		return ErrErasureIdentityMismatch
	}
	if r.CompletedAtMilliseconds < r.VerifiedAtMilliseconds {
		return ErrErasureBindingMismatch
	}
	if r.Identity != verificationRecordIdentity(r) {
		return ErrErasureIdentityMismatch
	}
	return nil
}

func EncodeErasureVerification(value ErasureVerification) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return erasureMetadataEncode(value.record, maxEncodedErasureVerificationBytes)
}

// ParseErasureVerification checks claims against an explicit ref, not omitted
// request preimages, fence/list/current observations or durable commits.
func ParseErasureVerification(encoded []byte, ref ErasureOperationRef) (ErasureVerification, error) {
	var record erasureVerificationRecord
	if !erasureMetadataDecode(encoded, maxEncodedErasureVerificationBytes, &record) {
		return ErasureVerification{}, ErrInvalidErasureContract
	}
	value := ErasureVerification{record: record, ref: ref}
	if err := value.Validate(); err != nil {
		return ErasureVerification{}, err
	}
	scope, err := cloneErasureMetadataScope(ref.Scope())
	if err != nil {
		return ErasureVerification{}, err
	}
	value.ref, err = NewErasureOperationRef(scope, ref.NamespaceIdentity(), ref.OperationIdentity())
	if err != nil {
		return ErasureVerification{}, err
	}
	return value, nil
}
