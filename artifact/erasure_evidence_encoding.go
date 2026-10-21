package artifact

import (
	"encoding/hex"
	"encoding/json"
	"strings"
)

const (
	erasureEvidenceContract        = "open-trestle/artifact-erasure-evidence"
	maxEncodedErasureEvidenceBytes = 1048576
)

type erasureEvidenceRecord struct {
	Contract               string   `json:"contract"`
	SchemaVersion          int      `json:"schema_version"`
	Identity               string   `json:"identity,omitempty"`
	NamespaceIdentity      string   `json:"namespace_identity"`
	ScopeIdentity          string   `json:"scope_identity"`
	OperationIdentity      string   `json:"operation_identity"`
	Kind                   string   `json:"kind"`
	Slot                   string   `json:"slot"`
	AttemptIdentity        string   `json:"attempt_identity"`
	ObservedAtMilliseconds int64    `json:"observed_at_milliseconds"`
	ParentIdentities       []string `json:"parent_identities"`
	RecordHex              string   `json:"record_hex"`
}

func evidenceRecordLimit(kind string) int {
	switch kind {
	case "response":
		return maxEncodedAttemptResponseBytes
	case "fence":
		return 4096
	case "verification", "candidate":
		return 8192
	default:
		return 0
	}
}

func (r erasureEvidenceRecord) shape() error {
	if r.Contract != erasureEvidenceContract || r.SchemaVersion != 1 || !validDigest(r.Identity) ||
		!validDigest(r.NamespaceIdentity) || !validDigest(r.ScopeIdentity) || !validDigest(r.OperationIdentity) ||
		!erasureMetadataMillis(r.ObservedAtMilliseconds) || r.ParentIdentities == nil || len(r.ParentIdentities) > 3 ||
		!erasureMetadataHex(r.RecordHex, evidenceRecordLimit(r.Kind)) {
		return ErrInvalidErasureContract
	}
	for i, id := range r.ParentIdentities {
		if !validDigest(id) || id == r.Identity {
			return ErrInvalidErasureContract
		}
		for j := 0; j < i; j++ {
			if id == r.ParentIdentities[j] {
				return ErrInvalidErasureContract
			}
		}
	}
	arity := 0
	switch r.Kind {
	case "response", "unknown":
		if !validDigest(r.AttemptIdentity) || r.Slot != r.Kind+":"+r.AttemptIdentity {
			return ErrInvalidErasureContract
		}
	case "fence":
		arity = 1
		if r.Slot != "fence" {
			return ErrInvalidErasureContract
		}
	case "verification":
		arity = 3
		if len(r.Slot) != len("verification:")+64 || !strings.HasPrefix(r.Slot, "verification:") || !validDigest(r.Slot[len("verification:"):]) {
			return ErrInvalidErasureContract
		}
	case "candidate":
		arity = 1
		if r.Slot != "candidate" {
			return ErrInvalidErasureContract
		}
	case "published":
		arity = 2
		if r.Slot != "published" {
			return ErrInvalidErasureContract
		}
	default:
		return ErrInvalidErasureContract
	}
	if r.Kind != "response" && r.Kind != "unknown" && r.AttemptIdentity != "" {
		return ErrInvalidErasureContract
	}
	if len(r.ParentIdentities) != arity {
		return ErrInvalidErasureContract
	}
	if r.Kind == "unknown" || r.Kind == "published" {
		if r.RecordHex != "" {
			return ErrInvalidErasureContract
		}
	} else if r.RecordHex == "" {
		return ErrInvalidErasureContract
	}
	return nil
}

func evidenceRecordIdentity(r erasureEvidenceRecord) string {
	r.Identity = ""
	encoded, _ := json.Marshal(r)
	return erasureRecordIdentity(erasureEvidenceContract, encoded)
}

func (e ErasureEvidence) Validate() error {
	_, err := e.validate()
	return err
}

func (e ErasureEvidence) validate() (attemptResponseRecord, error) {
	r := e.record
	if err := r.shape(); err != nil {
		return attemptResponseRecord{}, err
	}
	if _, err := erasureMetadataEncode(r, maxEncodedErasureEvidenceBytes); err != nil {
		return attemptResponseRecord{}, err
	}
	response, err := evidencePayloadShape(r)
	if err != nil {
		return attemptResponseRecord{}, err
	}
	if e.ref.Validate() != nil {
		return attemptResponseRecord{}, ErrInvalidErasureContract
	}
	if r.NamespaceIdentity != e.ref.NamespaceIdentity() || r.ScopeIdentity != e.ref.Scope().Identity() || r.OperationIdentity != e.ref.OperationIdentity() {
		return attemptResponseRecord{}, ErrErasureIdentityMismatch
	}
	switch r.Kind {
	case "response":
		response, err = bindAttemptResponse(response, e.ref)
		if err != nil {
			return attemptResponseRecord{}, err
		}
		if response.OperationIdentity != r.OperationIdentity || response.AttemptIdentity != r.AttemptIdentity || response.ObservedAtMilliseconds != r.ObservedAtMilliseconds {
			return attemptResponseRecord{}, ErrErasureBindingMismatch
		}
	case "fence":
		body, _ := hex.DecodeString(r.RecordHex)
		version, err := ParseObjectVersion(body)
		if err != nil {
			return attemptResponseRecord{}, err
		}
		if version.Kind() != ObjectVersionData {
			return attemptResponseRecord{}, ErrInvalidErasureContract
		}
		if version.NamespaceIdentity() != r.NamespaceIdentity {
			return attemptResponseRecord{}, ErrErasureBindingMismatch
		}
	case "verification":
		body, _ := hex.DecodeString(r.RecordHex)
		verification, err := ParseErasureVerification(body, e.ref)
		if err != nil {
			return attemptResponseRecord{}, err
		}
		if r.Slot != "verification:"+verification.Identity() {
			return attemptResponseRecord{}, ErrInvalidErasureContract
		}
		vr := verification.record
		if r.ObservedAtMilliseconds != vr.CompletedAtMilliseconds || r.ParentIdentities[0] != vr.FenceEvidenceIdentity ||
			r.ParentIdentities[1] != vr.ListResponseIdentities[0] || r.ParentIdentities[2] != vr.CurrentResponseIdentity {
			return attemptResponseRecord{}, ErrErasureBindingMismatch
		}
	case "candidate":
		body, _ := hex.DecodeString(r.RecordHex)
		attestation, err := ParseErasureAttestationV2(body, e.ref.Scope())
		if err != nil {
			return attemptResponseRecord{}, err
		}
		if attestation.NamespaceIdentity() != r.NamespaceIdentity || attestation.OperationIdentity() != r.OperationIdentity {
			return attemptResponseRecord{}, ErrErasureIdentityMismatch
		}
		if attestation.record.CompletedAtMilliseconds != r.ObservedAtMilliseconds {
			return attemptResponseRecord{}, ErrErasureBindingMismatch
		}
	}
	if r.Identity != evidenceRecordIdentity(r) {
		return attemptResponseRecord{}, ErrErasureIdentityMismatch
	}
	return response, nil
}

// EncodeErasureEvidence returns a new canonical byte slice, not an accepted row.
func EncodeErasureEvidence(e ErasureEvidence) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return erasureMetadataEncode(e.record, maxEncodedErasureEvidenceBytes)
}

// ParseErasureEvidence binds only supplied labels and nested metadata. It cannot
// validate omitted requests, policy history, provider observations or commits.
func ParseErasureEvidence(encoded []byte, ref ErasureOperationRef) (ErasureEvidence, error) {
	var record erasureEvidenceRecord
	if !erasureMetadataDecode(encoded, maxEncodedErasureEvidenceBytes, &record) {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	value := ErasureEvidence{record: record, ref: ref}
	if err := value.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	scope, err := cloneErasureMetadataScope(ref.Scope())
	if err != nil {
		return ErasureEvidence{}, err
	}
	value.ref, err = NewErasureOperationRef(scope, ref.NamespaceIdentity(), ref.OperationIdentity())
	if err != nil {
		return ErasureEvidence{}, err
	}
	return value, nil
}

func newErasureEvidence(ref ErasureOperationRef, kind, slot, attempt string, at int64, parents []string, body []byte) (ErasureEvidence, error) {
	if len(body) > evidenceRecordLimit(kind) || len(parents) > 3 || len(slot) > 77 || len(attempt) > 64 {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	r := erasureEvidenceRecord{Contract: erasureEvidenceContract, SchemaVersion: 1,
		NamespaceIdentity: ref.NamespaceIdentity(), ScopeIdentity: ref.Scope().Identity(), OperationIdentity: ref.OperationIdentity(),
		Kind: kind, Slot: slot, AttemptIdentity: attempt, ObservedAtMilliseconds: at, ParentIdentities: append([]string{}, parents...), RecordHex: hex.EncodeToString(body)}
	r.Identity = ref.OperationIdentity()
	if _, err := erasureMetadataEncode(r, maxEncodedErasureEvidenceBytes); err != nil {
		return ErasureEvidence{}, err
	}
	r.Identity = evidenceRecordIdentity(r)
	encoded, err := erasureMetadataEncode(r, maxEncodedErasureEvidenceBytes)
	if err != nil {
		return ErasureEvidence{}, err
	}
	return ParseErasureEvidence(encoded, ref)
}

func evidencePayloadShape(r erasureEvidenceRecord) (attemptResponseRecord, error) {
	var response attemptResponseRecord
	body, _ := hex.DecodeString(r.RecordHex)
	switch r.Kind {
	case "response":
		if !erasureMetadataDecode(body, maxEncodedAttemptResponseBytes, &response) {
			return attemptResponseRecord{}, ErrInvalidErasureContract
		}
		if err := response.shape(); err != nil {
			return attemptResponseRecord{}, err
		}
		if err := responseBodyShape(response); err != nil {
			return attemptResponseRecord{}, err
		}
	case "fence":
		var version objectVersionRecord
		if !erasureMetadataDecode(body, 4096, &version) || version.Contract != objectVersionContract || version.SchemaVersion != 1 ||
			!validDigest(version.Identity) || (ExactObjectKey{version.NamespaceIdentity, version.Key}).Validate() != nil ||
			version.Kind != "data" || !validObjectVersionID(version.VersionID) {
			return attemptResponseRecord{}, ErrInvalidErasureContract
		}
	case "verification":
		var verification erasureVerificationRecord
		if !erasureMetadataDecode(body, 8192, &verification) {
			return attemptResponseRecord{}, ErrInvalidErasureContract
		}
		if err := verification.shape(); err != nil {
			return attemptResponseRecord{}, err
		}
	case "candidate":
		var attestation erasureAttestationV2Record
		if !erasureMetadataDecode(body, 8192, &attestation) {
			return attemptResponseRecord{}, ErrInvalidErasureContract
		}
		if err := attestation.shape(); err != nil {
			return attemptResponseRecord{}, err
		}
	}
	return response, nil
}
