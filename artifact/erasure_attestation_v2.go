package artifact

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// ErasureAttestationV2 is immutable content-free metadata. Its zero is invalid.
// It carries neither a protected policy witness nor accepted publication state.
type ErasureAttestationV2 struct {
	record erasureAttestationV2Record
	scope  audit.ReviewScope
}

func (a ErasureAttestationV2) Identity() string          { return a.record.Identity }
func (a ErasureAttestationV2) NamespaceIdentity() string { return a.record.NamespaceIdentity }
func (a ErasureAttestationV2) ScopeIdentity() string     { return a.record.ScopeIdentity }
func (a ErasureAttestationV2) ArtifactIdentity() string  { return a.record.ArtifactIdentity }
func (a ErasureAttestationV2) PayloadDigest() string     { return a.record.PayloadDigest }
func (a ErasureAttestationV2) AdmissionIdentity() string { return a.record.AdmissionIdentity }
func (a ErasureAttestationV2) OperationIdentity() string { return a.record.OperationIdentity }
func (a ErasureAttestationV2) OriginalAuthorizationIdentity() string {
	return a.record.OriginalAuthorizationIdentity
}
func (a ErasureAttestationV2) AuthorizationDocumentDigest() string {
	return a.record.AuthorizationDocumentDigest
}
func (a ErasureAttestationV2) ErasureProtocol() string { return a.record.ErasureProtocol }
func (a ErasureAttestationV2) PolicyIdentity() string  { return a.record.PolicyIdentity }
func (a ErasureAttestationV2) ProtectedPolicyIdentity() string {
	return a.record.ProtectedPolicyIdentity
}
func (a ErasureAttestationV2) ResumePolicyIdentity() string { return a.record.ResumePolicyIdentity }
func (a ErasureAttestationV2) ConfigurationEvidenceIdentity() string {
	return a.record.ConfigurationEvidenceIdentity
}
func (a ErasureAttestationV2) FenceIdentity() string          { return a.record.FenceIdentity }
func (a ErasureAttestationV2) FenceVersionIdentity() string   { return a.record.FenceVersionIdentity }
func (a ErasureAttestationV2) VerificationIdentity() string   { return a.record.VerificationIdentity }
func (a ErasureAttestationV2) ProofScope() string             { return a.record.ProofScope }
func (a ErasureAttestationV2) RemainingDataVersions() uint32  { return a.record.RemainingDataVersions }
func (a ErasureAttestationV2) RemainingDeleteMarkers() uint32 { return a.record.RemainingDeleteMarkers }
func (a ErasureAttestationV2) RemainingRecord() string        { return a.record.RemainingRecord }
func (a ErasureAttestationV2) LegacyReceiptIdentity() string  { return a.record.LegacyReceiptIdentity }

func (a ErasureAttestationV2) PreparedAt() time.Time {
	return erasureValueTime(a.record.PreparedAtMilliseconds)
}
func (a ErasureAttestationV2) VerifiedAt() time.Time {
	return erasureValueTime(a.record.VerifiedAtMilliseconds)
}
func (a ErasureAttestationV2) CompletedAt() time.Time {
	return erasureValueTime(a.record.CompletedAtMilliseconds)
}
func (a ErasureAttestationV2) String() string   { return "artifact erasure attestation" }
func (a ErasureAttestationV2) GoString() string { return "artifact.ErasureAttestationV2{<redacted>}" }
func (a ErasureAttestationV2) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, a.String(), a.GoString())
}

// NewAttestationCandidateEvidence checks an actual selected protected snapshot.
// The original operation policy label is preserved. Original/current stable
// policy comparison and full durable dependency closure still belong to a journal.
func NewAttestationCandidateEvidence(op ErasureOperation, admission ArtifactAdmission, policy ProtectedErasurePolicy, verification ErasureVerification) (ErasureEvidence, error) {
	if policy.Validate() != nil {
		return ErasureEvidence{}, ErrErasureAuthorityRequired
	}
	if err := op.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	if err := admission.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	if err := verification.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	if op.LegacyReceiptIdentity() != "" {
		return ErasureEvidence{}, ErrErasureLegacyInventoryRequired
	}
	if admission.Scope() != op.Scope() || admission.NamespaceIdentity() != op.NamespaceIdentity() ||
		admission.ArtifactIdentity() != op.ArtifactIdentity() || admission.Identity() != op.AdmissionIdentity() ||
		verification.ref != op.Ref() || verification.ArtifactIdentity() != op.ArtifactIdentity() ||
		policy.NamespaceIdentity() != op.NamespaceIdentity() || policy.ErasurePolicyIdentity() != op.PolicyIdentity() ||
		policy.Protocol() != op.ErasureProtocol() || policy.Ownership() != op.Ownership() ||
		verification.VerifiedAt().Before(op.PreparedAt()) || !policy.AllowsAt(verification.VerifiedAt()) || !policy.AllowsAt(verification.CompletedAt()) {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	fence, err := NewErasureFence(op)
	if err != nil {
		return ErasureEvidence{}, err
	}
	parent, err := NewVerificationEvidence(verification)
	if err != nil {
		return ErasureEvidence{}, err
	}
	r := erasureAttestationV2Record{Contract: erasureAttestationV2Contract, SchemaVersion: 2,
		NamespaceIdentity: op.NamespaceIdentity(), ScopeIdentity: op.Scope().Identity(), ArtifactIdentity: op.ArtifactIdentity(),
		PayloadDigest: admission.PayloadDigest(), AdmissionIdentity: op.AdmissionIdentity(), OperationIdentity: op.Identity(),
		OriginalAuthorizationIdentity: op.OriginalAuthorizationIdentity(), AuthorizationDocumentDigest: op.AuthorizationDocumentDigest(),
		ErasureProtocol: op.ErasureProtocol(), PolicyIdentity: op.PolicyIdentity(), ProtectedPolicyIdentity: op.ProtectedPolicyIdentity(),
		ResumePolicyIdentity: policy.Identity(), ConfigurationEvidenceIdentity: policy.ConfigurationEvidenceIdentity(),
		FenceIdentity: fence.Identity(), FenceVersionIdentity: verification.FenceVersionIdentity(), VerificationIdentity: verification.Identity(),
		PreparedAtMilliseconds: op.PreparedAt().UnixMilli(), VerifiedAtMilliseconds: verification.VerifiedAt().UnixMilli(), CompletedAtMilliseconds: verification.CompletedAt().UnixMilli(),
		ProofScope: "all_versions_at_exact_key", RemainingDataVersions: 1, RemainingDeleteMarkers: 0, RemainingRecord: "content_free_fence", LegacyReceiptIdentity: ""}
	r.Identity = op.Identity()
	if _, err := erasureMetadataEncode(r, maxEncodedErasureAttestationV2Bytes); err != nil {
		return ErasureEvidence{}, err
	}
	r.Identity = attestationV2RecordIdentity(r)
	encoded, err := erasureMetadataEncode(r, maxEncodedErasureAttestationV2Bytes)
	if err != nil {
		return ErasureEvidence{}, err
	}
	return newErasureEvidence(op.Ref(), "candidate", "candidate", "", r.CompletedAtMilliseconds, []string{parent.Identity()}, encoded)
}

// NewAttestationPublicationEvidence compares the entire selected candidate with
// a full-read-shaped response. It does not prove the immutable request key or commit.
func NewAttestationPublicationEvidence(candidate ErasureEvidence, read ErasureEvidence, at time.Time) (ErasureEvidence, error) {
	if candidate.Kind() != "candidate" || !validErasureAuthorizationV2Time(at) {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if err := candidate.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	response, err := responseFromEvidence(read)
	if err != nil {
		return ErasureEvidence{}, err
	}
	if response.Code != "present" || response.ContentKind != "attestation" || response.VersionKind != "data" {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if candidate.Ref() != read.Ref() {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	expected := candidate.RecordBytes()
	body, _ := hex.DecodeString(response.RecordHex)
	if !bytes.Equal(body, expected) || response.ContentDigest != hashBytes(expected) || response.ResponseBytes != uint32(len(expected)) ||
		at.Before(read.ObservedAt()) || read.ObservedAt().Before(candidate.ObservedAt()) {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	return newErasureEvidence(candidate.Ref(), "published", "published", "", at.UnixMilli(), []string{candidate.Identity(), read.Identity()}, nil)
}
