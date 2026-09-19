package artifact

import (
	"fmt"
	"time"
)

// ErasureVerification is immutable metadata, not a terminal proof or permission.
// Its zero value is invalid; no request or policy witness is retained.
type ErasureVerification struct {
	record erasureVerificationRecord
	ref    ErasureOperationRef
}

func (v ErasureVerification) Identity() string              { return v.record.Identity }
func (v ErasureVerification) NamespaceIdentity() string     { return v.record.NamespaceIdentity }
func (v ErasureVerification) ScopeIdentity() string         { return v.record.ScopeIdentity }
func (v ErasureVerification) ArtifactIdentity() string      { return v.record.ArtifactIdentity }
func (v ErasureVerification) OperationIdentity() string     { return v.record.OperationIdentity }
func (v ErasureVerification) FenceEvidenceIdentity() string { return v.record.FenceEvidenceIdentity }
func (v ErasureVerification) FenceVersionIdentity() string  { return v.record.FenceVersionIdentity }
func (v ErasureVerification) CurrentResponseIdentity() string {
	return v.record.CurrentResponseIdentity
}

func (v ErasureVerification) ListResponseIdentities() []string {
	return append([]string(nil), v.record.ListResponseIdentities...)
}
func (v ErasureVerification) VerifiedAt() time.Time {
	return erasureValueTime(v.record.VerifiedAtMilliseconds)
}
func (v ErasureVerification) CompletedAt() time.Time {
	return erasureValueTime(v.record.CompletedAtMilliseconds)
}
func (v ErasureVerification) String() string   { return "artifact erasure verification" }
func (v ErasureVerification) GoString() string { return "artifact.ErasureVerification{<redacted>}" }
func (v ErasureVerification) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, v.String(), v.GoString())
}

// NewErasureVerification compares supplied shapes, canonical content and times.
// A singleton response cannot establish an empty input cursor, limit2, fresh
// reservations, accepted namespace keys, policy windows or known commits.
func NewErasureVerification(op ErasureOperation, fence ErasureEvidence, lists []ErasureEvidence, current ErasureEvidence, completed time.Time) (ErasureVerification, error) {
	if len(lists) != 1 || !validErasureAuthorizationV2Time(completed) || fence.Kind() != "fence" {
		return ErasureVerification{}, ErrInvalidErasureContract
	}
	if err := op.Validate(); err != nil {
		return ErasureVerification{}, err
	}
	if err := fence.Validate(); err != nil {
		return ErasureVerification{}, err
	}
	list, err := responseFromEvidence(lists[0])
	if err != nil {
		return ErasureVerification{}, err
	}
	read, err := responseFromEvidence(current)
	if err != nil {
		return ErasureVerification{}, err
	}
	if list.Code != "present" || list.ContentKind != "" || list.Truncated || len(list.Entries) != 1 ||
		list.Entries[0].Kind != "data" || !list.Entries[0].IsLatest ||
		read.Code != "present" || read.ContentKind != "fence" || read.VersionKind != "data" {
		return ErasureVerification{}, ErrInvalidErasureContract
	}
	version, err := ParseObjectVersion(fence.RecordBytes())
	if err != nil {
		return ErasureVerification{}, err
	}
	if fence.Ref() != op.Ref() || lists[0].Ref() != op.Ref() || current.Ref() != op.Ref() {
		return ErasureVerification{}, ErrErasureBindingMismatch
	}
	if fence.Identity() == lists[0].Identity() || fence.Identity() == current.Identity() || lists[0].Identity() == current.Identity() ||
		lists[0].AttemptIdentity() == current.AttemptIdentity() || current.Identity() == fence.record.ParentIdentities[0] {
		return ErasureVerification{}, ErrErasureBindingMismatch
	}
	if version.VersionID() != list.Entries[0].VersionID || version.Identity() != list.Entries[0].VersionIdentity || version.VersionID() != read.VersionID {
		return ErasureVerification{}, ErrErasureBindingMismatch
	}
	if err := exactFenceResponse(op, read); err != nil {
		return ErasureVerification{}, err
	}
	if fence.ObservedAt().Before(op.PreparedAt()) || lists[0].ObservedAt().Before(fence.ObservedAt()) ||
		current.ObservedAt().Before(lists[0].ObservedAt()) || completed.Before(current.ObservedAt()) {
		return ErasureVerification{}, ErrErasureBindingMismatch
	}
	r := erasureVerificationRecord{Contract: erasureVerificationContract, SchemaVersion: 1,
		NamespaceIdentity: op.NamespaceIdentity(), ScopeIdentity: op.Scope().Identity(), ArtifactIdentity: op.ArtifactIdentity(), OperationIdentity: op.Identity(),
		FenceEvidenceIdentity: fence.Identity(), FenceVersionIdentity: version.Identity(), ListResponseIdentities: []string{lists[0].Identity()},
		CurrentResponseIdentity: current.Identity(), VerifiedAtMilliseconds: current.ObservedAt().UnixMilli(), CompletedAtMilliseconds: completed.UnixMilli()}
	r.Identity = op.Identity()
	if _, err := erasureMetadataEncode(r, maxEncodedErasureVerificationBytes); err != nil {
		return ErasureVerification{}, err
	}
	r.Identity = verificationRecordIdentity(r)
	encoded, err := erasureMetadataEncode(r, maxEncodedErasureVerificationBytes)
	if err != nil {
		return ErasureVerification{}, err
	}
	return ParseErasureVerification(encoded, op.Ref())
}

func NewVerificationEvidence(verification ErasureVerification) (ErasureEvidence, error) {
	encoded, err := EncodeErasureVerification(verification)
	if err != nil {
		return ErasureEvidence{}, err
	}
	r := verification.record
	return newErasureEvidence(verification.ref, "verification", "verification:"+verification.Identity(), "", r.CompletedAtMilliseconds,
		[]string{r.FenceEvidenceIdentity, r.ListResponseIdentities[0], r.CurrentResponseIdentity}, encoded)
}
