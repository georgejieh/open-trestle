package artifact

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// ErasureEvidence is immutable metadata. Its zero value is invalid.
// Neither construction nor parsing supplies durable acceptance or effect authority.
type ErasureEvidence struct {
	record erasureEvidenceRecord
	ref    ErasureOperationRef
}

func (e ErasureEvidence) Identity() string        { return e.record.Identity }
func (e ErasureEvidence) Kind() string            { return e.record.Kind }
func (e ErasureEvidence) Slot() string            { return e.record.Slot }
func (e ErasureEvidence) AttemptIdentity() string { return e.record.AttemptIdentity }
func (e ErasureEvidence) ObservedAt() time.Time {
	return erasureValueTime(e.record.ObservedAtMilliseconds)
}
func (e ErasureEvidence) ParentIdentities() []string {
	return append([]string(nil), e.record.ParentIdentities...)
}
func (e ErasureEvidence) RecordBytes() []byte {
	if !erasureMetadataHex(e.record.RecordHex, evidenceRecordLimit(e.record.Kind)) {
		return nil
	}
	body, _ := hex.DecodeString(e.record.RecordHex)
	return body
}
func (e ErasureEvidence) Ref() ErasureOperationRef { return e.ref }
func (e ErasureEvidence) String() string           { return "artifact erasure evidence" }
func (e ErasureEvidence) GoString() string         { return "artifact.ErasureEvidence{<redacted>}" }
func (e ErasureEvidence) Format(state fmt.State, verb rune) {
	formatErasureValue(state, verb, e.String(), e.GoString())
}

func cloneErasureMetadataScope(scope audit.ReviewScope) (audit.ReviewScope, error) {
	value, err := audit.NewReviewScope(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
	if err != nil {
		return audit.ReviewScope{}, ErrInvalidErasureContract
	}
	return value, nil
}

func responseFromEvidence(e ErasureEvidence) (attemptResponseRecord, error) {
	if e.Kind() != "response" {
		return attemptResponseRecord{}, ErrInvalidErasureContract
	}
	if err := e.Validate(); err != nil {
		return attemptResponseRecord{}, err
	}
	var response attemptResponseRecord
	if err := json.Unmarshal(e.RecordBytes(), &response); err != nil {
		return attemptResponseRecord{}, ErrInvalidErasureContract
	}
	return response, nil
}

func exactFenceResponse(op ErasureOperation, r attemptResponseRecord) error {
	if r.Code != "present" || r.ContentKind != "fence" || r.VersionKind != "data" {
		return ErrInvalidErasureContract
	}
	fence, err := NewErasureFence(op)
	if err != nil {
		return err
	}
	expected, err := EncodeErasureFence(fence)
	if err != nil {
		return err
	}
	body, _ := hex.DecodeString(r.RecordHex)
	if !bytes.Equal(body, expected) || r.ContentDigest != hashBytes(expected) || r.ResponseBytes != uint32(len(expected)) {
		return ErrErasureBindingMismatch
	}
	return nil
}

// NewFenceObservationEvidence uses the explicit key only as metadata. A later
// journal must match it to both the parent request and the accepted CURRENT key.
func NewFenceObservationEvidence(op ErasureOperation, key ExactObjectKey, response ErasureEvidence, at time.Time) (ErasureEvidence, error) {
	if !validErasureAuthorizationV2Time(at) {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if err := op.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	if err := key.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	r, err := responseFromEvidence(response)
	if err != nil {
		return ErasureEvidence{}, err
	}
	if r.Code != "present" || r.ContentKind != "fence" || r.VersionKind != "data" {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if key.NamespaceIdentity() != op.NamespaceIdentity() || response.Ref() != op.Ref() {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	if err := exactFenceResponse(op, r); err != nil {
		return ErasureEvidence{}, err
	}
	if at.Before(response.ObservedAt()) || at.Before(op.PreparedAt()) {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	version, err := NewObjectVersion(key.NamespaceIdentity(), key.Key(), ObjectVersionData, r.VersionID)
	if err != nil {
		return ErasureEvidence{}, err
	}
	encoded, err := EncodeObjectVersion(version)
	if err != nil {
		return ErasureEvidence{}, err
	}
	return newErasureEvidence(op.Ref(), "fence", "fence", "", at.UnixMilli(), []string{response.Identity()}, encoded)
}
