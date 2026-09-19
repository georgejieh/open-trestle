package artifact

import (
	"encoding/hex"
	"time"
)

// AttemptResponseCode describes metadata, not a provider error or permission.
type AttemptResponseCode uint8

const (
	AttemptResponsePresent       AttemptResponseCode = 1
	AttemptResponseAbsent        AttemptResponseCode = 2
	AttemptResponseCreated       AttemptResponseCode = 3
	AttemptResponseConditionLost AttemptResponseCode = 4
	AttemptResponseDeleted       AttemptResponseCode = 5
	AttemptResponseNotFound      AttemptResponseCode = 6
	AttemptResponseConflict      AttemptResponseCode = 7
	AttemptResponseDenied        AttemptResponseCode = 8
	AttemptResponseMalformed     AttemptResponseCode = 9
	AttemptResponseUnavailable   AttemptResponseCode = 10
	AttemptResponseAbandoned     AttemptResponseCode = 11
)

func (c AttemptResponseCode) String() string {
	switch c {
	case AttemptResponsePresent:
		return "present"
	case AttemptResponseAbsent:
		return "absent"
	case AttemptResponseCreated:
		return "created"
	case AttemptResponseConditionLost:
		return "condition_lost"
	case AttemptResponseDeleted:
		return "deleted"
	case AttemptResponseNotFound:
		return "not_found"
	case AttemptResponseConflict:
		return "conflict"
	case AttemptResponseDenied:
		return "denied"
	case AttemptResponseMalformed:
		return "malformed"
	case AttemptResponseUnavailable:
		return "unavailable"
	case AttemptResponseAbandoned:
		return "abandoned"
	default:
		return ""
	}
}

// AttemptResponseOptions contains supplied observations and complete request metadata.
// Ciphertext digests and list byte counts remain claims; ciphertext is not retained.
type AttemptResponseOptions struct {
	Attempt         ErasureAttempt
	Code            AttemptResponseCode
	ObservedAt      time.Time
	Version         ObjectVersion
	ContentKind     string
	ContentDigest   string
	CanonicalRecord []byte
	Page            VersionPage
	ResponseBytes   uint32
}

func responseCodeAllowed(kind AttemptKind, code AttemptResponseCode) bool {
	if kind < AttemptCurrentRead || kind > AttemptAttestationCreate {
		return false
	}
	switch code {
	case AttemptResponsePresent:
		return kind >= AttemptCurrentRead && kind <= AttemptVersionList
	case AttemptResponseAbsent:
		return kind >= AttemptCurrentRead && kind <= AttemptAttestationRead
	case AttemptResponseCreated, AttemptResponseConditionLost:
		return kind == AttemptIntentCreate || kind == AttemptFenceCreate || kind == AttemptAttestationCreate
	case AttemptResponseDeleted, AttemptResponseNotFound:
		return kind == AttemptVersionDelete
	case AttemptResponseConflict, AttemptResponseDenied, AttemptResponseMalformed, AttemptResponseUnavailable, AttemptResponseAbandoned:
		return true
	default:
		return false
	}
}

func responseVersionKind(kind ObjectVersionKind) string {
	switch kind {
	case ObjectVersionData:
		return "data"
	case ObjectVersionDeleteMarker:
		return "delete_marker"
	default:
		return ""
	}
}

func emptyResponsePage(page VersionPage) bool {
	return len(page.Entries) == 0 && page.Next == (VersionCursor{}) && !page.Truncated && page.ResponseBytes == 0
}

// NewAttemptResponseEvidence checks supplied request relations without retaining
// the request or an accepted witness. Uncertainty persistence belongs to a journal.
func NewAttemptResponseEvidence(o AttemptResponseOptions) (ErasureEvidence, error) {
	if !validErasureAuthorizationV2Time(o.ObservedAt) || len(o.ContentKind) > 13 || len(o.ContentDigest) > 64 ||
		len(o.CanonicalRecord) > responseBodyLimit(o.ContentKind) || len(o.Page.Entries) > 256 ||
		len(o.Page.Next.KeyMarker) > 1024 || len(o.Page.Next.VersionIDMarker) > 504 {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if err := o.Attempt.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	request := o.Attempt.Request()
	if err := request.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	if !responseCodeAllowed(request.Kind(), o.Code) || o.ResponseBytes > request.MaximumResponseBytes() {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	list := request.Kind() == AttemptVersionList && o.Code == AttemptResponsePresent
	read := request.Kind() >= AttemptCurrentRead && request.Kind() <= AttemptAttestationRead && o.Code == AttemptResponsePresent
	marker := request.Kind() == AttemptCurrentRead && o.Code == AttemptResponseAbsent && o.ContentKind == "delete_marker"
	if !list && !emptyResponsePage(o.Page) {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if !read && !marker && o.Version != (ObjectVersion{}) {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if read {
		allowed := request.Kind() == AttemptCurrentRead && (o.ContentKind == "ciphertext" || o.ContentKind == "fence") ||
			request.Kind() == AttemptIntentRead && o.ContentKind == "operation" || request.Kind() == AttemptAttestationRead && o.ContentKind == "attestation"
		if !allowed || o.Version.Kind() != ObjectVersionData {
			return ErasureEvidence{}, ErrInvalidErasureContract
		}
	}
	if o.Code == AttemptResponseAbsent && o.ContentKind == "delete_marker" && !marker {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if marker && o.Version.Kind() != ObjectVersionDeleteMarker {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if read || marker {
		if err := o.Version.Validate(); err != nil {
			return ErasureEvidence{}, err
		}
	}
	r := attemptResponseRecord{Contract: attemptResponseContract, SchemaVersion: 1,
		OperationIdentity: request.OperationIdentity(), AttemptIdentity: o.Attempt.Identity(), ObservedAtMilliseconds: o.ObservedAt.UnixMilli(),
		Code: o.Code.String(), ContentKind: o.ContentKind, VersionKind: responseVersionKind(o.Version.Kind()), VersionID: o.Version.VersionID(),
		ContentDigest: o.ContentDigest, RecordHex: hex.EncodeToString(o.CanonicalRecord), ResponseBytes: o.ResponseBytes,
		Entries: []attemptResponseEntry{}, KeyMarker: o.Page.Next.KeyMarker, VersionIDMarker: o.Page.Next.VersionIDMarker, Truncated: o.Page.Truncated}
	if list {
		if len(o.Page.Entries) > int(request.PageLimit()) || o.Page.ResponseBytes < 1 || o.Page.ResponseBytes > request.MaximumResponseBytes() {
			return ErasureEvidence{}, ErrInvalidErasureContract
		}
		latest := 0
		for _, entry := range o.Page.Entries {
			if err := entry.Version.Validate(); err != nil {
				return ErasureEvidence{}, err
			}
			r.Entries = append(r.Entries, attemptResponseEntry{entry.Version.Identity(), responseVersionKind(entry.Version.Kind()), entry.Version.VersionID(), entry.IsLatest})
			if entry.IsLatest {
				latest++
			}
		}
		if len(r.Entries) > 0 && request.KeyMarker() == "" && !r.Truncated && latest != 1 {
			return ErasureEvidence{}, ErrInvalidErasureContract
		}
		if r.Truncated && r.KeyMarker == request.KeyMarker() && r.VersionIDMarker == request.VersionIDMarker() {
			return ErasureEvidence{}, ErrInvalidErasureContract
		}
	}
	// A temporary well-shaped identity permits the same structural validation
	// used by parsers before any dependency binding or identity derivation.
	r.Identity = request.OperationIdentity()
	if err := r.shape(); err != nil {
		return ErasureEvidence{}, err
	}
	if err := responseBodyShape(r); err != nil {
		return ErasureEvidence{}, err
	}
	if _, err := erasureMetadataEncode(r, maxEncodedAttemptResponseBytes); err != nil {
		return ErasureEvidence{}, err
	}
	labels, err := inspectResponseBody(r, request.Scope())
	if err != nil {
		return ErasureEvidence{}, err
	}
	if err := responseBodyClaims(r); err != nil {
		return ErasureEvidence{}, err
	}
	if o.ObservedAt.Before(o.Attempt.ReservedAt()) {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	if (read || marker) && (o.Version.NamespaceIdentity() != request.NamespaceIdentity() || o.Version.Key() != request.Key()) {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	if list {
		if o.Page.ResponseBytes != o.ResponseBytes {
			return ErasureEvidence{}, ErrErasureBindingMismatch
		}
		for _, entry := range o.Page.Entries {
			if entry.Version.NamespaceIdentity() != request.NamespaceIdentity() || entry.Version.Key() != request.Key() {
				return ErasureEvidence{}, ErrErasureBindingMismatch
			}
		}
		if r.Truncated && r.KeyMarker != request.Key() {
			return ErasureEvidence{}, ErrErasureBindingMismatch
		}
	}
	if r.RecordHex != "" {
		if labels.namespace != request.NamespaceIdentity() || labels.scope != request.ScopeIdentity() || labels.operation != request.OperationIdentity() || labels.artifact != request.ArtifactIdentity() {
			return ErasureEvidence{}, ErrErasureBindingMismatch
		}
		if r.ContentKind != "fence" && (labels.admission != request.AdmissionIdentity() || labels.authorization != request.OriginalAuthorizationIdentity() || labels.document != request.AuthorizationDocumentDigest()) {
			return ErasureEvidence{}, ErrErasureBindingMismatch
		}
	}
	r.Identity = responseRecordIdentity(r)
	encoded, err := erasureMetadataEncode(r, maxEncodedAttemptResponseBytes)
	if err != nil {
		return ErasureEvidence{}, err
	}
	ref, err := NewErasureOperationRef(request.Scope(), request.NamespaceIdentity(), request.OperationIdentity())
	if err != nil {
		return ErasureEvidence{}, err
	}
	return newErasureEvidence(ref, "response", "response:"+o.Attempt.Identity(), o.Attempt.Identity(), o.ObservedAt.UnixMilli(), nil, encoded)
}

func NewAttemptUnknownEvidence(attempt ErasureAttempt, at time.Time) (ErasureEvidence, error) {
	if !validErasureAuthorizationV2Time(at) {
		return ErasureEvidence{}, ErrInvalidErasureContract
	}
	if err := attempt.Validate(); err != nil {
		return ErasureEvidence{}, err
	}
	if at.Before(attempt.ReservedAt()) {
		return ErasureEvidence{}, ErrErasureBindingMismatch
	}
	request := attempt.Request()
	ref, err := NewErasureOperationRef(request.Scope(), request.NamespaceIdentity(), request.OperationIdentity())
	if err != nil {
		return ErasureEvidence{}, err
	}
	return newErasureEvidence(ref, "unknown", "unknown:"+attempt.Identity(), attempt.Identity(), at.UnixMilli(), nil, nil)
}
