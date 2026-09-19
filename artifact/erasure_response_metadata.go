package artifact

import (
	"bytes"
	"encoding/hex"
)

// ParseAttemptResponseEvidence checks the full supplied request and response.
// It returns copied metadata and cannot restore a reservation permit.
func ParseAttemptResponseEvidence(e ErasureEvidence, attempt ErasureAttempt) (AttemptResponseOptions, error) {
	if err := attempt.Validate(); err != nil {
		return AttemptResponseOptions{}, err
	}
	r, err := responseFromEvidence(e)
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	request := attempt.Request()
	ref, err := NewErasureOperationRef(request.Scope(), request.NamespaceIdentity(), request.OperationIdentity())
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	if e.Ref() != ref || e.AttemptIdentity() != attempt.Identity() || r.AttemptIdentity != attempt.Identity() ||
		r.OperationIdentity != request.OperationIdentity() || e.ObservedAt().Before(attempt.ReservedAt()) {
		return AttemptResponseOptions{}, ErrErasureBindingMismatch
	}
	o := AttemptResponseOptions{Attempt: attempt, ObservedAt: e.ObservedAt(), ContentKind: r.ContentKind,
		ContentDigest: r.ContentDigest, ResponseBytes: r.ResponseBytes}
	for c := AttemptResponsePresent; c <= AttemptResponseAbandoned; c++ {
		if c.String() == r.Code {
			o.Code = c
			break
		}
	}
	if r.VersionKind != "" {
		kind := ObjectVersionData
		if r.VersionKind == "delete_marker" {
			kind = ObjectVersionDeleteMarker
		}
		o.Version, err = NewObjectVersion(request.NamespaceIdentity(), request.Key(), kind, r.VersionID)
		if err != nil {
			return AttemptResponseOptions{}, err
		}
	}
	if request.Kind() == AttemptVersionList && o.Code == AttemptResponsePresent {
		o.Page = VersionPage{Entries: make([]VersionEntry, 0, len(r.Entries)),
			Next:      VersionCursor{KeyMarker: r.KeyMarker, VersionIDMarker: r.VersionIDMarker},
			Truncated: r.Truncated, ResponseBytes: r.ResponseBytes}
		for _, entry := range r.Entries {
			kind := ObjectVersionData
			if entry.Kind == "delete_marker" {
				kind = ObjectVersionDeleteMarker
			}
			version, err := NewObjectVersion(request.NamespaceIdentity(), request.Key(), kind, entry.VersionID)
			if err != nil {
				return AttemptResponseOptions{}, err
			}
			if version.Identity() != entry.VersionIdentity {
				return AttemptResponseOptions{}, ErrErasureBindingMismatch
			}
			o.Page.Entries = append(o.Page.Entries, VersionEntry{Version: version, IsLatest: entry.IsLatest})
		}
	}
	o.CanonicalRecord, err = hex.DecodeString(r.RecordHex)
	if err != nil {
		return AttemptResponseOptions{}, ErrInvalidErasureContract
	}
	// Clone the request as well as response payloads. Neither retains authority.
	request, err = request.clone()
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	o.Attempt, err = NewErasureAttempt(request, attempt.Sequence(), attempt.ReservedAt())
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	rebuilt, err := NewAttemptResponseEvidence(o)
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	expected, err := erasureMetadataEncode(e.record, maxEncodedErasureEvidenceBytes)
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	actual, err := erasureMetadataEncode(rebuilt.record, maxEncodedErasureEvidenceBytes)
	if err != nil {
		return AttemptResponseOptions{}, err
	}
	if !bytes.Equal(expected, actual) {
		return AttemptResponseOptions{}, ErrErasureBindingMismatch
	}
	return o, nil
}
