package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

func resumeResponseCode(err error) AttemptResponseCode {
	switch {
	case errors.Is(err, ErrErasureBlocked):
		return AttemptResponseDenied
	case errors.Is(err, ErrRemoteObjectConflict), errors.Is(err, ErrRemoteStoreConflict), errors.Is(err, ErrErasureConflict):
		return AttemptResponseConflict
	case errors.Is(err, ErrRemoteObjectIntegrity), errors.Is(err, ErrRemoteObjectTooLarge), errors.Is(err, ErrInvalidErasureContract):
		return AttemptResponseMalformed
	default:
		return AttemptResponseUnavailable
	}
}

func emptyResumeObject(o RemoteObject) bool {
	return len(o.Content) == 0 && o.Version == "" && o.Digest == ""
}

// Only exact content-free bytes enter evidence. No current ciphertext or legacy
// body survives this classification; the caller clears the backend buffer.
func (i *resumeInvocation) classifyRead(a ErasureAttempt, q resumeRequest, got ErasureObjectRead) (AttemptResponseOptions, error) {
	r := AttemptResponseOptions{Attempt: a}
	switch got.Kind {
	case ErasureReadAbsent:
		if !emptyResumeObject(got.Object) || got.Marker != (ObjectVersion{}) {
			return r, ErrRemoteObjectIntegrity
		}
		if q.kind == AttemptCurrentRead && i.pinned.Identity() != "" {
			return r, ErrErasureConflict
		}
		r.Code = AttemptResponseAbsent
	case ErasureReadCurrentDeleteMarker:
		if !emptyResumeObject(got.Object) || got.Marker.Validate() != nil || got.Marker.Kind() != ObjectVersionDeleteMarker ||
			got.Marker.Key() != q.key.Key() || got.Marker.NamespaceIdentity() != q.key.NamespaceIdentity() {
			return r, ErrRemoteObjectIntegrity
		}
		if q.legacy || q.kind != AttemptCurrentRead || i.pinned.Identity() != "" {
			return r, ErrErasureConflict
		}
		r.Code, r.ContentKind, r.Version = AttemptResponseAbsent, "delete_marker", got.Marker
	case ErasureReadPresent:
		if got.Marker != (ObjectVersion{}) || len(got.Object.Content) == 0 || uint64(len(got.Object.Content)) > uint64(q.maximum) ||
			!validAdmissionVersion(got.Object.Version) || !validDigest(got.Object.Digest) || hashBytes(got.Object.Content) != got.Object.Digest {
			return r, ErrRemoteObjectIntegrity
		}
		if q.legacy {
			return r, ErrErasureConflict
		}
		version, err := NewObjectVersion(q.key.NamespaceIdentity(), q.key.Key(), ObjectVersionData, strings.TrimPrefix(got.Object.Version, "version:"))
		if err != nil {
			return r, ErrRemoteObjectIntegrity
		}
		r.Code, r.Version, r.ContentDigest, r.ResponseBytes = AttemptResponsePresent, version, got.Object.Digest, uint32(len(got.Object.Content))
		switch q.kind {
		case AttemptCurrentRead:
			fence, err := NewErasureFence(i.operation)
			if err != nil {
				return r, err
			}
			canonical, err := EncodeErasureFence(fence)
			if err != nil {
				return r, err
			}
			if bytes.Equal(got.Object.Content, canonical) {
				if i.pinned.Identity() != "" && version != i.pinned {
					return r, ErrErasureConflict
				}
				r.ContentKind, r.CanonicalRecord = "fence", canonical
			} else {
				if bytes.HasPrefix(got.Object.Content, []byte("OTAF")) || i.pinned.Identity() != "" || len(q.expected) != 0 {
					return r, ErrErasureConflict
				}
				r.ContentKind = "ciphertext"
			}
		case AttemptIntentRead, AttemptAttestationRead:
			if len(q.expected) == 0 || !bytes.Equal(got.Object.Content, q.expected) {
				return r, ErrErasureConflict
			}
			r.ContentKind = "operation"
			if q.kind == AttemptAttestationRead {
				r.ContentKind = "attestation"
			}
			r.CanonicalRecord = append([]byte(nil), q.expected...)
		default:
			return r, ErrRemoteObjectIntegrity
		}
	default:
		return r, ErrRemoteObjectIntegrity
	}
	return r, nil
}

// A scan is private to one mutation-free discovery chain. Resetting it after
// every delete discards all provider continuation authority.
type versionScan struct {
	expected      VersionCursor
	cursors       map[VersionCursor]bool
	versions      map[string]bool
	pages, latest int
	done          bool
	required      ObjectVersion
}

func (*versionScan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure version scan{redacted}"))
}

func validateVersionScan(s *versionScan, key ExactObjectKey, input VersionCursor, limit uint16, maximum uint32, page VersionPage) error {
	if s == nil || s.done || key.Validate() != nil || input != s.expected || limit < 1 || limit > 256 ||
		maximum < 4096 || maximum > 1<<20 || page.ResponseBytes == 0 || page.ResponseBytes > maximum ||
		len(page.Entries) > int(limit) || s.pages >= 64 || len(s.versions)+len(page.Entries) > 4096 {
		return ErrRemoteObjectIntegrity
	}
	if input != (VersionCursor{}) && (input.KeyMarker != key.Key() || !validObjectVersionID(input.VersionIDMarker)) {
		return ErrRemoteObjectIntegrity
	}
	if page.Truncated {
		if len(page.Entries) == 0 || page.Next.KeyMarker != key.Key() || !validObjectVersionID(page.Next.VersionIDMarker) ||
			page.Next == input || s.cursors[page.Next] {
			return ErrRemoteObjectIntegrity
		}
	} else if page.Next != (VersionCursor{}) {
		return ErrRemoteObjectIntegrity
	}
	latest := s.latest
	seen := make(map[string]bool, len(page.Entries))
	for _, entry := range page.Entries {
		v := entry.Version
		if v.Validate() != nil || v.Key() != key.Key() || v.NamespaceIdentity() != key.NamespaceIdentity() ||
			seen[v.VersionID()] || s.versions[v.VersionID()] {
			return ErrRemoteObjectIntegrity
		}
		if s.required.Identity() != "" && v.VersionID() == s.required.VersionID() && v != s.required {
			return ErrRemoteObjectIntegrity
		}
		seen[v.VersionID()] = true
		if entry.IsLatest {
			latest++
		}
	}
	if latest > 1 || !page.Truncated && len(s.versions)+len(seen) != 0 && latest != 1 {
		return ErrRemoteObjectIntegrity
	}
	// Commit the local cursor state only after the entire page passes validation.
	if s.cursors == nil {
		s.cursors = make(map[VersionCursor]bool)
	}
	if s.versions == nil {
		s.versions = make(map[string]bool)
	}
	s.cursors[input] = true
	for id := range seen {
		s.versions[id] = true
	}
	s.pages++
	s.latest, s.expected, s.done = latest, page.Next, !page.Truncated
	return nil
}

func validateTerminalFencePage(observation resumeObservation, key ExactObjectKey, pinned ObjectVersion) error {
	r, p := observation.attempt.Request(), observation.response.Page
	if observation.response.Code != AttemptResponsePresent || r.Kind() != AttemptVersionList || r.Key() != key.Key() ||
		r.NamespaceIdentity() != key.NamespaceIdentity() || r.KeyMarker() != "" || r.VersionIDMarker() != "" || r.PageLimit() != 2 ||
		p.Truncated || p.Next != (VersionCursor{}) || len(p.Entries) != 1 || !p.Entries[0].IsLatest ||
		p.Entries[0].Version.Kind() != ObjectVersionData || p.Entries[0].Version != pinned {
		return ErrErasureConflict
	}
	return nil
}
