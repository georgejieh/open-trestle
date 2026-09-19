package artifact

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

// Immutable per-store routing. Only the new constructor installs this mode.
type envelopeAdmissionMode struct {
	journal   AdmissionPreparationJournal
	policy    ProtectedErasurePolicy
	namespace StorageNamespace
	clock     ErasureClock
}

func (envelopeAdmissionMode) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact admission mode{redacted}"))
}

// A permit belongs to one live Put stack, never a persisted admission or read.
type putPermit struct {
	consumed          atomic.Bool
	admissionIdentity string
}

func (p *putPermit) consume(a ArtifactAdmission) bool {
	return p != nil && a.Validate() == nil && p.admissionIdentity == a.Identity() && p.consumed.CompareAndSwap(false, true)
}
func (*putPermit) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact Put permit{redacted}"))
}

// NewEnvelopeStoreWithAdmissionPreparation accepts trusted database-only journal
// dependencies. The concrete same-index PostgreSQL/S3 factory is the eligible
// production composition; this interface is not an in-process security sandbox.
func NewEnvelopeStoreWithAdmissionPreparation(o EnvelopeAdmissionPreparationOptions) (*EnvelopeStore, error) {
	if nilErasureDependency(o.Backend) || o.Backend.Validate() != nil {
		return nil, ErrErasureBackendUnsupported
	}
	if nilErasureDependency(o.Keys) || nilErasureDependency(o.Clock) {
		return nil, ErrInvalidRemoteStore
	}
	if nilErasureDependency(o.Journal) {
		return nil, ErrErasureJournalRequired
	}
	if o.Policy.Validate() != nil {
		return nil, ErrErasureAuthorityRequired
	}
	n, err := NewStorageNamespace(o.Backend.ConfigurationIdentity(), o.Policy.Prefix(), o.Policy.NamespaceEpochIdentity())
	if err != nil || n.Identity() != o.Policy.NamespaceIdentity() || o.Policy.BackendKind() != "aws_s3_general_purpose" ||
		o.Policy.NamespaceMode() != "protected_new_nonnull" || o.Policy.Protocol() != "same-key-fence-v2" || o.Policy.Ownership() != "all_versions_at_exact_key" {
		return nil, ErrErasureNamespaceUnsupported
	}
	if !validDigest(o.Journal.DatabaseAuthorityIdentity()) || o.Policy.DatabaseAuthorityIdentity() != o.Journal.DatabaseAuthorityIdentity() {
		return nil, ErrErasureBindingMismatch
	}
	s, err := NewEnvelopeStore(o.Policy.Prefix(), o.Backend, o.Keys)
	if err != nil {
		return nil, err
	}
	s.admission = &envelopeAdmissionMode{journal: o.Journal, policy: o.Policy, namespace: n, clock: o.Clock}
	return s, nil
}

func (s *EnvelopeStore) admissionMode(ctx context.Context) (*envelopeAdmissionMode, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if s == nil || s.admission == nil {
		return nil, ErrErasureJournalRequired
	}
	m := s.admission
	if nilErasureDependency(m.journal) || nilErasureDependency(m.clock) {
		return nil, ErrErasureJournalRequired
	}
	if m.policy.Validate() != nil {
		return nil, ErrErasureAuthorityRequired
	}
	if m.namespace.Validate() != nil || m.namespace.Identity() != m.policy.NamespaceIdentity() || m.policy.DatabaseAuthorityIdentity() != m.journal.DatabaseAuthorityIdentity() {
		return nil, ErrErasureBindingMismatch
	}
	return m, nil
}

func (s *EnvelopeStore) putAdmittedArtifact(ctx context.Context, value Artifact, at time.Time) (bool, error) {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return false, err
	}
	now := m.clock.Now() // Sampled decision time, not observed commit time.
	if !validErasureAuthorizationV2Time(at) || !validErasureAuthorizationV2Time(now) || at.After(now) {
		return false, ErrInvalidErasureContract
	}
	if err := validatePut(ctx, value, now); err != nil {
		return false, err
	}
	if at.Before(value.CreatedAt()) || now.Before(value.CreatedAt()) || !m.policy.AllowsAt(at) || !m.policy.AllowsAt(now) {
		return false, ErrErasureBindingMismatch
	}
	candidate, err := NewArtifactAdmission(value, m.namespace.Identity(), now)
	if err != nil {
		return false, err
	}
	a, inserted, err := m.journal.AdmitArtifact(ctx, candidate)
	if err != nil {
		return false, err
	}
	if !admissionMatchesArtifact(a, value) || a.NamespaceIdentity() != m.namespace.Identity() {
		return false, ErrErasureConflict
	}
	var permit *putPermit
	if inserted {
		permit = &putPermit{admissionIdentity: a.Identity()}
	}
	// Even legacy reads occur only after the known admission commit.
	if err := s.refuseAdmissionLegacyObjects(ctx, a); err != nil {
		return false, err
	}
	// For a new admission, object presence is contamination, not deduplication.
	if inserted {
		object, readErr := s.backend.Read(ctx, s.artifactObjectKey(a.Scope(), a.ArtifactIdentity()), maxRemoteArtifactBytes)
		clear(object.Content)
		if readErr == nil {
			return false, ErrErasureLegacyInventoryRequired
		}
		if !errors.Is(readErr, ErrRemoteObjectNotFound) {
			return false, mapRemoteReadError(readErr)
		}
	} else {
		_, object, found, readErr := s.readAdmissionObject(ctx, a)
		if readErr != nil {
			return false, readErr
		}
		if !found {
			return false, ErrErasureUnknownOutcome
		}
		if err := s.confirmAdmissionObject(ctx, a, object); err != nil {
			return false, err
		}
		return false, nil
	}
	if err := validateContext(ctx); err != nil {
		return false, err
	}
	if !permit.consume(a) {
		return false, ErrErasureUnknownOutcome
	}
	encoded, err := Encode(value)
	if err != nil {
		return false, err
	}
	defer clear(encoded)
	object, err := s.encryptArtifact(ctx, value, encoded)
	if err != nil {
		return false, err
	}
	created, err := s.backend.Create(ctx, s.artifactObjectKey(a.Scope(), a.ArtifactIdentity()), object, hashBytes(object))
	clear(object)
	if err != nil {
		return false, mapRemoteMutationError(err)
	}
	// Create's bool contains no version authority. Never repeat it, even on false.
	_, observed, found, err := s.readAdmissionObject(ctx, a)
	if err != nil {
		return false, err
	}
	if !found {
		return false, ErrErasureUnknownOutcome
	}
	if err := s.confirmAdmissionObject(ctx, a, observed); err != nil {
		return false, err
	}
	return created, nil
}

func admissionMatchesArtifact(a ArtifactAdmission, v Artifact) bool {
	if a.Validate() != nil || v.Validate() != nil {
		return false
	}
	projected, err := NewArtifactAdmission(v, a.NamespaceIdentity(), a.AdmittedAt())
	if err != nil {
		return false
	}
	left, err := EncodeArtifactAdmission(a)
	if err != nil {
		return false
	}
	right, err := EncodeArtifactAdmission(projected)
	return err == nil && bytes.Equal(left, right)
}

func validAdmissionVersion(version string) bool {
	if len(version) < 9 || len(version) > 512 || !utf8.ValidString(version) || !strings.HasPrefix(version, "version:") || version == "version:null" {
		return false
	}
	for _, r := range version {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *EnvelopeStore) refuseAdmissionLegacyObjects(ctx context.Context, a ArtifactAdmission) error {
	for _, key := range []string{s.deletionReceiptObjectKey(a.Scope(), a.ArtifactIdentity()), s.deletionIntentObjectKey(a.Scope(), a.ArtifactIdentity())} {
		object, err := s.backend.Read(ctx, key, maxEncodedDeletionRecordBytes)
		clear(object.Content)
		if err == nil {
			return ErrErasureLegacyInventoryRequired
		}
		if !errors.Is(err, ErrRemoteObjectNotFound) {
			return mapRemoteReadError(err)
		}
	}
	return nil
}

// readAdmissionObject clears ciphertext and returns only the observed token and
// digest alongside the decrypted artifact. It never confirms or mints permits.
func (s *EnvelopeStore) readAdmissionObject(ctx context.Context, a ArtifactAdmission) (Artifact, RemoteObject, bool, error) {
	object, err := s.backend.Read(ctx, s.artifactObjectKey(a.Scope(), a.ArtifactIdentity()), maxRemoteArtifactBytes)
	defer clear(object.Content)
	if errors.Is(err, ErrRemoteObjectNotFound) {
		return Artifact{}, RemoteObject{}, false, nil
	}
	if err != nil {
		return Artifact{}, RemoteObject{}, false, mapRemoteReadError(err)
	}
	if !validAdmissionVersion(object.Version) {
		return Artifact{}, RemoteObject{}, false, ErrRemoteStoreConflict
	}
	v, err := s.decryptRemoteObject(ctx, a.Scope(), a.ArtifactIdentity(), object)
	if err != nil {
		return Artifact{}, RemoteObject{}, false, err
	}
	if !admissionMatchesArtifact(a, v) {
		return Artifact{}, RemoteObject{}, false, ErrErasureConflict
	}
	return v, RemoteObject{Version: object.Version, Digest: object.Digest}, true, nil
}

func (s *EnvelopeStore) confirmAdmissionObject(ctx context.Context, a ArtifactAdmission, object RemoteObject) error {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return err
	}
	now := m.clock.Now()
	if !validErasureAuthorizationV2Time(now) || now.Before(a.AdmittedAt()) {
		return ErrInvalidErasureContract
	}
	if !now.Before(a.ExpiresAt()) {
		return ErrArtifactExpired
	}
	if !m.policy.AllowsAt(now) {
		return ErrErasureBindingMismatch
	}
	return m.journal.ConfirmAdmission(ctx, a, object.Version, object.Digest, now)
}

func (s *EnvelopeStore) getAdmittedArtifact(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (Artifact, error) {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return Artifact{}, err
	}
	now := m.clock.Now()
	if !validErasureAuthorizationV2Time(at) || !validErasureAuthorizationV2Time(now) || at.After(now) {
		return Artifact{}, ErrInvalidErasureContract
	}
	a, found, err := m.journal.ReadAdmission(ctx, scope, m.namespace.Identity(), identity)
	if err != nil {
		return Artifact{}, err
	}
	if !found {
		return Artifact{}, ErrErasureAdmissionMissing
	}
	if _, prepared, err := m.journal.FindPreparedErasure(ctx, scope, a.NamespaceIdentity(), identity); err != nil {
		return Artifact{}, err
	} else if prepared {
		return Artifact{}, ErrArtifactDeleted
	}
	if !at.Before(a.ExpiresAt()) || !now.Before(a.ExpiresAt()) {
		return Artifact{}, ErrArtifactExpired
	}
	if at.Before(a.CreatedAt()) {
		return Artifact{}, ErrErasureBindingMismatch
	}
	if err := s.refuseAdmissionLegacyObjects(ctx, a); err != nil {
		return Artifact{}, err
	}
	v, _, found, err := s.readAdmissionObject(ctx, a)
	if err != nil {
		return Artifact{}, err
	}
	if !found {
		return Artifact{}, ErrErasureUnknownOutcome
	}
	// Require the original admission and no preparation in the same final snapshot.
	// No database lock crosses object or key-provider I/O.
	if err := m.journal.CheckAdmissionReadable(ctx, a); err != nil {
		return Artifact{}, err
	}
	return v, nil
}

func (s *EnvelopeStore) ReadAdmission(ctx context.Context, scope audit.ReviewScope, namespace, identity string) (ArtifactAdmission, bool, error) {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return ArtifactAdmission{}, false, err
	}
	return m.journal.ReadAdmission(ctx, scope, namespace, identity)
}
func (s *EnvelopeStore) PrepareErasure(ctx context.Context, grant ErasureAuthorizationV2, at time.Time) (ErasureOperation, error) {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return ErasureOperation{}, err
	}
	operation, _, err := m.journal.AcceptErasure(ctx, grant, at)
	if err != nil {
		return ErasureOperation{}, err
	}
	return operation, nil
}
func (s *EnvelopeStore) ReadPreparedErasure(ctx context.Context, ref ErasureOperationRef) (ErasureOperation, bool, error) {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return ErasureOperation{}, false, err
	}
	return m.journal.ReadPreparedErasure(ctx, ref)
}
func (s *EnvelopeStore) FindPreparedErasure(ctx context.Context, scope audit.ReviewScope, namespace, identity string) (ErasureOperation, bool, error) {
	m, err := s.admissionMode(ctx)
	if err != nil {
		return ErasureOperation{}, false, err
	}
	return m.journal.FindPreparedErasure(ctx, scope, namespace, identity)
}

func nilErasureDependency(value any) bool {
	if value == nil {
		return true
	}
	r := reflect.ValueOf(value)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return r.IsNil()
	}
	return false
}
