package artifact

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	remoteEnvelopeMagic          = "OTAE0001"
	remoteEnvelopeNonceBytes     = 12
	maxRemoteEnvelopeHeaderBytes = 16 << 10
	maxRemoteArtifactBytes       = maxEncodedArtifactBytes + maxRemoteEnvelopeHeaderBytes + 64
	maxWrappedDataKeyBytes       = 16 << 10
	maxKeyReferenceBytes         = 256
	maxObjectVersionBytes        = 512
	maxObjectPrefixBytes         = 128
)

var (
	// ErrRemoteObjectNotFound is returned by a backend when an exact key is absent.
	ErrRemoteObjectNotFound = errors.New("remote object not found")
	// ErrRemoteObjectConflict is returned by a backend when conditional mutation loses a race.
	ErrRemoteObjectConflict = errors.New("remote object version conflict")
	// ErrRemoteObjectTooLarge is returned before an excessive body is materialized.
	ErrRemoteObjectTooLarge = errors.New("remote object exceeds size limit")
	// ErrRemoteObjectIntegrity identifies backend checksum or immutable metadata failure.
	ErrRemoteObjectIntegrity = errors.New("remote object integrity failure")
	// ErrRemoteStorePersistence identifies an unavailable or failed object backend.
	ErrRemoteStorePersistence = errors.New("remote artifact store persistence failure")
	// ErrRemoteStoreConflict identifies a changed object at an immutable key.
	ErrRemoteStoreConflict = errors.New("remote artifact store conflict")
	// ErrEnvelopeKeyUnavailable identifies a failed tenant key operation.
	ErrEnvelopeKeyUnavailable = errors.New("artifact envelope key unavailable")
	// ErrInvalidEnvelopeKey identifies unsafe data-key material or metadata.
	ErrInvalidEnvelopeKey = errors.New("invalid artifact envelope key")
	// ErrInvalidRemoteStore identifies a malformed backend, key provider, or key prefix.
	ErrInvalidRemoteStore = errors.New("invalid remote artifact store")
)

// RemoteObject is a bounded, versioned object returned by an object-storage backend.
type RemoteObject struct {
	Content []byte
	Version string
	Digest  string
}

func (o RemoteObject) validate(maximum int) error {
	validContent := len(o.Content) > 0 && len(o.Content) <= maximum
	validMetadata := validRemoteValue(o.Version, maxObjectVersionBytes) && validDigest(o.Digest)
	if !validContent || !validMetadata || hashBytes(o.Content) != o.Digest {
		return ErrCorruptArtifact
	}
	return nil
}

func (o RemoteObject) String() string   { return "remote artifact object" }
func (o RemoteObject) GoString() string { return "artifact.RemoteObject{<redacted>}" }
func (o RemoteObject) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "remote artifact object", "artifact.RemoteObject{<redacted>}")
}

// RemoteObjectBackend supplies bounded conditional single-object operations.
// Create must atomically refuse an existing key and durably retain content before returning true.
// Read must enforce maximum before materializing content and return an immutable version token.
// Delete must remove only the supplied version. Implementations must not silently use unconditional deletion.
type RemoteObjectBackend interface {
	Create(context.Context, string, []byte, string) (bool, error)
	Read(context.Context, string, int) (RemoteObject, error)
	Delete(context.Context, string, string) (bool, error)
}

// EnvelopeDataKey carries one plaintext data key and its externally wrapped form.
type EnvelopeDataKey struct {
	plaintext    [32]byte
	keyReference string
	wrapped      []byte
}

// NewEnvelopeDataKey constructs provider output. The wrapped bytes must differ from plaintext.
func NewEnvelopeDataKey(plaintext [32]byte, keyReference string, wrapped []byte) (EnvelopeDataKey, error) {
	value := EnvelopeDataKey{plaintext: plaintext, keyReference: strings.Clone(keyReference), wrapped: append([]byte(nil), wrapped...)}
	return admitEnvelopeDataKey(&value)
}
func admitEnvelopeDataKey(value *EnvelopeDataKey) (EnvelopeDataKey, error) {
	if value == nil || value.validate() != nil {
		value.clear()
		return EnvelopeDataKey{}, ErrInvalidEnvelopeKey
	}
	return *value, nil
}

func (k *EnvelopeDataKey) clear() {
	if k == nil {
		return
	}
	clear(k.plaintext[:])
	clear(k.wrapped)
	k.keyReference = ""
}

func (k EnvelopeDataKey) validate() error {
	allZero := true
	for _, value := range k.plaintext {
		allZero = allZero && value == 0
	}
	unsafeWrap := len(k.wrapped) == len(k.plaintext) && bytes.Equal(k.wrapped, k.plaintext[:])
	if allZero || unsafeWrap || !validRemoteValue(k.keyReference, maxKeyReferenceBytes) || len(k.wrapped) == 0 || len(k.wrapped) > maxWrappedDataKeyBytes {
		return ErrInvalidEnvelopeKey
	}
	return nil
}

func (k EnvelopeDataKey) String() string   { return "artifact envelope data key" }
func (k EnvelopeDataKey) GoString() string { return "artifact.EnvelopeDataKey{<redacted>}" }
func (k EnvelopeDataKey) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "artifact envelope data key", "artifact.EnvelopeDataKey{<redacted>}")
}

// EnvelopeKeyProvider creates and unwraps data keys under a tenant-specific wrapping key.
// Implementations join ErrInvalidEnvelopeKey for deterministic malformed or cross-wired output; other operation errors are treated as unavailable.
type EnvelopeKeyProvider interface {
	GenerateDataKey(context.Context, string) (EnvelopeDataKey, error)
	UnwrapDataKey(context.Context, string, string, []byte) ([32]byte, error)
}

// VerifyEnvelopeKeyProvider performs one tenant-bound generate and unwrap round trip without retaining key material.
func VerifyEnvelopeKeyProvider(ctx context.Context, tenantID string, provider EnvelopeKeyProvider) error {
	if ctx == nil || ctx.Err() != nil || nilInterface(provider) {
		return ErrEnvelopeKeyUnavailable
	}
	if _, err := audit.NewReviewScope(tenantID, "secret-backend", "conformance"); err != nil {
		return ErrInvalidEnvelopeKey
	}
	key, err := provider.GenerateDataKey(ctx, tenantID)
	defer key.clear()
	if err != nil {
		return err
	}
	if key.validate() != nil {
		return ErrInvalidEnvelopeKey
	}
	wrapped := append([]byte(nil), key.wrapped...)
	defer clear(wrapped)
	unwrapped, err := provider.UnwrapDataKey(ctx, tenantID, key.keyReference, wrapped)
	defer clear(unwrapped[:])
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(key.plaintext[:], unwrapped[:]) != 1 {
		return ErrInvalidEnvelopeKey
	}
	return nil
}

// EnvelopeStore encrypts artifacts client-side before conditional object storage.
type EnvelopeStore struct {
	prefix    string
	backend   RemoteObjectBackend
	keys      EnvelopeKeyProvider
	admission *envelopeAdmissionMode
	resume    *envelopeErasureMode
}

// NewEnvelopeStore creates a store whose object names are opaque scope and artifact identities.
func NewEnvelopeStore(prefix string, backend RemoteObjectBackend, keys EnvelopeKeyProvider) (*EnvelopeStore, error) {
	prefix = strings.TrimSuffix(prefix, "/")
	if !validObjectPrefix(prefix) || nilInterface(backend) || nilInterface(keys) {
		return nil, ErrInvalidRemoteStore
	}
	return &EnvelopeStore{prefix: strings.Clone(prefix), backend: backend, keys: keys}, nil
}

func (s *EnvelopeStore) Put(ctx context.Context, value Artifact, at time.Time) (bool, error) {
	if err := validatePut(ctx, value, at); err != nil {
		return false, err
	}
	if s == nil || nilInterface(s.backend) || nilInterface(s.keys) {
		return false, ErrInvalidRemoteStore
	}
	if value.Protection() != ProtectionEnvelopeEncrypted {
		return false, ErrStoreProtectionMismatch
	}
	if s.admission != nil {
		return s.putAdmittedArtifact(ctx, value, at)
	}
	deleted, err := s.deletionExists(ctx, value.Scope(), value.Identity())
	if err != nil {
		return false, err
	}
	if deleted {
		return false, ErrArtifactDeleted
	}
	key := s.artifactObjectKey(value.Scope(), value.Identity())
	if existing, found, readErr := s.readArtifact(ctx, value.Scope(), value.Identity()); readErr != nil {
		return false, readErr
	} else if found {
		if existing.Identity() != value.Identity() {
			return false, ErrCorruptArtifact
		}
		return false, nil
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
	created, err := s.backend.Create(ctx, key, object, hashBytes(object))
	clear(object)
	if err != nil {
		return false, mapRemoteMutationError(err)
	}
	if created {
		existing, found, verifyErr := s.readArtifact(ctx, value.Scope(), value.Identity())
		if verifyErr != nil || !found || existing.Identity() != value.Identity() {
			if verifyErr != nil {
				return false, verifyErr
			}
			return false, ErrRemoteStoreConflict
		}
		return true, nil
	}
	existing, found, err := s.readArtifact(ctx, value.Scope(), value.Identity())
	if err != nil {
		return false, err
	}
	if !found || existing.Identity() != value.Identity() {
		return false, ErrRemoteStoreConflict
	}
	return false, nil
}

func (s *EnvelopeStore) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (Artifact, error) {
	if err := validateGet(ctx, scope, identity, at); err != nil {
		return Artifact{}, err
	}
	if s == nil || nilInterface(s.backend) || nilInterface(s.keys) {
		return Artifact{}, ErrInvalidRemoteStore
	}
	if s.admission != nil {
		return s.getAdmittedArtifact(ctx, scope, identity, at)
	}
	deleted, err := s.deletionExists(ctx, scope, identity)
	if err != nil {
		return Artifact{}, err
	}
	if deleted {
		return Artifact{}, ErrArtifactDeleted
	}
	value, found, err := s.readArtifact(ctx, scope, identity)
	if err != nil {
		return Artifact{}, err
	}
	if !found {
		return Artifact{}, ErrArtifactNotFound
	}
	if at.UnixMilli() >= value.expiresAtMillis {
		return Artifact{}, ErrArtifactExpired
	}
	return value, nil
}

func (s *EnvelopeStore) encryptArtifact(ctx context.Context, value Artifact, plaintext []byte) ([]byte, error) {
	dataKey, err := s.keys.GenerateDataKey(ctx, value.Scope().TenantID())
	defer dataKey.clear()
	if err != nil {
		if errors.Is(err, ErrInvalidEnvelopeKey) {
			return nil, ErrInvalidEnvelopeKey
		}
		return nil, ErrEnvelopeKeyUnavailable
	}
	if dataKey.validate() != nil {
		return nil, ErrInvalidEnvelopeKey
	}
	block, err := aes.NewCipher(dataKey.plaintext[:])
	if err != nil {
		return nil, ErrInvalidEnvelopeKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidEnvelopeKey
	}
	nonce := make([]byte, remoteEnvelopeNonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrEnvelopeKeyUnavailable
	}
	header := remoteEnvelopeHeader{
		Contract: "open-trestle/encrypted-artifact", SchemaVersion: 1,
		ScopeIdentity: value.Scope().Identity(), ArtifactIdentity: value.Identity(),
		KeyReference: dataKey.keyReference, WrappedDataKey: dataKey.wrapped, Nonce: nonce,
	}
	aad := remoteEnvelopeAAD(header)
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	defer clear(ciphertext)
	header.CiphertextDigest = hashBytes(ciphertext)
	header.CiphertextBytes = len(ciphertext)
	return encodeRemoteEnvelope(header, ciphertext)
}

func (s *EnvelopeStore) readArtifact(ctx context.Context, scope audit.ReviewScope, identity string) (Artifact, bool, error) {
	object, err := s.backend.Read(ctx, s.artifactObjectKey(scope, identity), maxRemoteArtifactBytes)
	if errors.Is(err, ErrRemoteObjectNotFound) {
		return Artifact{}, false, nil
	}
	if err != nil {
		return Artifact{}, false, mapRemoteReadError(err)
	}
	value, err := s.decryptRemoteObject(ctx, scope, identity, object)
	if err != nil {
		return Artifact{}, false, err
	}
	return value, true, nil
}

func (s *EnvelopeStore) decryptRemoteObject(ctx context.Context, scope audit.ReviewScope, identity string, object RemoteObject) (Artifact, error) {
	if object.validate(maxRemoteArtifactBytes) != nil {
		return Artifact{}, ErrCorruptArtifact
	}
	header, ciphertext, err := parseRemoteEnvelope(object.Content)
	if err != nil || header.ScopeIdentity != scope.Identity() || header.ArtifactIdentity != identity {
		return Artifact{}, ErrCorruptArtifact
	}
	wrapped := append([]byte(nil), header.WrappedDataKey...)
	defer clear(wrapped)
	plaintextKey, err := s.keys.UnwrapDataKey(ctx, scope.TenantID(), header.KeyReference, wrapped)
	defer clear(plaintextKey[:])
	if err != nil {
		if errors.Is(err, ErrInvalidEnvelopeKey) {
			return Artifact{}, ErrInvalidEnvelopeKey
		}
		return Artifact{}, ErrEnvelopeKeyUnavailable
	}
	keyMaterial := EnvelopeDataKey{plaintext: plaintextKey, keyReference: header.KeyReference, wrapped: header.WrappedDataKey}
	defer keyMaterial.clear()
	if keyMaterial.validate() != nil {
		return Artifact{}, ErrInvalidEnvelopeKey
	}
	block, err := aes.NewCipher(plaintextKey[:])
	if err != nil {
		return Artifact{}, ErrInvalidEnvelopeKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Artifact{}, ErrInvalidEnvelopeKey
	}
	plaintext, err := aead.Open(nil, header.Nonce, ciphertext, remoteEnvelopeAAD(header))
	if err != nil {
		return Artifact{}, ErrCorruptArtifact
	}
	defer clear(plaintext)
	value, err := Parse(plaintext)
	if err != nil || value.Scope().Identity() != scope.Identity() || value.Identity() != identity || value.Protection() != ProtectionEnvelopeEncrypted {
		return Artifact{}, ErrCorruptArtifact
	}
	return value, nil
}

func (s *EnvelopeStore) artifactObjectKey(scope audit.ReviewScope, identity string) string {
	return s.prefix + "/artifacts/" + scope.Identity() + "/" + identity
}
func (s *EnvelopeStore) deletionIntentObjectKey(scope audit.ReviewScope, identity string) string {
	return s.prefix + "/deletions/" + scope.Identity() + "/" + identity + ".intent"
}
func (s *EnvelopeStore) deletionReceiptObjectKey(scope audit.ReviewScope, identity string) string {
	return s.prefix + "/deletions/" + scope.Identity() + "/" + identity + ".receipt"
}

type remoteEnvelopeHeader struct {
	Contract         string `json:"contract"`
	SchemaVersion    int    `json:"schema_version"`
	ScopeIdentity    string `json:"scope_identity"`
	ArtifactIdentity string `json:"artifact_identity"`
	KeyReference     string `json:"key_reference"`
	WrappedDataKey   []byte `json:"wrapped_data_key"`
	Nonce            []byte `json:"nonce"`
	CiphertextDigest string `json:"ciphertext_digest"`
	CiphertextBytes  int    `json:"ciphertext_bytes"`
}

func remoteEnvelopeAAD(header remoteEnvelopeHeader) []byte {
	value := struct {
		Contract             string `json:"contract"`
		SchemaVersion        int    `json:"schema_version"`
		ScopeIdentity        string `json:"scope_identity"`
		ArtifactIdentity     string `json:"artifact_identity"`
		KeyReference         string `json:"key_reference"`
		WrappedDataKeyDigest string `json:"wrapped_data_key_digest"`
	}{
		header.Contract, header.SchemaVersion, header.ScopeIdentity, header.ArtifactIdentity,
		header.KeyReference, hashBytes(header.WrappedDataKey),
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func encodeRemoteEnvelope(header remoteEnvelopeHeader, ciphertext []byte) ([]byte, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil || len(headerBytes) == 0 || len(headerBytes) > maxRemoteEnvelopeHeaderBytes {
		return nil, ErrCorruptArtifact
	}
	result := make([]byte, len(remoteEnvelopeMagic)+4+len(headerBytes)+len(ciphertext))
	copy(result, remoteEnvelopeMagic)
	binary.BigEndian.PutUint32(result[len(remoteEnvelopeMagic):], uint32(len(headerBytes)))
	copy(result[len(remoteEnvelopeMagic)+4:], headerBytes)
	copy(result[len(remoteEnvelopeMagic)+4+len(headerBytes):], ciphertext)
	if len(result) > maxRemoteArtifactBytes {
		clear(result)
		return nil, ErrRemoteObjectTooLarge
	}
	return result, nil
}

func parseRemoteEnvelope(encoded []byte) (remoteEnvelopeHeader, []byte, error) {
	minimum := len(remoteEnvelopeMagic) + 4 + remoteEnvelopeNonceBytes + 16
	if len(encoded) < minimum || len(encoded) > maxRemoteArtifactBytes || string(encoded[:len(remoteEnvelopeMagic)]) != remoteEnvelopeMagic {
		return remoteEnvelopeHeader{}, nil, ErrCorruptArtifact
	}
	headerLength := int(binary.BigEndian.Uint32(encoded[len(remoteEnvelopeMagic):]))
	headerStart := len(remoteEnvelopeMagic) + 4
	if headerLength <= 0 || headerLength > maxRemoteEnvelopeHeaderBytes || headerStart+headerLength >= len(encoded) {
		return remoteEnvelopeHeader{}, nil, ErrCorruptArtifact
	}
	headerBytes := encoded[headerStart : headerStart+headerLength]
	decoder := json.NewDecoder(bytes.NewReader(headerBytes))
	decoder.DisallowUnknownFields()
	var header remoteEnvelopeHeader
	if err := decoder.Decode(&header); err != nil {
		return remoteEnvelopeHeader{}, nil, ErrCorruptArtifact
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return remoteEnvelopeHeader{}, nil, ErrCorruptArtifact
	}
	canonical, _ := json.Marshal(header)
	ciphertext := encoded[headerStart+headerLength:]
	validHeader := bytes.Equal(canonical, headerBytes) && header.Contract == "open-trestle/encrypted-artifact" && header.SchemaVersion == 1
	validBindings := validDigest(header.ScopeIdentity) && validDigest(header.ArtifactIdentity) && validRemoteValue(header.KeyReference, maxKeyReferenceBytes)
	validKey := len(header.WrappedDataKey) > 0 && len(header.WrappedDataKey) <= maxWrappedDataKeyBytes
	validNonce := len(header.Nonce) == remoteEnvelopeNonceBytes
	validCiphertext := header.CiphertextBytes == len(ciphertext) && validDigest(header.CiphertextDigest) && hashBytes(ciphertext) == header.CiphertextDigest
	validPayload := validKey && validNonce && validCiphertext
	if !validHeader || !validBindings || !validPayload {
		return remoteEnvelopeHeader{}, nil, ErrCorruptArtifact
	}
	return header, ciphertext, nil
}

func validRemoteValue(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate == 0x7f {
			return false
		}
	}
	return true
}

func validObjectPrefix(value string) bool {
	validLength := len(value) > 0 && len(value) <= maxObjectPrefixBytes && utf8.ValidString(value)
	validShape := !strings.HasPrefix(value, "/") && !strings.HasSuffix(value, "/") && !strings.Contains(value, "//")
	if !validLength || !validShape {
		return false
	}
	for _, candidate := range value {
		alphaNumeric := candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9'
		if !alphaNumeric && candidate != '-' && candidate != '_' && candidate != '/' {
			return false
		}
	}
	return true
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}

func mapRemoteReadError(err error) error {
	if errors.Is(err, ErrRemoteObjectConflict) {
		return ErrRemoteStoreConflict
	}
	if errors.Is(err, ErrRemoteObjectTooLarge) || errors.Is(err, ErrRemoteObjectIntegrity) {
		return ErrCorruptArtifact
	}
	return ErrRemoteStorePersistence
}
func mapRemoteMutationError(err error) error {
	if errors.Is(err, ErrRemoteObjectConflict) {
		return ErrRemoteStoreConflict
	}
	return ErrRemoteStorePersistence
}
