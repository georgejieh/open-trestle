package artifact

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// ErrEnvelopeStorageConformance identifies invalid conformance authority, scope, time, or terminal proof.
var ErrEnvelopeStorageConformance = errors.New("envelope storage conformance failed")

const envelopeStorageConformancePayload = `{"contract":"open-trestle/envelope-storage-conformance","schema_version":1}`

// EnvelopeStorageConformanceReceipt binds one verified create, encrypted read, exact delete, and absence result.
type EnvelopeStorageConformanceReceipt struct{ authorityIdentity, artifactIdentity, objectDigest, versionIdentity, identity string }

func (r EnvelopeStorageConformanceReceipt) Identity() string { return r.identity }
func (r EnvelopeStorageConformanceReceipt) Validate() error {
	if !validDigest(r.authorityIdentity) || !validDigest(r.artifactIdentity) || !validDigest(r.objectDigest) || !validDigest(r.versionIdentity) || r.identity != deriveEnvelopeStorageConformanceIdentity(r) {
		return ErrEnvelopeStorageConformance
	}
	return nil
}
func (r EnvelopeStorageConformanceReceipt) String() string {
	return "envelope storage conformance receipt"
}
func (r EnvelopeStorageConformanceReceipt) GoString() string {
	return "artifact.EnvelopeStorageConformanceReceipt{<redacted>}"
}
func (r EnvelopeStorageConformanceReceipt) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, r.String(), r.GoString())
}

// EnvelopeStorageAuthorityIdentity binds one tenant to exact object, key, and prefix authorities.
func EnvelopeStorageAuthorityIdentity(tenantID, objectBackendIdentity, keyProviderIdentity, prefix string) (string, error) {
	if _, err := audit.NewReviewScope(tenantID, "envelope-storage-authority", "configuration"); err != nil || !validDigest(objectBackendIdentity) || !validDigest(keyProviderIdentity) || !validObjectPrefix(prefix) {
		return "", ErrInvalidRemoteStore
	}
	wire := struct {
		Contract              string `json:"contract"`
		SchemaVersion         int    `json:"schema_version"`
		TenantID              string `json:"tenant_id"`
		ObjectBackendIdentity string `json:"object_backend_identity"`
		KeyProviderIdentity   string `json:"key_provider_identity"`
		Prefix                string `json:"prefix"`
	}{"open-trestle/envelope-storage-authority", 1, tenantID, objectBackendIdentity, keyProviderIdentity, prefix}
	encoded, _ := json.Marshal(wire)
	sum := hashBytes(encoded)
	return sum, nil
}

// VerifyEnvelopeStorageConformance runs one fixed public artifact through encryption, storage, retrieval, exact deletion, and absence verification.
func VerifyEnvelopeStorageConformance(ctx context.Context, store *EnvelopeStore, scope audit.ReviewScope, authorityIdentity string, createdAt time.Time) (EnvelopeStorageConformanceReceipt, error) {
	if ctx == nil || ctx.Err() != nil || store == nil || nilInterface(store.backend) || nilInterface(store.keys) || scope.Validate() != nil || !validDigest(authorityIdentity) || !validConformanceTime(createdAt) {
		return EnvelopeStorageConformanceReceipt{}, ErrEnvelopeStorageConformance
	}
	createdAt = time.UnixMilli(createdAt.UnixMilli()).UTC()
	payload := []byte(envelopeStorageConformancePayload)
	value, err := New(scope, KindTaskInput, "application/json", ClassificationPublic, OriginHost, ProtectionEnvelopeEncrypted, []string{authorityIdentity}, payload, createdAt, createdAt.Add(30*24*time.Hour))
	if err != nil {
		return EnvelopeStorageConformanceReceipt{}, ErrEnvelopeStorageConformance
	}
	if _, err = store.Put(ctx, value, createdAt.Add(time.Millisecond)); err != nil {
		return EnvelopeStorageConformanceReceipt{}, err
	}
	key := store.artifactObjectKey(scope, value.Identity())
	object, err := store.backend.Read(ctx, key, maxRemoteArtifactBytes)
	if err != nil {
		return EnvelopeStorageConformanceReceipt{}, mapRemoteReadError(err)
	}
	defer clear(object.Content)
	cleanup := func() { _, _ = store.backend.Delete(ctx, key, object.Version) }
	encodedPayload := []byte(base64.StdEncoding.EncodeToString(payload))
	if object.validate(maxRemoteArtifactBytes) != nil || bytes.Contains(object.Content, payload) || bytes.Contains(object.Content, encodedPayload) {
		cleanup()
		return EnvelopeStorageConformanceReceipt{}, ErrCorruptArtifact
	}
	retrieved, err := store.decryptRemoteObject(ctx, scope, value.Identity(), object)
	if err != nil {
		cleanup()
		return EnvelopeStorageConformanceReceipt{}, err
	}
	retrievedPayload := retrieved.Payload()
	defer clear(retrievedPayload)
	if retrieved.Identity() != value.Identity() || retrieved.PayloadDigest() != value.PayloadDigest() || subtle.ConstantTimeCompare(retrievedPayload, payload) != 1 {
		cleanup()
		return EnvelopeStorageConformanceReceipt{}, ErrCorruptArtifact
	}
	deleted, err := store.backend.Delete(ctx, key, object.Version)
	if err != nil {
		return EnvelopeStorageConformanceReceipt{}, mapRemoteMutationError(err)
	}
	if !deleted {
		return EnvelopeStorageConformanceReceipt{}, ErrRemoteStoreConflict
	}
	remaining, readErr := store.backend.Read(ctx, key, maxRemoteArtifactBytes)
	clear(remaining.Content)
	if readErr == nil {
		return EnvelopeStorageConformanceReceipt{}, ErrRemoteStoreConflict
	}
	if !errors.Is(readErr, ErrRemoteObjectNotFound) {
		return EnvelopeStorageConformanceReceipt{}, mapRemoteReadError(readErr)
	}
	receipt := EnvelopeStorageConformanceReceipt{authorityIdentity: authorityIdentity, artifactIdentity: value.Identity(), objectDigest: object.Digest, versionIdentity: hashBytes([]byte(object.Version))}
	receipt.identity = deriveEnvelopeStorageConformanceIdentity(receipt)
	if receipt.Validate() != nil {
		return EnvelopeStorageConformanceReceipt{}, ErrEnvelopeStorageConformance
	}
	return receipt, nil
}
func validConformanceTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(time.UnixMilli(value.UnixMilli()).UTC()) && value.Year() >= 1970 && value.Year() <= 9998
}
func deriveEnvelopeStorageConformanceIdentity(receipt EnvelopeStorageConformanceReceipt) string {
	wire := struct {
		Contract          string `json:"contract"`
		SchemaVersion     int    `json:"schema_version"`
		AuthorityIdentity string `json:"authority_identity"`
		ArtifactIdentity  string `json:"artifact_identity"`
		ObjectDigest      string `json:"object_digest"`
		VersionIdentity   string `json:"version_identity"`
		Deleted           bool   `json:"deleted"`
	}{"open-trestle/envelope-storage-conformance-receipt", 1, receipt.authorityIdentity, receipt.artifactIdentity, receipt.objectDigest, receipt.versionIdentity, true}
	encoded, _ := json.Marshal(wire)
	return hashBytes(encoded)
}
