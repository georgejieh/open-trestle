package artifact

import (
	"bytes"
	"encoding/json"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	storageNamespaceContract         = "open-trestle/artifact-storage-namespace"
	artifactAdmissionContract        = "open-trestle/artifact-admission"
	maxEncodedStorageNamespaceBytes  = 4096
	maxEncodedArtifactAdmissionBytes = 16384
)

// Identity is omitted only when deriving the unsigned preimage. Public codecs
// require a nonempty valid identity before accepting or encoding a record.
type storageNamespaceRecord struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	Identity                     string `json:"identity,omitempty"`
	BackendConfigurationIdentity string `json:"backend_configuration_identity"`
	Prefix                       string `json:"prefix"`
	NamespaceEpochIdentity       string `json:"namespace_epoch_identity"`
}

type artifactAdmissionRecord struct {
	Contract               string   `json:"contract"`
	SchemaVersion          int      `json:"schema_version"`
	Identity               string   `json:"identity,omitempty"`
	NamespaceIdentity      string   `json:"namespace_identity"`
	ScopeIdentity          string   `json:"scope_identity"`
	TenantID               string   `json:"tenant_id"`
	RepositoryID           string   `json:"repository_id"`
	ReviewRunID            string   `json:"review_run_id"`
	ArtifactIdentity       string   `json:"artifact_identity"`
	Kind                   string   `json:"kind"`
	MediaType              string   `json:"media_type"`
	Classification         string   `json:"classification"`
	Origin                 string   `json:"origin"`
	Protection             string   `json:"protection"`
	Provenance             []string `json:"provenance"`
	PayloadDigest          string   `json:"payload_digest"`
	CreatedAtMilliseconds  int64    `json:"created_at_milliseconds"`
	ExpiresAtMilliseconds  int64    `json:"expires_at_milliseconds"`
	AdmittedAtMilliseconds int64    `json:"admitted_at_milliseconds"`
}

// EncodeStorageNamespace returns an independent canonical JSON record.
func EncodeStorageNamespace(value StorageNamespace) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(storageNamespaceRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedStorageNamespaceBytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseStorageNamespace accepts only bounded, exact canonical metadata shape.
func ParseStorageNamespace(encoded []byte) (StorageNamespace, error) {
	var record storageNamespaceRecord
	if !canonicalErasureRecord(encoded, maxEncodedStorageNamespaceBytes, &record) || record.Contract != storageNamespaceContract || record.SchemaVersion != 1 {
		return StorageNamespace{}, ErrInvalidErasureContract
	}
	value := StorageNamespace{
		identity: record.Identity, backendConfigurationIdentity: record.BackendConfigurationIdentity,
		prefix: record.Prefix, namespaceEpochIdentity: record.NamespaceEpochIdentity,
	}
	if err := value.Validate(); err != nil {
		return StorageNamespace{}, err
	}
	return value, nil
}

// EncodeArtifactAdmission returns independent canonical metadata bytes, never payload.
func EncodeArtifactAdmission(value ArtifactAdmission) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(artifactAdmissionRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedArtifactAdmissionBytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseArtifactAdmission verifies historical metadata identities without creating
// an Artifact, accessing payload, or granting any authority.
func ParseArtifactAdmission(encoded []byte) (ArtifactAdmission, error) {
	var record artifactAdmissionRecord
	if !canonicalErasureRecord(encoded, maxEncodedArtifactAdmissionBytes, &record) || record.Contract != artifactAdmissionContract || record.SchemaVersion != 1 ||
		!validDigest(record.Identity) || !validDigest(record.ScopeIdentity) {
		return ArtifactAdmission{}, ErrInvalidErasureContract
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return ArtifactAdmission{}, ErrInvalidErasureContract
	}
	kind, classification, origin, protection, err := parseEnums(record.Kind, record.Classification, record.Origin, record.Protection)
	if err != nil {
		return ArtifactAdmission{}, ErrInvalidErasureContract
	}
	value := ArtifactAdmission{
		identity: record.Identity, namespaceIdentity: record.NamespaceIdentity, artifactIdentity: record.ArtifactIdentity,
		scope: scope, kind: kind, mediaType: record.MediaType, classification: classification, origin: origin, protection: protection,
		provenance: append([]string(nil), record.Provenance...), payloadDigest: record.PayloadDigest,
		createdAtMillis: record.CreatedAtMilliseconds, expiresAtMillis: record.ExpiresAtMilliseconds, admittedAtMillis: record.AdmittedAtMilliseconds,
	}
	// Malformed fields take priority over otherwise well-shaped identity errors.
	if err := value.validateFields(); err != nil {
		return ArtifactAdmission{}, err
	}
	if scope.Identity() != record.ScopeIdentity {
		return ArtifactAdmission{}, ErrErasureIdentityMismatch
	}
	if err := value.Validate(); err != nil {
		return ArtifactAdmission{}, err
	}
	return value, nil
}

func canonicalErasureRecord(encoded []byte, limit int, record any) bool {
	if len(encoded) == 0 || len(encoded) > limit {
		return false
	}
	if err := json.Unmarshal(encoded, record); err != nil {
		return false
	}
	// Fixed Go JSON re-encoding rejects aliases, duplicates, unknown fields,
	// alternate escaping, ordering and spacing. Field validation also rejects
	// a missing identity or null provenance, which can survive re-encoding.
	canonical, err := json.Marshal(record)
	return err == nil && bytes.Equal(canonical, encoded)
}

func storageNamespaceRecordFromValue(value StorageNamespace) storageNamespaceRecord {
	return storageNamespaceRecord{
		Contract: storageNamespaceContract, SchemaVersion: 1, Identity: value.identity,
		BackendConfigurationIdentity: value.backendConfigurationIdentity, Prefix: value.prefix,
		NamespaceEpochIdentity: value.namespaceEpochIdentity,
	}
}

func artifactAdmissionRecordFromValue(value ArtifactAdmission) artifactAdmissionRecord {
	return artifactAdmissionRecord{
		Contract: artifactAdmissionContract, SchemaVersion: 1, Identity: value.identity,
		NamespaceIdentity: value.namespaceIdentity, ScopeIdentity: value.scope.Identity(),
		TenantID: value.scope.TenantID(), RepositoryID: value.scope.RepositoryID(), ReviewRunID: value.scope.ReviewRunID(),
		ArtifactIdentity: value.artifactIdentity, Kind: value.kind.String(), MediaType: value.mediaType,
		Classification: value.classification.String(), Origin: value.origin.String(), Protection: value.protection.String(),
		Provenance: value.Provenance(), PayloadDigest: value.payloadDigest,
		CreatedAtMilliseconds: value.createdAtMillis, ExpiresAtMilliseconds: value.expiresAtMillis, AdmittedAtMilliseconds: value.admittedAtMillis,
	}
}

func deriveStorageNamespaceIdentity(value StorageNamespace) string {
	record := storageNamespaceRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return erasureRecordIdentity(storageNamespaceContract, encoded)
}

func deriveArtifactAdmissionIdentity(value ArtifactAdmission) string {
	record := artifactAdmissionRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return erasureRecordIdentity(artifactAdmissionContract, encoded)
}

func erasureRecordIdentity(contract string, unsigned []byte) string {
	return hashBytes(append([]byte(contract+"/v1\x00"), unsigned...))
}

// This is the exact original undomained v1 metadata preimage in deriveIdentity.
// It intentionally neither constructs an Artifact nor includes admission fields.
func deriveAdmissionOriginalIdentity(value ArtifactAdmission) string {
	return hashValue(struct {
		ScopeIdentity         string   `json:"scope_identity"`
		Kind                  string   `json:"kind"`
		MediaType             string   `json:"media_type"`
		Classification        string   `json:"classification"`
		Origin                string   `json:"origin"`
		Protection            string   `json:"protection"`
		Provenance            []string `json:"provenance"`
		PayloadDigest         string   `json:"payload_digest"`
		CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
		ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
	}{
		ScopeIdentity: value.scope.Identity(), Kind: value.kind.String(), MediaType: value.mediaType,
		Classification: value.classification.String(), Origin: value.origin.String(), Protection: value.protection.String(),
		Provenance: value.provenance, PayloadDigest: value.payloadDigest,
		CreatedAtMilliseconds: value.createdAtMillis, ExpiresAtMilliseconds: value.expiresAtMillis,
	})
}
