package artifact

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	attemptRequestContract        = "open-trestle/artifact-erasure-attempt-request"
	erasureAttemptContract        = "open-trestle/artifact-erasure-attempt"
	maxEncodedAttemptRequestBytes = 8192
	maxEncodedErasureAttemptBytes = 1024
)

// Only identity is omitted from the hash preimage; empty options stay present.
type attemptRequestRecord struct {
	Contract                      string `json:"contract"`
	SchemaVersion                 int    `json:"schema_version"`
	Identity                      string `json:"identity,omitempty"`
	ReservationIdentity           string `json:"reservation_identity"`
	NamespaceIdentity             string `json:"namespace_identity"`
	ScopeIdentity                 string `json:"scope_identity"`
	ArtifactIdentity              string `json:"artifact_identity"`
	AdmissionIdentity             string `json:"admission_identity"`
	OperationIdentity             string `json:"operation_identity"`
	OriginalAuthorizationIdentity string `json:"original_authorization_identity"`
	AuthorizationDocumentDigest   string `json:"authorization_document_digest"`
	AllowanceIdentity             string `json:"allowance_identity"`
	AllowanceDocumentDigest       string `json:"allowance_document_digest"`
	ProtectedPolicyIdentity       string `json:"protected_policy_identity"`
	ExpectedBucketOwner           string `json:"expected_bucket_owner"`
	Kind                          string `json:"kind"`
	Key                           string `json:"key"`
	VersionKind                   string `json:"version_kind"`
	VersionID                     string `json:"version_id"`
	KeyMarker                     string `json:"key_marker"`
	VersionIDMarker               string `json:"version_id_marker"`
	PageLimit                     uint16 `json:"page_limit"`
	MaximumResponseBytes          uint32 `json:"maximum_response_bytes"`
	BodyDigest                    string `json:"body_digest"`
	BodyBytes                     uint32 `json:"body_bytes"`
	Condition                     string `json:"condition"`
	ObservationIdentity           string `json:"observation_identity"`
}

type erasureAttemptRecord struct {
	Contract               string `json:"contract"`
	SchemaVersion          int    `json:"schema_version"`
	Identity               string `json:"identity,omitempty"`
	RequestIdentity        string `json:"request_identity"`
	Sequence               uint64 `json:"sequence"`
	ReservedAtMilliseconds int64  `json:"reserved_at_milliseconds"`
}

// EncodeAttemptRequest returns independent canonical metadata bytes.
func EncodeAttemptRequest(value AttemptRequest) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(attemptRequestRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedAttemptRequestBytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseAttemptRequest binds explicit scope, not omitted operation or allowance authority.
func ParseAttemptRequest(encoded []byte, scope audit.ReviewScope) (AttemptRequest, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedAttemptRequestBytes {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	if !utf8.Valid(encoded) {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	var record attemptRequestRecord
	if !canonicalErasureRecord(encoded, maxEncodedAttemptRequestBytes, &record) ||
		record.Contract != attemptRequestContract || record.SchemaVersion != 1 ||
		!validDigest(record.Identity) || !validDigest(record.ScopeIdentity) {
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	var kind AttemptKind
	switch record.Kind {
	case "current_read":
		kind = AttemptCurrentRead
	case "intent_read":
		kind = AttemptIntentRead
	case "attestation_read":
		kind = AttemptAttestationRead
	case "version_list":
		kind = AttemptVersionList
	case "intent_create":
		kind = AttemptIntentCreate
	case "fence_create":
		kind = AttemptFenceCreate
	case "version_delete":
		kind = AttemptVersionDelete
	case "attestation_create":
		kind = AttemptAttestationCreate
	default:
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	var versionKind ObjectVersionKind
	switch record.VersionKind {
	case "":
	case "data":
		versionKind = ObjectVersionData
	case "delete_marker":
		versionKind = ObjectVersionDeleteMarker
	default:
		return AttemptRequest{}, ErrInvalidErasureContract
	}
	value := AttemptRequest{
		identity: record.Identity, scope: scope, kind: kind, versionKind: versionKind,
		reservationIdentity:           record.ReservationIdentity,
		namespaceIdentity:             record.NamespaceIdentity,
		artifactIdentity:              record.ArtifactIdentity,
		admissionIdentity:             record.AdmissionIdentity,
		operationIdentity:             record.OperationIdentity,
		originalAuthorizationIdentity: record.OriginalAuthorizationIdentity,
		authorizationDocumentDigest:   record.AuthorizationDocumentDigest,
		allowanceIdentity:             record.AllowanceIdentity,
		allowanceDocumentDigest:       record.AllowanceDocumentDigest,
		protectedPolicyIdentity:       record.ProtectedPolicyIdentity,
		expectedBucketOwner:           record.ExpectedBucketOwner,
		key:                           record.Key,
		versionID:                     record.VersionID,
		keyMarker:                     record.KeyMarker,
		versionIDMarker:               record.VersionIDMarker,
		pageLimit:                     record.PageLimit,
		maximumResponseBytes:          record.MaximumResponseBytes,
		bodyDigest:                    record.BodyDigest,
		bodyBytes:                     record.BodyBytes,
		condition:                     record.Condition,
		observationIdentity:           record.ObservationIdentity,
	}
	if err := value.validateFields(); err != nil {
		return AttemptRequest{}, err
	}
	if scope.Identity() != record.ScopeIdentity {
		return AttemptRequest{}, ErrErasureIdentityMismatch
	}
	if err := value.Validate(); err != nil {
		return AttemptRequest{}, err
	}
	return value.clone()
}

// EncodeErasureAttempt returns independent canonical metadata bytes.
func EncodeErasureAttempt(value ErasureAttempt) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(erasureAttemptRecordFromValue(value))
	if err != nil || len(encoded) > maxEncodedErasureAttemptBytes {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

// ParseErasureAttempt binds the complete supplied request metadata.
func ParseErasureAttempt(encoded []byte, request AttemptRequest) (ErasureAttempt, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedErasureAttemptBytes {
		return ErasureAttempt{}, ErrInvalidErasureContract
	}
	if !utf8.Valid(encoded) {
		return ErasureAttempt{}, ErrInvalidErasureContract
	}
	var record erasureAttemptRecord
	if !canonicalErasureRecord(encoded, maxEncodedErasureAttemptBytes, &record) ||
		record.Contract != erasureAttemptContract || record.SchemaVersion != 1 ||
		!validDigest(record.Identity) || !validDigest(record.RequestIdentity) ||
		record.Sequence < 1 || record.Sequence > 4096 || record.ReservedAtMilliseconds <= 0 ||
		record.ReservedAtMilliseconds > maxArtifactUnixMilliseconds {
		return ErasureAttempt{}, ErrInvalidErasureContract
	}
	if err := request.Validate(); err != nil {
		return ErasureAttempt{}, err
	}
	if request.Identity() != record.RequestIdentity {
		return ErasureAttempt{}, ErrErasureIdentityMismatch
	}
	value := ErasureAttempt{
		identity: record.Identity, request: request,
		sequence: record.Sequence, reservedAtMillis: record.ReservedAtMilliseconds,
	}
	if err := value.Validate(); err != nil {
		return ErasureAttempt{}, err
	}
	value.identity = strings.Clone(value.identity)
	return value, nil
}

func attemptRequestRecordFromValue(value AttemptRequest) attemptRequestRecord {
	versionKind := ""
	switch value.versionKind {
	case ObjectVersionData:
		versionKind = "data"
	case ObjectVersionDeleteMarker:
		versionKind = "delete_marker"
	}
	return attemptRequestRecord{
		Contract: attemptRequestContract, SchemaVersion: 1, Identity: value.identity,
		ReservationIdentity:           value.reservationIdentity,
		NamespaceIdentity:             value.namespaceIdentity,
		ScopeIdentity:                 value.scope.Identity(),
		ArtifactIdentity:              value.artifactIdentity,
		AdmissionIdentity:             value.admissionIdentity,
		OperationIdentity:             value.operationIdentity,
		OriginalAuthorizationIdentity: value.originalAuthorizationIdentity,
		AuthorizationDocumentDigest:   value.authorizationDocumentDigest,
		AllowanceIdentity:             value.allowanceIdentity,
		AllowanceDocumentDigest:       value.allowanceDocumentDigest,
		ProtectedPolicyIdentity:       value.protectedPolicyIdentity,
		ExpectedBucketOwner:           value.expectedBucketOwner,
		Kind:                          value.kind.String(),
		Key:                           value.key,
		VersionKind:                   versionKind,
		VersionID:                     value.versionID,
		KeyMarker:                     value.keyMarker,
		VersionIDMarker:               value.versionIDMarker,
		PageLimit:                     value.pageLimit,
		MaximumResponseBytes:          value.maximumResponseBytes,
		BodyDigest:                    value.bodyDigest,
		BodyBytes:                     value.bodyBytes,
		Condition:                     value.condition,
		ObservationIdentity:           value.observationIdentity,
	}
}

func erasureAttemptRecordFromValue(value ErasureAttempt) erasureAttemptRecord {
	return erasureAttemptRecord{
		Contract: erasureAttemptContract, SchemaVersion: 1, Identity: value.identity,
		RequestIdentity: value.request.Identity(), Sequence: value.sequence,
		ReservedAtMilliseconds: value.reservedAtMillis,
	}
}

func deriveAttemptRequestIdentity(value AttemptRequest) string {
	record := attemptRequestRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return erasureRecordIdentity(attemptRequestContract, encoded)
}

func deriveErasureAttemptIdentity(value ErasureAttempt) string {
	record := erasureAttemptRecordFromValue(value)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	return erasureRecordIdentity(erasureAttemptContract, encoded)
}
