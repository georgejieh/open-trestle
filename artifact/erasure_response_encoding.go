package artifact

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	attemptResponseContract        = "open-trestle/artifact-erasure-response"
	maxEncodedAttemptResponseBytes = 262144
)

type attemptResponseRecord struct {
	Contract               string                 `json:"contract"`
	SchemaVersion          int                    `json:"schema_version"`
	Identity               string                 `json:"identity,omitempty"`
	OperationIdentity      string                 `json:"operation_identity"`
	AttemptIdentity        string                 `json:"attempt_identity"`
	ObservedAtMilliseconds int64                  `json:"observed_at_milliseconds"`
	Code                   string                 `json:"code"`
	ContentKind            string                 `json:"content_kind"`
	VersionKind            string                 `json:"version_kind"`
	VersionID              string                 `json:"version_id"`
	ContentDigest          string                 `json:"content_digest"`
	RecordHex              string                 `json:"record_hex"`
	ResponseBytes          uint32                 `json:"response_bytes"`
	Entries                []attemptResponseEntry `json:"entries"`
	KeyMarker              string                 `json:"key_marker"`
	VersionIDMarker        string                 `json:"version_id_marker"`
	Truncated              bool                   `json:"truncated"`
}
type attemptResponseEntry struct {
	VersionIdentity string `json:"version_identity"`
	Kind            string `json:"kind"`
	VersionID       string `json:"version_id"`
	IsLatest        bool   `json:"is_latest"`
}

// Each nested type has its own cap, independent of its envelope's cap.
func erasureMetadataHex(value string, limit int) bool {
	if len(value) > 2*limit || len(value)%2 != 0 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func erasureMetadataDecode(encoded []byte, limit int, record any) bool {
	return len(encoded) > 0 && len(encoded) <= limit && utf8.Valid(encoded) && canonicalErasureRecord(encoded, limit, record)
}

func erasureMetadataMillis(ms int64) bool {
	return ms > 0 && ms <= maxArtifactUnixMilliseconds
}

func erasureMetadataEncode(record any, limit int) ([]byte, error) {
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > limit {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}

func responseBodyLimit(kind string) int {
	switch kind {
	case "fence":
		return 4096
	case "operation":
		return 16384
	case "attestation":
		return 8192
	default:
		return 0
	}
}

func (r attemptResponseRecord) shape() error {
	if r.Contract != attemptResponseContract || r.SchemaVersion != 1 ||
		!validDigest(r.Identity) || !validDigest(r.OperationIdentity) || !validDigest(r.AttemptIdentity) ||
		!erasureMetadataMillis(r.ObservedAtMilliseconds) || r.Entries == nil || len(r.Entries) > 256 ||
		!erasureMetadataHex(r.RecordHex, responseBodyLimit(r.ContentKind)) {
		return ErrInvalidErasureContract
	}
	noVersion := r.VersionKind == "" && r.VersionID == ""
	noPage := len(r.Entries) == 0 && r.KeyMarker == "" && r.VersionIDMarker == "" && !r.Truncated
	noContent := r.ContentKind == "" && r.ContentDigest == "" && r.RecordHex == ""
	switch r.Code {
	case "present":
		if r.ContentKind == "" {
			if !noContent || !noVersion || r.ResponseBytes < 1 || r.ResponseBytes > 1048576 {
				return ErrInvalidErasureContract
			}
			if r.Truncated {
				if len(r.Entries) == 0 || !validExactObjectKey(r.KeyMarker) || !validObjectVersionID(r.VersionIDMarker) {
					return ErrInvalidErasureContract
				}
			} else if r.KeyMarker != "" || r.VersionIDMarker != "" {
				return ErrInvalidErasureContract
			}
			seen := make(map[string]bool, len(r.Entries))
			latest := 0
			for _, entry := range r.Entries {
				if !validDigest(entry.VersionIdentity) || (entry.Kind != "data" && entry.Kind != "delete_marker") ||
					!validObjectVersionID(entry.VersionID) || seen[entry.VersionID] {
					return ErrInvalidErasureContract
				}
				seen[entry.VersionID] = true
				if entry.IsLatest {
					latest++
				}
			}
			if latest > 1 {
				return ErrInvalidErasureContract
			}
		} else {
			if !noPage || r.VersionKind != "data" || !validObjectVersionID(r.VersionID) || !validDigest(r.ContentDigest) || r.ResponseBytes < 1 {
				return ErrInvalidErasureContract
			}
			switch r.ContentKind {
			case "ciphertext":
				if r.RecordHex != "" || r.ResponseBytes > 33554432 {
					return ErrInvalidErasureContract
				}
			case "fence", "operation", "attestation":
				if r.RecordHex == "" || r.ResponseBytes > 33554432 {
					return ErrInvalidErasureContract
				}
			default:
				return ErrInvalidErasureContract
			}
		}
	case "absent":
		if !noPage || r.ContentDigest != "" || r.RecordHex != "" || r.ResponseBytes != 0 {
			return ErrInvalidErasureContract
		}
		if r.ContentKind == "delete_marker" {
			if r.VersionKind != "delete_marker" || !validObjectVersionID(r.VersionID) {
				return ErrInvalidErasureContract
			}
		} else if !noContent || !noVersion {
			return ErrInvalidErasureContract
		}
	case "created", "condition_lost", "deleted", "not_found", "conflict", "denied", "malformed", "unavailable", "abandoned":
		if !noVersion || !noPage || !noContent || r.ResponseBytes != 0 {
			return ErrInvalidErasureContract
		}
	default:
		return ErrInvalidErasureContract
	}
	return nil
}

func responseRecordIdentity(r attemptResponseRecord) string {
	r.Identity = ""
	encoded, _ := json.Marshal(r)
	return erasureRecordIdentity(attemptResponseContract, encoded)
}

// responseBody contains only labels available in canonical content.
type responseBody struct {
	namespace, scope, operation, artifact, admission, authorization, document string
}

func inspectResponseBody(r attemptResponseRecord, scope audit.ReviewScope) (responseBody, error) {
	if r.RecordHex == "" {
		return responseBody{}, nil
	}
	if !erasureMetadataHex(r.RecordHex, responseBodyLimit(r.ContentKind)) {
		return responseBody{}, ErrInvalidErasureContract
	}
	body, _ := hex.DecodeString(r.RecordHex)
	var labels responseBody
	switch r.ContentKind {
	case "fence":
		value, err := ParseErasureFence(body)
		if err != nil {
			return responseBody{}, err
		}
		labels = responseBody{namespace: value.NamespaceIdentity(), scope: value.ScopeIdentity(), operation: value.OperationIdentity(), artifact: value.ArtifactIdentity()}
	case "operation":
		var record erasureOperationRecord
		if !erasureMetadataDecode(body, 16384, &record) || record.Contract != erasureOperationContract || record.SchemaVersion != 2 ||
			!validDigest(record.Identity) || !validDigest(record.ScopeIdentity) {
			return responseBody{}, ErrInvalidErasureContract
		}
		value := ErasureOperation{scope: scope, namespaceIdentity: record.NamespaceIdentity, artifactIdentity: record.ArtifactIdentity,
			admissionIdentity: record.AdmissionIdentity, originalAuthorizationIdentity: record.OriginalAuthorizationIdentity,
			authorizationDocumentDigest: record.AuthorizationDocumentDigest, policyIdentity: record.PolicyIdentity,
			protectedPolicyIdentity: record.ProtectedPolicyIdentity, ownership: record.Ownership, preparedAtMillis: record.PreparedAtMilliseconds,
			erasureProtocol: record.ErasureProtocol, legacyReceiptIdentity: record.LegacyReceiptIdentity}
		if err := value.validateFields(); err != nil {
			return responseBody{}, err
		}
		identity := record.Identity
		record.Identity = ""
		unsigned, _ := json.Marshal(record)
		if identity != hashBytes(append([]byte(erasureOperationContract+"/v2\x00"), unsigned...)) {
			return responseBody{}, ErrErasureIdentityMismatch
		}
		labels = responseBody{record.NamespaceIdentity, record.ScopeIdentity, identity, record.ArtifactIdentity, record.AdmissionIdentity, record.OriginalAuthorizationIdentity, record.AuthorizationDocumentDigest}
	case "attestation":
		var record erasureAttestationV2Record
		if !erasureMetadataDecode(body, 8192, &record) {
			return responseBody{}, ErrInvalidErasureContract
		}
		if err := record.shape(); err != nil {
			return responseBody{}, err
		}
		if err := record.relations(); err != nil {
			return responseBody{}, err
		}
		if record.Identity != attestationV2RecordIdentity(record) {
			return responseBody{}, ErrErasureIdentityMismatch
		}
		labels = responseBody{record.NamespaceIdentity, record.ScopeIdentity, record.OperationIdentity, record.ArtifactIdentity, record.AdmissionIdentity, record.OriginalAuthorizationIdentity, record.AuthorizationDocumentDigest}
	default:
		return responseBody{}, ErrInvalidErasureContract
	}
	return labels, nil
}

func parseAttemptResponse(encoded []byte, ref ErasureOperationRef) (attemptResponseRecord, error) {
	var r attemptResponseRecord
	if !erasureMetadataDecode(encoded, maxEncodedAttemptResponseBytes, &r) {
		return attemptResponseRecord{}, ErrInvalidErasureContract
	}
	if err := r.shape(); err != nil {
		return attemptResponseRecord{}, err
	}
	if err := responseBodyShape(r); err != nil {
		return attemptResponseRecord{}, err
	}
	labels, err := inspectResponseBody(r, ref.Scope())
	if err != nil {
		return attemptResponseRecord{}, err
	}
	if r.Identity != responseRecordIdentity(r) {
		return attemptResponseRecord{}, ErrErasureIdentityMismatch
	}
	if r.RecordHex != "" && (labels.namespace != ref.NamespaceIdentity() || labels.scope != ref.Scope().Identity() || labels.operation != ref.OperationIdentity()) {
		return attemptResponseRecord{}, ErrErasureIdentityMismatch
	}
	if err := responseBodyClaims(r); err != nil {
		return attemptResponseRecord{}, err
	}
	return r, nil
}

func responseBodyClaims(r attemptResponseRecord) error {
	if r.RecordHex == "" {
		return nil
	}
	body, _ := hex.DecodeString(r.RecordHex)
	if r.ContentDigest != hashBytes(body) || r.ResponseBytes != uint32(len(body)) {
		return ErrErasureBindingMismatch
	}
	return nil
}

// Inspect nested syntax before considering any well-shaped binding or checksum.
func responseBodyShape(r attemptResponseRecord) error {
	if !erasureMetadataHex(r.RecordHex, responseBodyLimit(r.ContentKind)) {
		return ErrInvalidErasureContract
	}
	if r.RecordHex == "" {
		return nil
	}
	body, _ := hex.DecodeString(r.RecordHex)
	switch r.ContentKind {
	case "fence":
		var record erasureFenceRecord
		if len(body) > 4096 || !bytes.HasPrefix(body, []byte(erasureFenceMagic)) ||
			!erasureMetadataDecode(body[len(erasureFenceMagic):], 4096-len(erasureFenceMagic), &record) ||
			record.Contract != erasureFenceContract || record.SchemaVersion != 1 || record.ErasureProtocol != erasureOperationProtocol ||
			!erasureMetadataMillis(record.PreparedAtMilliseconds) {
			return ErrInvalidErasureContract
		}
		for _, id := range [...]string{record.Identity, record.NamespaceIdentity, record.ScopeIdentity, record.ArtifactIdentity, record.OperationIdentity} {
			if !validDigest(id) {
				return ErrInvalidErasureContract
			}
		}
	case "operation":
		var record erasureOperationRecord
		if !erasureMetadataDecode(body, 16384, &record) || record.Contract != erasureOperationContract || record.SchemaVersion != 2 ||
			record.Ownership != erasureAuthorizationV2Ownership || record.ErasureProtocol != erasureOperationProtocol ||
			!erasureMetadataMillis(record.PreparedAtMilliseconds) || record.LegacyReceiptIdentity != "" && !validDigest(record.LegacyReceiptIdentity) {
			return ErrInvalidErasureContract
		}
		for _, id := range [...]string{record.Identity, record.NamespaceIdentity, record.ScopeIdentity, record.ArtifactIdentity, record.AdmissionIdentity,
			record.OriginalAuthorizationIdentity, record.AuthorizationDocumentDigest, record.PolicyIdentity, record.ProtectedPolicyIdentity} {
			if !validDigest(id) {
				return ErrInvalidErasureContract
			}
		}
	case "attestation":
		var record erasureAttestationV2Record
		if !erasureMetadataDecode(body, 8192, &record) {
			return ErrInvalidErasureContract
		}
		return record.shape()
	default:
		return ErrInvalidErasureContract
	}
	return nil
}
