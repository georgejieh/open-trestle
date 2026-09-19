package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"
)

const objectVersionContract = "open-trestle/artifact-object-version"

type objectVersionRecord struct {
	Contract          string `json:"contract"`
	SchemaVersion     int    `json:"schema_version"`
	Identity          string `json:"identity,omitempty"`
	NamespaceIdentity string `json:"namespace_identity"`
	Key               string `json:"key"`
	Kind              string `json:"kind"`
	VersionID         string `json:"version_id"`
}

func objectVersionRecordFromValue(v ObjectVersion) objectVersionRecord {
	kind := "data"
	if v.kind == ObjectVersionDeleteMarker {
		kind = "delete_marker"
	}
	return objectVersionRecord{objectVersionContract, 1, v.identity, v.namespaceIdentity, v.key, kind, v.versionID}
}
func deriveObjectVersionIdentity(v ObjectVersion) string {
	record := objectVersionRecordFromValue(v)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	sum := sha256.Sum256(append([]byte(objectVersionContract+"/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}
func EncodeObjectVersion(v ObjectVersion) ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(objectVersionRecordFromValue(v))
	if err != nil || len(encoded) > 4096 {
		return nil, ErrInvalidErasureContract
	}
	return encoded, nil
}
func ParseObjectVersion(encoded []byte) (ObjectVersion, error) {
	var record objectVersionRecord
	if !utf8.Valid(encoded) || !canonicalErasureRecord(encoded, 4096, &record) || record.Contract != objectVersionContract || record.SchemaVersion != 1 {
		return ObjectVersion{}, ErrInvalidErasureContract
	}
	var kind ObjectVersionKind
	switch record.Kind {
	case "data":
		kind = ObjectVersionData
	case "delete_marker":
		kind = ObjectVersionDeleteMarker
	default:
		return ObjectVersion{}, ErrInvalidErasureContract
	}
	value, err := NewObjectVersion(record.NamespaceIdentity, record.Key, kind, record.VersionID)
	if err != nil {
		return ObjectVersion{}, err
	}
	if record.Identity != value.identity {
		return ObjectVersion{}, ErrErasureIdentityMismatch
	}
	canonical, err := EncodeObjectVersion(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ObjectVersion{}, ErrInvalidErasureContract
	}
	return value, nil
}
