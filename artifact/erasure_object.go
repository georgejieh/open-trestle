package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrErasureBlocked is a definitive refusal, never evidence of absence.
var ErrErasureBlocked = errors.New("erasure operation blocked")

// ExactObjectKey is immutable scoped metadata, not a grant. Its zero is invalid.
type ExactObjectKey struct{ namespaceIdentity, key string }

func NewExactObjectKey(namespace, key string) (ExactObjectKey, error) {
	if len(namespace) != 64 || len(key) == 0 || len(key) > 1024 {
		return ExactObjectKey{}, ErrInvalidErasureContract
	}
	value := ExactObjectKey{namespace, key}
	if err := value.Validate(); err != nil {
		return ExactObjectKey{}, err
	}
	value.namespaceIdentity, value.key = strings.Clone(namespace), strings.Clone(key)
	return value, nil
}
func (k ExactObjectKey) Validate() error {
	if !validDigest(k.namespaceIdentity) || k.namespaceIdentity == strings.Repeat("0", 64) || !validExactObjectKey(k.key) {
		return ErrInvalidErasureContract
	}
	return nil
}
func (k ExactObjectKey) NamespaceIdentity() string { return k.namespaceIdentity }
func (k ExactObjectKey) Key() string               { return k.key }
func (k ExactObjectKey) String() string            { return "artifact exact object key" }
func (k ExactObjectKey) GoString() string          { return "artifact.ExactObjectKey{<redacted>}" }
func (k ExactObjectKey) Format(s fmt.State, v rune) {
	formatErasureValue(s, v, k.String(), k.GoString())
}

func validExactObjectKey(key string) bool {
	if len(key) == 0 || len(key) > 1024 || !utf8.ValidString(key) {
		return false
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, c := range segment {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}

type ObjectVersionKind uint8

const (
	ObjectVersionData         ObjectVersionKind = 1
	ObjectVersionDeleteMarker ObjectVersionKind = 2
)

// ObjectVersion identifies metadata only. It cannot authorize a request.
type ObjectVersion struct {
	identity, namespaceIdentity, key, versionID string
	kind                                        ObjectVersionKind
}

func NewObjectVersion(namespace, key string, kind ObjectVersionKind, versionID string) (ObjectVersion, error) {
	if len(namespace) != 64 || len(key) == 0 || len(key) > 1024 || len(versionID) == 0 || len(versionID) > 504 {
		return ObjectVersion{}, ErrInvalidErasureContract
	}
	value := ObjectVersion{namespaceIdentity: namespace, key: key, versionID: versionID, kind: kind}
	if !value.validFields() {
		return ObjectVersion{}, ErrInvalidErasureContract
	}
	value.namespaceIdentity, value.key, value.versionID = strings.Clone(namespace), strings.Clone(key), strings.Clone(versionID)
	value.identity = deriveObjectVersionIdentity(value)
	return value, nil
}
func (v ObjectVersion) validFields() bool {
	return (ExactObjectKey{v.namespaceIdentity, v.key}).Validate() == nil && (v.kind == ObjectVersionData || v.kind == ObjectVersionDeleteMarker) && validObjectVersionID(v.versionID)
}
func validObjectVersionID(id string) bool {
	if len(id) < 1 || len(id) > 504 || id == "null" || !utf8.ValidString(id) {
		return false
	}
	for _, c := range id {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (v ObjectVersion) Validate() error {
	if !v.validFields() || !validDigest(v.identity) || v.identity == strings.Repeat("0", 64) {
		return ErrInvalidErasureContract
	}
	if v.identity != deriveObjectVersionIdentity(v) {
		return ErrErasureIdentityMismatch
	}
	return nil
}
func (v ObjectVersion) Identity() string          { return v.identity }
func (v ObjectVersion) NamespaceIdentity() string { return v.namespaceIdentity }
func (v ObjectVersion) Key() string               { return v.key }
func (v ObjectVersion) Kind() ObjectVersionKind   { return v.kind }
func (v ObjectVersion) VersionID() string         { return v.versionID }
func (v ObjectVersion) String() string            { return "artifact object version" }
func (v ObjectVersion) GoString() string          { return "artifact.ObjectVersion{<redacted>}" }
func (v ObjectVersion) Format(s fmt.State, verb rune) {
	formatErasureValue(s, verb, v.String(), v.GoString())
}

type VersionCursor struct{ KeyMarker, VersionIDMarker string }
type VersionEntry struct {
	Version  ObjectVersion
	IsLatest bool
}
type VersionPage struct {
	Entries       []VersionEntry
	Next          VersionCursor
	Truncated     bool
	ResponseBytes uint32
}
type ErasureReadKind uint8

const (
	ErasureReadPresent             ErasureReadKind = 1
	ErasureReadAbsent              ErasureReadKind = 2
	ErasureReadCurrentDeleteMarker ErasureReadKind = 3
)

// ErasureObjectRead has exclusive branches: Present has Object only, Absent has
// neither payload, and CurrentDeleteMarker has Marker only. Errors return zero.
type ErasureObjectRead struct {
	Kind   ErasureReadKind
	Object RemoteObject
	Marker ObjectVersion
}
type VersionDeleteOutcome uint8

const (
	VersionDeleteDeleted  VersionDeleteOutcome = 1
	VersionDeleteNotFound VersionDeleteOutcome = 2
)

type ErasureObjectBackend interface {
	ConfiguredObjectBackend
	ValidateErasure() error
	ReadErasureObject(context.Context, ExactObjectKey, string, uint32) (ErasureObjectRead, error)
	CreateErasureObject(context.Context, ExactObjectKey, string, []byte, string) (bool, error)
	ListObjectVersions(context.Context, ExactObjectKey, string, VersionCursor, uint16, uint32) (VersionPage, error)
	DeleteObjectVersion(context.Context, ExactObjectKey, string, ObjectVersion) (VersionDeleteOutcome, error)
}
