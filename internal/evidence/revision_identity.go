package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// RevisionKind identifies the immutable source object category.
type RevisionKind string

// RevisionAlgorithm identifies the digest algorithm used by the source object.
type RevisionAlgorithm string

const (
	RevisionKindGitCommit RevisionKind = "git_commit"

	RevisionAlgorithmSHA1   RevisionAlgorithm = "sha1"
	RevisionAlgorithmSHA256 RevisionAlgorithm = "sha256"
)

// RevisionIdentity records canonical syntax for a full immutable revision identifier.
type RevisionIdentity struct {
	identity  string
	kind      RevisionKind
	algorithm RevisionAlgorithm
	digest    string
}

// NewRevisionIdentity validates and labels a full revision digest without resolving it.
func NewRevisionIdentity(kind RevisionKind, algorithm RevisionAlgorithm, digest string) (RevisionIdentity, error) {
	if kind != RevisionKindGitCommit {
		return RevisionIdentity{}, fmt.Errorf("unsupported revision kind %q", kind)
	}
	expectedLength := 0
	switch algorithm {
	case RevisionAlgorithmSHA1:
		expectedLength = sha1HexLength
	case RevisionAlgorithmSHA256:
		expectedLength = sha256.Size * 2
	default:
		return RevisionIdentity{}, fmt.Errorf("unsupported revision algorithm %q", algorithm)
	}
	if len(digest) != expectedLength {
		return RevisionIdentity{}, fmt.Errorf("%s revision digest has %d characters, want %d", algorithm, len(digest), expectedLength)
	}
	if digest != strings.ToLower(digest) {
		return RevisionIdentity{}, fmt.Errorf("revision digest must use lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return RevisionIdentity{}, fmt.Errorf("revision digest is not hexadecimal: %w", err)
	}
	if strings.Trim(digest, "0") == "" {
		return RevisionIdentity{}, fmt.Errorf("revision digest must not be all zero")
	}
	preimage := struct {
		Contract      string            `json:"contract"`
		SchemaVersion int               `json:"schema_version"`
		Kind          RevisionKind      `json:"kind"`
		Algorithm     RevisionAlgorithm `json:"algorithm"`
		Digest        string            `json:"digest"`
	}{
		Contract:      "open-trestle/revision-identity",
		SchemaVersion: 1,
		Kind:          kind,
		Algorithm:     algorithm,
		Digest:        digest,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RevisionIdentity{}, fmt.Errorf("encode revision identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return RevisionIdentity{
		identity:  hex.EncodeToString(identityDigest[:]),
		kind:      kind,
		algorithm: algorithm,
		digest:    digest,
	}, nil
}

// A full Git SHA-1 object identifier contains 40 hexadecimal characters.
const sha1HexLength = 40

// Identity returns the versioned canonical SHA-256 identity.
func (r RevisionIdentity) Identity() string {
	return r.identity
}

// Kind returns the immutable source object category.
func (r RevisionIdentity) Kind() RevisionKind {
	return r.kind
}

// Algorithm returns the source digest algorithm.
func (r RevisionIdentity) Algorithm() RevisionAlgorithm {
	return r.algorithm
}

// Digest returns the full lowercase source object digest.
func (r RevisionIdentity) Digest() string {
	return r.digest
}
