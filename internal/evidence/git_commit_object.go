package evidence

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strconv"
)

// Bounds caller-controlled hashing while covering practical commit payloads.
const maxGitCommitObjectBytes = 4 << 20

const gitObjectFramingVersion = "git-object-v1"

// GitCommitObjectVerification records exact Git commit object identity verification.
type GitCommitObjectVerification struct {
	identity         string
	revisionIdentity string
	algorithm        RevisionAlgorithm
	computedDigest   string
	contentSizeBytes int
}

// VerifyGitCommitObject verifies exact unframed payload bytes against a commit object ID.
func VerifyGitCommitObject(revision RevisionIdentity, content []byte) (GitCommitObjectVerification, error) {
	if len(content) > maxGitCommitObjectBytes {
		return GitCommitObjectVerification{}, fmt.Errorf("git commit object has %d bytes, want at most %d", len(content), maxGitCommitObjectBytes)
	}
	canonicalRevision, err := NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || revision != canonicalRevision {
		return GitCommitObjectVerification{}, fmt.Errorf("revision identity is not canonical")
	}
	var objectHash hash.Hash
	switch canonicalRevision.Algorithm() {
	case RevisionAlgorithmSHA1:
		objectHash = sha1.New()
	case RevisionAlgorithmSHA256:
		objectHash = sha256.New()
	default:
		return GitCommitObjectVerification{}, fmt.Errorf("unsupported revision algorithm %q", canonicalRevision.Algorithm())
	}
	for _, part := range [][]byte{[]byte("commit "), []byte(strconv.Itoa(len(content))), []byte{0}, content} {
		written, err := objectHash.Write(part)
		if err != nil || written != len(part) {
			return GitCommitObjectVerification{}, fmt.Errorf("hash git commit object framing")
		}
	}
	computedBytes := objectHash.Sum(nil)
	expectedBytes, err := hex.DecodeString(canonicalRevision.Digest())
	if err != nil {
		return GitCommitObjectVerification{}, fmt.Errorf("decode revision digest: %w", err)
	}
	if len(expectedBytes) != len(computedBytes) || subtle.ConstantTimeCompare(expectedBytes, computedBytes) != 1 {
		return GitCommitObjectVerification{}, fmt.Errorf("git commit object digest does not match revision")
	}
	computedDigest := hex.EncodeToString(computedBytes)
	preimage := struct {
		Contract         string            `json:"contract"`
		SchemaVersion    int               `json:"schema_version"`
		RevisionIdentity string            `json:"revision_identity"`
		ObjectType       string            `json:"object_type"`
		Algorithm        RevisionAlgorithm `json:"algorithm"`
		ComputedDigest   string            `json:"computed_digest"`
		ContentSizeBytes int               `json:"content_size_bytes"`
		FramingVersion   string            `json:"framing_version"`
	}{
		Contract:         "open-trestle/git-commit-object-verification",
		SchemaVersion:    1,
		RevisionIdentity: canonicalRevision.Identity(),
		ObjectType:       "commit",
		Algorithm:        canonicalRevision.Algorithm(),
		ComputedDigest:   computedDigest,
		ContentSizeBytes: len(content),
		FramingVersion:   gitObjectFramingVersion,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitCommitObjectVerification{}, fmt.Errorf("encode git commit object verification identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitCommitObjectVerification{
		identity:         hex.EncodeToString(identityDigest[:]),
		revisionIdentity: canonicalRevision.Identity(),
		algorithm:        canonicalRevision.Algorithm(),
		computedDigest:   computedDigest,
		contentSizeBytes: len(content),
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (v GitCommitObjectVerification) Identity() string {
	return v.identity
}

// RevisionIdentity returns the revision identity whose object digest was verified.
func (v GitCommitObjectVerification) RevisionIdentity() string {
	return v.revisionIdentity
}

// Algorithm returns the Git object digest algorithm.
func (v GitCommitObjectVerification) Algorithm() RevisionAlgorithm {
	return v.algorithm
}

// ObjectType returns the fixed Git object type.
func (v GitCommitObjectVerification) ObjectType() string {
	if v.identity == "" {
		return ""
	}
	return "commit"
}

// ComputedDigest returns the full computed Git object digest.
func (v GitCommitObjectVerification) ComputedDigest() string {
	return v.computedDigest
}

// ContentSizeBytes returns the verified unframed payload size.
func (v GitCommitObjectVerification) ContentSizeBytes() int {
	return v.contentSizeBytes
}

// FramingVersion returns the Git object framing contract version.
func (v GitCommitObjectVerification) FramingVersion() string {
	if v.identity == "" {
		return ""
	}
	return gitObjectFramingVersion
}
