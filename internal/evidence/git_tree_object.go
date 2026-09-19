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

// Bounds caller-controlled hashing while covering large tree payloads.
const maxGitTreeObjectBytes = 16 << 20

// GitTreeObjectVerification records supplied tree object identity and commit-reference verification.
type GitTreeObjectVerification struct {
	identity           string
	gitCommitIdentity  string
	revisionIdentity   string
	treeAlgorithm      RevisionAlgorithm
	declaredTreeDigest string
	computedTreeDigest string
	contentSizeBytes   int
}

// VerifyGitTreeObject verifies exact tree payload bytes against a reparsed commit reference.
func VerifyGitTreeObject(revision RevisionIdentity, commitVerification GitCommitObjectVerification, commitContent []byte, commit GitCommit, treeContent []byte) (GitTreeObjectVerification, error) {
	if len(treeContent) > maxGitTreeObjectBytes {
		return GitTreeObjectVerification{}, fmt.Errorf("git tree object has %d bytes, want at most %d", len(treeContent), maxGitTreeObjectBytes)
	}
	canonicalRevision, err := NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || revision != canonicalRevision {
		return GitTreeObjectVerification{}, fmt.Errorf("revision identity is not canonical")
	}
	canonicalCommitVerification, err := VerifyGitCommitObject(canonicalRevision, commitContent)
	if err != nil || commitVerification != canonicalCommitVerification {
		return GitTreeObjectVerification{}, fmt.Errorf("git commit object verification does not match content")
	}
	canonicalCommit, err := ParseVerifiedGitCommit(canonicalRevision, canonicalCommitVerification, commitContent)
	if err != nil || !gitCommitValuesEqual(commit, canonicalCommit) {
		return GitTreeObjectVerification{}, fmt.Errorf("git commit does not match verified content")
	}
	var objectHash hash.Hash
	switch canonicalCommit.TreeAlgorithm() {
	case RevisionAlgorithmSHA1:
		objectHash = sha1.New()
	case RevisionAlgorithmSHA256:
		objectHash = sha256.New()
	default:
		return GitTreeObjectVerification{}, fmt.Errorf("unsupported tree algorithm %q", canonicalCommit.TreeAlgorithm())
	}
	for _, part := range [][]byte{[]byte("tree "), []byte(strconv.Itoa(len(treeContent))), []byte{0}, treeContent} {
		written, err := objectHash.Write(part)
		if err != nil || written != len(part) {
			return GitTreeObjectVerification{}, fmt.Errorf("hash git tree object framing")
		}
	}
	computedBytes := objectHash.Sum(nil)
	declaredBytes, err := hex.DecodeString(canonicalCommit.TreeDigest())
	if err != nil {
		return GitTreeObjectVerification{}, fmt.Errorf("decode declared tree digest: %w", err)
	}
	if len(declaredBytes) != len(computedBytes) || subtle.ConstantTimeCompare(declaredBytes, computedBytes) != 1 {
		return GitTreeObjectVerification{}, fmt.Errorf("git tree object digest does not match commit")
	}
	computedDigest := hex.EncodeToString(computedBytes)
	preimage := struct {
		Contract           string            `json:"contract"`
		SchemaVersion      int               `json:"schema_version"`
		GitCommitIdentity  string            `json:"git_commit_identity"`
		RevisionIdentity   string            `json:"revision_identity"`
		TreeAlgorithm      RevisionAlgorithm `json:"tree_algorithm"`
		DeclaredTreeDigest string            `json:"declared_tree_digest"`
		ComputedTreeDigest string            `json:"computed_tree_digest"`
		ContentSizeBytes   int               `json:"content_size_bytes"`
		ObjectType         string            `json:"object_type"`
		FramingVersion     string            `json:"framing_version"`
	}{
		Contract:           "open-trestle/git-tree-object-verification",
		SchemaVersion:      1,
		GitCommitIdentity:  canonicalCommit.Identity(),
		RevisionIdentity:   canonicalRevision.Identity(),
		TreeAlgorithm:      canonicalCommit.TreeAlgorithm(),
		DeclaredTreeDigest: canonicalCommit.TreeDigest(),
		ComputedTreeDigest: computedDigest,
		ContentSizeBytes:   len(treeContent),
		ObjectType:         "tree",
		FramingVersion:     gitObjectFramingVersion,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitTreeObjectVerification{}, fmt.Errorf("encode git tree object verification identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitTreeObjectVerification{
		identity:           hex.EncodeToString(identityDigest[:]),
		gitCommitIdentity:  canonicalCommit.Identity(),
		revisionIdentity:   canonicalRevision.Identity(),
		treeAlgorithm:      canonicalCommit.TreeAlgorithm(),
		declaredTreeDigest: canonicalCommit.TreeDigest(),
		computedTreeDigest: computedDigest,
		contentSizeBytes:   len(treeContent),
	}, nil
}

func gitCommitValuesEqual(first, second GitCommit) bool {
	if (first.parents == nil) != (second.parents == nil) || first.identity != second.identity || first.revisionIdentity != second.revisionIdentity || first.objectVerificationIdentity != second.objectVerificationIdentity || first.treeAlgorithm != second.treeAlgorithm || first.treeDigest != second.treeDigest || first.encoding != second.encoding || first.headerCount != second.headerCount || first.messageSizeBytes != second.messageSizeBytes || first.messageDigest != second.messageDigest || len(first.parents) != len(second.parents) {
		return false
	}
	for i := range first.parents {
		if first.parents[i] != second.parents[i] {
			return false
		}
	}
	return true
}

// Identity returns the versioned canonical SHA-256 identity.
func (v GitTreeObjectVerification) Identity() string {
	return v.identity
}

// GitCommitIdentity returns the exact parsed commit identity.
func (v GitTreeObjectVerification) GitCommitIdentity() string {
	return v.gitCommitIdentity
}

// RevisionIdentity returns the revision identity whose tree reference was verified.
func (v GitTreeObjectVerification) RevisionIdentity() string {
	return v.revisionIdentity
}

// TreeAlgorithm returns the declared tree object digest algorithm.
func (v GitTreeObjectVerification) TreeAlgorithm() RevisionAlgorithm {
	return v.treeAlgorithm
}

// DeclaredTreeDigest returns the full tree object ID declared by the commit.
func (v GitTreeObjectVerification) DeclaredTreeDigest() string {
	return v.declaredTreeDigest
}

// ComputedTreeDigest returns the full digest computed from supplied tree bytes.
func (v GitTreeObjectVerification) ComputedTreeDigest() string {
	return v.computedTreeDigest
}

// ContentSizeBytes returns the verified unframed tree payload size.
func (v GitTreeObjectVerification) ContentSizeBytes() int {
	return v.contentSizeBytes
}

// ObjectType returns the fixed Git object type.
func (v GitTreeObjectVerification) ObjectType() string {
	if v.identity == "" {
		return ""
	}
	return "tree"
}

// FramingVersion returns the Git object framing contract version.
func (v GitTreeObjectVerification) FramingVersion() string {
	if v.identity == "" {
		return ""
	}
	return gitObjectFramingVersion
}
