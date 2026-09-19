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

// Bounds caller-controlled hashing while covering large source blobs.
const maxGitBlobObjectBytes = 64 << 20

// GitBlobObjectVerification records one selected immediate blob object verification.
type GitBlobObjectVerification struct {
	identity                 string
	gitCommitIdentity        string
	gitTreeIdentity          string
	treeVerificationIdentity string
	entryIndex               int
	entryMode                GitTreeMode
	entryName                []byte
	algorithm                RevisionAlgorithm
	declaredBlobDigest       string
	computedBlobDigest       string
	contentSizeBytes         int
}

// VerifyGitBlobObject verifies exact blob bytes for one canonical immediate tree entry.
func VerifyGitBlobObject(revision RevisionIdentity, commitVerification GitCommitObjectVerification, commitContent []byte, commit GitCommit, treeVerification GitTreeObjectVerification, treeContent []byte, tree GitTree, entryIndex int, blobContent []byte) (GitBlobObjectVerification, error) {
	if len(blobContent) > maxGitBlobObjectBytes {
		return GitBlobObjectVerification{}, fmt.Errorf("git blob object has %d bytes, want at most %d", len(blobContent), maxGitBlobObjectBytes)
	}
	canonicalTree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, treeVerification, treeContent)
	if err != nil || !gitTreeValuesEqual(tree, canonicalTree) {
		return GitBlobObjectVerification{}, fmt.Errorf("git tree does not match verified content")
	}
	if entryIndex < 0 || entryIndex >= len(canonicalTree.entries) {
		return GitBlobObjectVerification{}, fmt.Errorf("git tree entry index %d is out of range", entryIndex)
	}
	entry := canonicalTree.entries[entryIndex]
	switch entry.mode {
	case GitTreeModeRegular, GitTreeModeExecutable, GitTreeModeSymlink:
		if entry.kind != GitTreeEntryKindBlob {
			return GitBlobObjectVerification{}, fmt.Errorf("git tree entry kind does not match blob mode")
		}
	case GitTreeModeDirectory, GitTreeModeGitlink:
		return GitBlobObjectVerification{}, fmt.Errorf("git tree entry mode %q does not reference a blob", entry.mode)
	default:
		return GitBlobObjectVerification{}, fmt.Errorf("unsupported git tree entry mode %q", entry.mode)
	}
	var objectHash hash.Hash
	switch entry.objectAlgorithm {
	case RevisionAlgorithmSHA1:
		objectHash = sha1.New()
	case RevisionAlgorithmSHA256:
		objectHash = sha256.New()
	default:
		return GitBlobObjectVerification{}, fmt.Errorf("unsupported blob algorithm %q", entry.objectAlgorithm)
	}
	for _, part := range [][]byte{[]byte("blob "), []byte(strconv.Itoa(len(blobContent))), []byte{0}, blobContent} {
		written, err := objectHash.Write(part)
		if err != nil || written != len(part) {
			return GitBlobObjectVerification{}, fmt.Errorf("hash git blob object framing")
		}
	}
	computedBytes := objectHash.Sum(nil)
	declaredBytes, err := hex.DecodeString(entry.objectDigest)
	if err != nil {
		return GitBlobObjectVerification{}, fmt.Errorf("decode declared blob digest: %w", err)
	}
	if len(declaredBytes) != len(computedBytes) || subtle.ConstantTimeCompare(declaredBytes, computedBytes) != 1 {
		return GitBlobObjectVerification{}, fmt.Errorf("git blob object digest does not match tree entry")
	}
	computedDigest := hex.EncodeToString(computedBytes)
	preimage := struct {
		Contract                 string            `json:"contract"`
		SchemaVersion            int               `json:"schema_version"`
		GitCommitIdentity        string            `json:"git_commit_identity"`
		GitTreeIdentity          string            `json:"git_tree_identity"`
		TreeVerificationIdentity string            `json:"tree_verification_identity"`
		EntryIndex               int               `json:"entry_index"`
		EntryMode                GitTreeMode       `json:"entry_mode"`
		EntryNameHex             string            `json:"entry_name_hex"`
		Algorithm                RevisionAlgorithm `json:"algorithm"`
		DeclaredBlobDigest       string            `json:"declared_blob_digest"`
		ComputedBlobDigest       string            `json:"computed_blob_digest"`
		ContentSizeBytes         int               `json:"content_size_bytes"`
		ObjectType               string            `json:"object_type"`
		FramingVersion           string            `json:"framing_version"`
	}{
		Contract:                 "open-trestle/git-blob-object-verification",
		SchemaVersion:            1,
		GitCommitIdentity:        canonicalTree.GitCommitIdentity(),
		GitTreeIdentity:          canonicalTree.Identity(),
		TreeVerificationIdentity: canonicalTree.TreeVerificationIdentity(),
		EntryIndex:               entryIndex,
		EntryMode:                entry.mode,
		EntryNameHex:             hex.EncodeToString(entry.name),
		Algorithm:                entry.objectAlgorithm,
		DeclaredBlobDigest:       entry.objectDigest,
		ComputedBlobDigest:       computedDigest,
		ContentSizeBytes:         len(blobContent),
		ObjectType:               "blob",
		FramingVersion:           gitObjectFramingVersion,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitBlobObjectVerification{}, fmt.Errorf("encode git blob object verification identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitBlobObjectVerification{
		identity:                 hex.EncodeToString(identityDigest[:]),
		gitCommitIdentity:        canonicalTree.GitCommitIdentity(),
		gitTreeIdentity:          canonicalTree.Identity(),
		treeVerificationIdentity: canonicalTree.TreeVerificationIdentity(),
		entryIndex:               entryIndex,
		entryMode:                entry.mode,
		entryName:                append([]byte{}, entry.name...),
		algorithm:                entry.objectAlgorithm,
		declaredBlobDigest:       entry.objectDigest,
		computedBlobDigest:       computedDigest,
		contentSizeBytes:         len(blobContent),
	}, nil
}

func gitTreeValuesEqual(first, second GitTree) bool {
	if (first.entries == nil) != (second.entries == nil) || first.identity != second.identity || first.gitCommitIdentity != second.gitCommitIdentity || first.treeVerificationIdentity != second.treeVerificationIdentity || first.treeAlgorithm != second.treeAlgorithm || first.treeDigest != second.treeDigest || len(first.entries) != len(second.entries) {
		return false
	}
	for i := range first.entries {
		if !gitTreeEntryValuesEqual(first.entries[i], second.entries[i]) {
			return false
		}
	}
	return true
}

func gitTreeEntryValuesEqual(first, second GitTreeEntry) bool {
	if (first.name == nil) != (second.name == nil) || first.mode != second.mode || first.kind != second.kind || first.objectAlgorithm != second.objectAlgorithm || first.objectDigest != second.objectDigest || len(first.name) != len(second.name) {
		return false
	}
	for i := range first.name {
		if first.name[i] != second.name[i] {
			return false
		}
	}
	return true
}

// Identity returns the versioned canonical SHA-256 identity.
func (v GitBlobObjectVerification) Identity() string {
	return v.identity
}

// GitCommitIdentity returns the exact parsed commit identity.
func (v GitBlobObjectVerification) GitCommitIdentity() string {
	return v.gitCommitIdentity
}

// GitTreeIdentity returns the exact parsed tree identity.
func (v GitBlobObjectVerification) GitTreeIdentity() string {
	return v.gitTreeIdentity
}

// TreeVerificationIdentity returns the exact tree object verification identity.
func (v GitBlobObjectVerification) TreeVerificationIdentity() string {
	return v.treeVerificationIdentity
}

// EntryIndex returns the canonical zero-based tree entry index.
func (v GitBlobObjectVerification) EntryIndex() int {
	return v.entryIndex
}

// EntryMode returns the selected canonical tree mode.
func (v GitBlobObjectVerification) EntryMode() GitTreeMode {
	return v.entryMode
}

// EntryName returns a defensive copy of the selected raw name bytes.
func (v GitBlobObjectVerification) EntryName() []byte {
	return append([]byte{}, v.entryName...)
}

// EntryNameHex returns lowercase hexadecimal selected name bytes.
func (v GitBlobObjectVerification) EntryNameHex() string {
	return hex.EncodeToString(v.entryName)
}

// Algorithm returns the selected blob object digest algorithm.
func (v GitBlobObjectVerification) Algorithm() RevisionAlgorithm {
	return v.algorithm
}

// DeclaredBlobDigest returns the full blob object ID declared by the tree entry.
func (v GitBlobObjectVerification) DeclaredBlobDigest() string {
	return v.declaredBlobDigest
}

// ComputedBlobDigest returns the full digest computed from supplied blob bytes.
func (v GitBlobObjectVerification) ComputedBlobDigest() string {
	return v.computedBlobDigest
}

// ContentSizeBytes returns the verified unframed blob payload size.
func (v GitBlobObjectVerification) ContentSizeBytes() int {
	return v.contentSizeBytes
}

// ObjectType returns the fixed Git object type.
func (v GitBlobObjectVerification) ObjectType() string {
	if v.identity == "" {
		return ""
	}
	return "blob"
}

// FramingVersion returns the Git object framing contract version.
func (v GitBlobObjectVerification) FramingVersion() string {
	if v.identity == "" {
		return ""
	}
	return gitObjectFramingVersion
}
