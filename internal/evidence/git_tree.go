package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	maxGitTreeEntries        = 65_536
	maxGitTreeNameBytes      = 4 << 10
	maxGitTreeTotalNameBytes = maxGitTreeObjectBytes
)

// GitTreeMode identifies an accepted canonical Git tree mode.
type GitTreeMode string

// GitTreeEntryKind identifies the object kind implied by a tree mode.
type GitTreeEntryKind string

const (
	GitTreeModeRegular    GitTreeMode = "100644"
	GitTreeModeExecutable GitTreeMode = "100755"
	GitTreeModeSymlink    GitTreeMode = "120000"
	GitTreeModeDirectory  GitTreeMode = "40000"
	GitTreeModeGitlink    GitTreeMode = "160000"

	GitTreeEntryKindBlob   GitTreeEntryKind = "blob"
	GitTreeEntryKindTree   GitTreeEntryKind = "tree"
	GitTreeEntryKindCommit GitTreeEntryKind = "commit"
)

// GitTreeEntry records one immediate parsed tree entry.
type GitTreeEntry struct {
	mode            GitTreeMode
	kind            GitTreeEntryKind
	name            []byte
	objectAlgorithm RevisionAlgorithm
	objectDigest    string
}

// GitTree records canonical immediate entries parsed from a verified tree object.
type GitTree struct {
	identity                 string
	gitCommitIdentity        string
	treeVerificationIdentity string
	treeAlgorithm            RevisionAlgorithm
	treeDigest               string
	entries                  []GitTreeEntry
}

// ParseVerifiedGitTree parses canonical immediate entries from exact verified tree bytes.
func ParseVerifiedGitTree(revision RevisionIdentity, commitVerification GitCommitObjectVerification, commitContent []byte, commit GitCommit, treeVerification GitTreeObjectVerification, treeContent []byte) (GitTree, error) {
	canonicalVerification, err := VerifyGitTreeObject(revision, commitVerification, commitContent, commit, treeContent)
	if err != nil || treeVerification != canonicalVerification {
		return GitTree{}, fmt.Errorf("git tree object verification does not match content")
	}
	objectIDBytes := sha1HexLength / 2
	if canonicalVerification.TreeAlgorithm() == RevisionAlgorithmSHA256 {
		objectIDBytes = sha256.Size
	}
	entries := make([]GitTreeEntry, 0)
	seenNames := make(map[string]struct{})
	totalNameBytes := 0
	cursor := 0
	for cursor < len(treeContent) {
		if len(entries) >= maxGitTreeEntries {
			return GitTree{}, fmt.Errorf("git tree has more than %d entries", maxGitTreeEntries)
		}
		modeEnd := bytes.IndexByte(treeContent[cursor:], ' ')
		if modeEnd < 0 {
			return GitTree{}, fmt.Errorf("git tree entry is missing mode delimiter")
		}
		modeBytes := treeContent[cursor : cursor+modeEnd]
		mode, kind, err := parseGitTreeMode(modeBytes)
		if err != nil {
			return GitTree{}, err
		}
		cursor += modeEnd + 1
		nameEnd := bytes.IndexByte(treeContent[cursor:], 0)
		if nameEnd < 0 {
			return GitTree{}, fmt.Errorf("git tree entry is missing name terminator")
		}
		name := treeContent[cursor : cursor+nameEnd]
		if err := validateGitTreeName(name); err != nil {
			return GitTree{}, err
		}
		if totalNameBytes > maxGitTreeTotalNameBytes-len(name) {
			return GitTree{}, fmt.Errorf("git tree names exceed %d bytes", maxGitTreeTotalNameBytes)
		}
		totalNameBytes += len(name)
		nameKey := string(name)
		if _, exists := seenNames[nameKey]; exists {
			return GitTree{}, fmt.Errorf("git tree contains duplicate name %x", name)
		}
		cursor += nameEnd + 1
		if len(treeContent)-cursor < objectIDBytes {
			return GitTree{}, fmt.Errorf("git tree entry object ID is truncated")
		}
		objectID := treeContent[cursor : cursor+objectIDBytes]
		cursor += objectIDBytes
		entry := GitTreeEntry{
			mode:            mode,
			kind:            kind,
			name:            append([]byte{}, name...),
			objectAlgorithm: canonicalVerification.TreeAlgorithm(),
			objectDigest:    hex.EncodeToString(objectID),
		}
		if len(entries) > 0 {
			previous := entries[len(entries)-1]
			if compareGitTreeNames(previous.name, previous.mode == GitTreeModeDirectory, entry.name, entry.mode == GitTreeModeDirectory) >= 0 {
				return GitTree{}, fmt.Errorf("git tree entries are not in canonical order")
			}
		}
		seenNames[nameKey] = struct{}{}
		entries = append(entries, entry)
	}
	preimage := struct {
		Contract                 string            `json:"contract"`
		SchemaVersion            int               `json:"schema_version"`
		GitCommitIdentity        string            `json:"git_commit_identity"`
		TreeVerificationIdentity string            `json:"tree_verification_identity"`
		TreeAlgorithm            RevisionAlgorithm `json:"tree_algorithm"`
		TreeDigest               string            `json:"tree_digest"`
		EntryCount               int               `json:"entry_count"`
	}{
		Contract:                 "open-trestle/git-tree",
		SchemaVersion:            1,
		GitCommitIdentity:        canonicalVerification.GitCommitIdentity(),
		TreeVerificationIdentity: canonicalVerification.Identity(),
		TreeAlgorithm:            canonicalVerification.TreeAlgorithm(),
		TreeDigest:               canonicalVerification.ComputedTreeDigest(),
		EntryCount:               len(entries),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitTree{}, fmt.Errorf("encode git tree identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitTree{
		identity:                 hex.EncodeToString(identityDigest[:]),
		gitCommitIdentity:        canonicalVerification.GitCommitIdentity(),
		treeVerificationIdentity: canonicalVerification.Identity(),
		treeAlgorithm:            canonicalVerification.TreeAlgorithm(),
		treeDigest:               canonicalVerification.ComputedTreeDigest(),
		entries:                  cloneGitTreeEntries(entries),
	}, nil
}

func parseGitTreeMode(mode []byte) (GitTreeMode, GitTreeEntryKind, error) {
	switch string(mode) {
	case string(GitTreeModeRegular):
		return GitTreeModeRegular, GitTreeEntryKindBlob, nil
	case string(GitTreeModeExecutable):
		return GitTreeModeExecutable, GitTreeEntryKindBlob, nil
	case string(GitTreeModeSymlink):
		return GitTreeModeSymlink, GitTreeEntryKindBlob, nil
	case string(GitTreeModeDirectory):
		return GitTreeModeDirectory, GitTreeEntryKindTree, nil
	case string(GitTreeModeGitlink):
		return GitTreeModeGitlink, GitTreeEntryKindCommit, nil
	default:
		return "", "", fmt.Errorf("unsupported git tree mode %q", mode)
	}
}

func validateGitTreeName(name []byte) error {
	if len(name) == 0 || len(name) > maxGitTreeNameBytes {
		return fmt.Errorf("git tree name has %d bytes, want 1 to %d", len(name), maxGitTreeNameBytes)
	}
	if bytes.IndexByte(name, '/') >= 0 {
		return fmt.Errorf("git tree name contains slash")
	}
	if bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
		return fmt.Errorf("git tree name must not be a dot component")
	}
	return nil
}

func compareGitTreeNames(first []byte, firstDirectory bool, second []byte, secondDirectory bool) int {
	common := len(first)
	if len(second) < common {
		common = len(second)
	}
	for i := 0; i < common; i++ {
		if first[i] != second[i] {
			return int(first[i]) - int(second[i])
		}
	}
	firstNext := byte(0)
	if len(first) > common {
		firstNext = first[common]
	} else if firstDirectory {
		firstNext = '/'
	}
	secondNext := byte(0)
	if len(second) > common {
		secondNext = second[common]
	} else if secondDirectory {
		secondNext = '/'
	}
	return int(firstNext) - int(secondNext)
}

func cloneGitTreeEntries(entries []GitTreeEntry) []GitTreeEntry {
	result := make([]GitTreeEntry, len(entries))
	for i, entry := range entries {
		result[i] = entry
		result[i].name = append([]byte{}, entry.name...)
	}
	return result
}

// Identity returns the versioned canonical SHA-256 identity.
func (t GitTree) Identity() string {
	return t.identity
}

// GitCommitIdentity returns the exact parsed commit identity.
func (t GitTree) GitCommitIdentity() string {
	return t.gitCommitIdentity
}

// TreeVerificationIdentity returns the exact tree object verification identity.
func (t GitTree) TreeVerificationIdentity() string {
	return t.treeVerificationIdentity
}

// TreeAlgorithm returns the tree object digest algorithm.
func (t GitTree) TreeAlgorithm() RevisionAlgorithm {
	return t.treeAlgorithm
}

// TreeDigest returns the verified tree object digest.
func (t GitTree) TreeDigest() string {
	return t.treeDigest
}

// Entries returns defensive copies of canonical immediate entries.
func (t GitTree) Entries() []GitTreeEntry {
	return cloneGitTreeEntries(t.entries)
}

// EntryCount returns the number of immediate tree entries.
func (t GitTree) EntryCount() int {
	return len(t.entries)
}

// Mode returns the exact canonical Git mode.
func (e GitTreeEntry) Mode() GitTreeMode {
	return e.mode
}

// Kind returns the object kind implied by the mode.
func (e GitTreeEntry) Kind() GitTreeEntryKind {
	return e.kind
}

// Name returns a defensive copy of the raw name bytes.
func (e GitTreeEntry) Name() []byte {
	return append([]byte{}, e.name...)
}

// NameHex returns lowercase hexadecimal raw name bytes.
func (e GitTreeEntry) NameHex() string {
	return hex.EncodeToString(e.name)
}

// ObjectAlgorithm returns the immediate object ID algorithm.
func (e GitTreeEntry) ObjectAlgorithm() RevisionAlgorithm {
	return e.objectAlgorithm
}

// ObjectDigest returns the full lowercase immediate object ID.
func (e GitTreeEntry) ObjectDigest() string {
	return e.objectDigest
}
