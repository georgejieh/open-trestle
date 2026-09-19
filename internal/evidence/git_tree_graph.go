package evidence

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

const (
	maxGitTreeGraphDepth            = 128
	maxGitTreeGraphEntries          = 65_536
	maxGitTreeGraphUniqueTrees      = 65_536
	maxGitTreeGraphUniqueBlobs      = 65_536
	maxGitTreeGraphPathBytes        = 4 << 10
	maxGitTreeGraphTotalPathBytes   = 64 << 20
	maxGitTreeGraphTotalObjectBytes = 256 << 20
)

// GitTreeGraph records a recursively closed supplied Git tree and blob graph.
type GitTreeGraph struct {
	identity                     string
	gitCommitIdentity            string
	rootTreeIdentity             string
	rootTreeVerificationIdentity string
	algorithm                    RevisionAlgorithm
	entries                      []GitTreeGraphEntry
	uniqueTreeObjectCount        int
	uniqueBlobObjectCount        int
	totalObjectBytes             int64
	traversalDigest              string
}

// GitTreeGraphEntry records one expanded raw path and its verified object reference.
type GitTreeGraphEntry struct {
	path             []byte
	mode             GitTreeMode
	kind             GitTreeEntryKind
	objectDigest     string
	contentSizeBytes int
}

type verifiedGraphTree struct {
	digest      string
	contentSize int
	entries     []verifiedGraphEntry
}

type verifiedGraphBlob struct {
	digest      string
	contentSize int
}

type verifiedGraphEntry struct {
	name         []byte
	mode         GitTreeMode
	kind         GitTreeEntryKind
	objectDigest string
}

type verifiedGraphObjects struct {
	algorithm RevisionAlgorithm
	rootTree  string
	trees     map[string]verifiedGraphTree
	blobs     map[string]verifiedGraphBlob
}

type gitTreeGraphLimits struct {
	maxDepth            int
	maxEntries          int
	maxUniqueTrees      int
	maxUniqueBlobs      int
	maxPathBytes        int
	maxTotalPathBytes   int64
	maxTotalObjectBytes int64
}

type gitTreeGraphBudget struct {
	entries          int
	uniqueTrees      int
	uniqueBlobs      int
	totalPathBytes   int64
	totalObjectBytes int64
}

type gitTreeGraphStats struct {
	entryCount       int
	uniqueTrees      int
	uniqueBlobs      int
	totalObjectBytes int64
}

func standardGitTreeGraphLimits() gitTreeGraphLimits {
	return gitTreeGraphLimits{
		maxDepth:            maxGitTreeGraphDepth,
		maxEntries:          maxGitTreeGraphEntries,
		maxUniqueTrees:      maxGitTreeGraphUniqueTrees,
		maxUniqueBlobs:      maxGitTreeGraphUniqueBlobs,
		maxPathBytes:        maxGitTreeGraphPathBytes,
		maxTotalPathBytes:   maxGitTreeGraphTotalPathBytes,
		maxTotalObjectBytes: maxGitTreeGraphTotalObjectBytes,
	}
}

// VerifyGitTreeGraph verifies complete supplied child-tree and blob object closure.
func VerifyGitTreeGraph(revision RevisionIdentity, commitVerification GitCommitObjectVerification, commitContent []byte, commit GitCommit, rootTreeVerification GitTreeObjectVerification, rootTreeContent []byte, rootTree GitTree, childTreeContents map[string][]byte, blobContents map[string][]byte) (GitTreeGraph, error) {
	canonicalRoot, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, rootTreeVerification, rootTreeContent)
	if err != nil || !gitTreeValuesEqual(rootTree, canonicalRoot) {
		return GitTreeGraph{}, fmt.Errorf("root git tree does not match verified content")
	}
	algorithm := canonicalRoot.TreeAlgorithm()
	if len(childTreeContents) >= maxGitTreeGraphUniqueTrees || len(blobContents) > maxGitTreeGraphUniqueBlobs {
		return GitTreeGraph{}, fmt.Errorf("git tree graph has too many unique objects")
	}
	budget := gitTreeGraphBudget{}
	if err := budget.addObjectBytes(int64(len(rootTreeContent)), maxGitTreeGraphTotalObjectBytes); err != nil {
		return GitTreeGraph{}, err
	}
	for digest, content := range childTreeContents {
		if len(content) > maxGitTreeObjectBytes {
			return GitTreeGraph{}, fmt.Errorf("child git tree object %q exceeds %d bytes", digest, maxGitTreeObjectBytes)
		}
		if err := budget.addObjectBytes(int64(len(content)), maxGitTreeGraphTotalObjectBytes); err != nil {
			return GitTreeGraph{}, err
		}
	}
	for digest, content := range blobContents {
		if len(content) > maxGitBlobObjectBytes {
			return GitTreeGraph{}, fmt.Errorf("git blob object %q exceeds %d bytes", digest, maxGitBlobObjectBytes)
		}
		if err := budget.addObjectBytes(int64(len(content)), maxGitTreeGraphTotalObjectBytes); err != nil {
			return GitTreeGraph{}, err
		}
	}
	objects := verifiedGraphObjects{
		algorithm: algorithm,
		rootTree:  canonicalRoot.TreeDigest(),
		trees:     make(map[string]verifiedGraphTree, len(childTreeContents)+1),
		blobs:     make(map[string]verifiedGraphBlob, len(blobContents)),
	}
	objects.trees[canonicalRoot.TreeDigest()] = verifiedGraphTree{
		digest:      canonicalRoot.TreeDigest(),
		contentSize: len(rootTreeContent),
		entries:     graphEntriesFromGitTree(canonicalRoot.entries),
	}
	for digest, content := range childTreeContents {
		if err := validateGraphObjectDigest(digest, algorithm); err != nil {
			return GitTreeGraph{}, fmt.Errorf("invalid child tree key: %w", err)
		}
		if digest == canonicalRoot.TreeDigest() {
			return GitTreeGraph{}, fmt.Errorf("child tree map contains root tree object")
		}
		if _, exists := blobContents[digest]; exists {
			return GitTreeGraph{}, fmt.Errorf("object %q is supplied as both tree and blob", digest)
		}
		computed, err := hashGitGraphObject("tree", content, algorithm)
		if err != nil || !equalGraphDigests(computed, digest) {
			return GitTreeGraph{}, fmt.Errorf("child git tree object %q does not match supplied bytes", digest)
		}
		entries, err := parseGitTreeEntries(content, algorithm)
		if err != nil {
			return GitTreeGraph{}, fmt.Errorf("parse child git tree object %q: %w", digest, err)
		}
		objects.trees[digest] = verifiedGraphTree{digest: digest, contentSize: len(content), entries: graphEntriesFromGitTree(entries)}
	}
	for digest, content := range blobContents {
		if err := validateGraphObjectDigest(digest, algorithm); err != nil {
			return GitTreeGraph{}, fmt.Errorf("invalid blob key: %w", err)
		}
		if digest == canonicalRoot.TreeDigest() {
			return GitTreeGraph{}, fmt.Errorf("root tree object %q is also supplied as a blob", digest)
		}
		computed, err := hashGitGraphObject("blob", content, algorithm)
		if err != nil || !equalGraphDigests(computed, digest) {
			return GitTreeGraph{}, fmt.Errorf("git blob object %q does not match supplied bytes", digest)
		}
		objects.blobs[digest] = verifiedGraphBlob{digest: digest, contentSize: len(content)}
	}
	entries, stats, traversalDigest, err := traverseVerifiedGitGraph(objects, standardGitTreeGraphLimits())
	if err != nil {
		return GitTreeGraph{}, err
	}
	preimage := struct {
		Contract                     string            `json:"contract"`
		SchemaVersion                int               `json:"schema_version"`
		GitCommitIdentity            string            `json:"git_commit_identity"`
		RootTreeIdentity             string            `json:"root_tree_identity"`
		RootTreeVerificationIdentity string            `json:"root_tree_verification_identity"`
		Algorithm                    RevisionAlgorithm `json:"algorithm"`
		EntryCount                   int               `json:"entry_count"`
		UniqueTreeObjectCount        int               `json:"unique_tree_object_count"`
		UniqueBlobObjectCount        int               `json:"unique_blob_object_count"`
		TotalObjectBytes             int64             `json:"total_object_bytes"`
		TraversalDigest              string            `json:"traversal_digest"`
	}{
		Contract:                     "open-trestle/git-tree-graph",
		SchemaVersion:                1,
		GitCommitIdentity:            canonicalRoot.GitCommitIdentity(),
		RootTreeIdentity:             canonicalRoot.Identity(),
		RootTreeVerificationIdentity: canonicalRoot.TreeVerificationIdentity(),
		Algorithm:                    algorithm,
		EntryCount:                   stats.entryCount,
		UniqueTreeObjectCount:        stats.uniqueTrees,
		UniqueBlobObjectCount:        stats.uniqueBlobs,
		TotalObjectBytes:             stats.totalObjectBytes,
		TraversalDigest:              traversalDigest,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitTreeGraph{}, fmt.Errorf("encode git tree graph identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitTreeGraph{
		identity:                     hex.EncodeToString(identityDigest[:]),
		gitCommitIdentity:            canonicalRoot.GitCommitIdentity(),
		rootTreeIdentity:             canonicalRoot.Identity(),
		rootTreeVerificationIdentity: canonicalRoot.TreeVerificationIdentity(),
		algorithm:                    algorithm,
		entries:                      cloneGitTreeGraphEntries(entries),
		uniqueTreeObjectCount:        stats.uniqueTrees,
		uniqueBlobObjectCount:        stats.uniqueBlobs,
		totalObjectBytes:             stats.totalObjectBytes,
		traversalDigest:              traversalDigest,
	}, nil
}

func graphEntriesFromGitTree(entries []GitTreeEntry) []verifiedGraphEntry {
	result := make([]verifiedGraphEntry, len(entries))
	for i, entry := range entries {
		result[i] = verifiedGraphEntry{name: append([]byte{}, entry.name...), mode: entry.mode, kind: entry.kind, objectDigest: entry.objectDigest}
	}
	return result
}

func traverseVerifiedGitGraph(objects verifiedGraphObjects, limits gitTreeGraphLimits) ([]GitTreeGraphEntry, gitTreeGraphStats, string, error) {
	if err := validateGitTreeGraphLimits(limits); err != nil {
		return nil, gitTreeGraphStats{}, "", err
	}
	if err := validateGraphObjectDigest(objects.rootTree, objects.algorithm); err != nil {
		return nil, gitTreeGraphStats{}, "", fmt.Errorf("invalid root tree digest: %w", err)
	}
	if len(objects.trees) > limits.maxUniqueTrees || len(objects.blobs) > limits.maxUniqueBlobs {
		return nil, gitTreeGraphStats{}, "", fmt.Errorf("git tree graph exceeds unique object limits")
	}
	root, exists := objects.trees[objects.rootTree]
	if !exists || root.digest != objects.rootTree {
		return nil, gitTreeGraphStats{}, "", fmt.Errorf("root tree record is missing or inconsistent")
	}
	for digest, tree := range objects.trees {
		if err := validateGraphObjectDigest(digest, objects.algorithm); err != nil || tree.digest != digest || tree.contentSize < 0 {
			return nil, gitTreeGraphStats{}, "", fmt.Errorf("tree record %q is inconsistent", digest)
		}
		if _, collision := objects.blobs[digest]; collision {
			return nil, gitTreeGraphStats{}, "", fmt.Errorf("object %q has ambiguous tree and blob kinds", digest)
		}
	}
	for digest, blob := range objects.blobs {
		if err := validateGraphObjectDigest(digest, objects.algorithm); err != nil || blob.digest != digest || blob.contentSize < 0 {
			return nil, gitTreeGraphStats{}, "", fmt.Errorf("blob record %q is inconsistent", digest)
		}
	}
	entries := make([]GitTreeGraphEntry, 0)
	traversalHash := sha256.New()
	budget := gitTreeGraphBudget{}
	seenTrees := make(map[string]struct{})
	seenBlobs := make(map[string]struct{})
	activeTrees := make(map[string]struct{})
	seenPaths := make(map[string]struct{})
	var walkTree func(string, []byte, int) error
	walkTree = func(digest string, prefix []byte, depth int) error {
		if _, active := activeTrees[digest]; active {
			return fmt.Errorf("git tree graph contains an active tree cycle at %q", digest)
		}
		tree, exists := objects.trees[digest]
		if !exists || tree.digest != digest {
			return fmt.Errorf("referenced tree object %q is missing", digest)
		}
		if _, seen := seenTrees[digest]; !seen {
			if budget.uniqueTrees >= limits.maxUniqueTrees {
				return fmt.Errorf("git tree graph exceeds %d unique trees", limits.maxUniqueTrees)
			}
			budget.uniqueTrees++
			if err := budget.addObjectBytes(int64(tree.contentSize), limits.maxTotalObjectBytes); err != nil {
				return err
			}
			seenTrees[digest] = struct{}{}
		}
		activeTrees[digest] = struct{}{}
		defer delete(activeTrees, digest)
		for _, entry := range tree.entries {
			entryDepth := depth + 1
			if entryDepth > limits.maxDepth {
				return fmt.Errorf("git tree graph exceeds depth %d", limits.maxDepth)
			}
			if err := validateGitTreeName(entry.name); err != nil {
				return err
			}
			path := append([]byte{}, prefix...)
			if len(path) > 0 {
				path = append(path, '/')
			}
			path = append(path, entry.name...)
			if len(path) > limits.maxPathBytes {
				return fmt.Errorf("git tree graph path has %d bytes, want at most %d", len(path), limits.maxPathBytes)
			}
			if _, duplicate := seenPaths[string(path)]; duplicate {
				return fmt.Errorf("git tree graph contains duplicate expanded path %x", path)
			}
			if budget.entries >= limits.maxEntries {
				return fmt.Errorf("git tree graph exceeds %d entries", limits.maxEntries)
			}
			if err := budget.addPathBytes(int64(len(path)), limits.maxTotalPathBytes); err != nil {
				return err
			}
			if err := validateGraphObjectDigest(entry.objectDigest, objects.algorithm); err != nil {
				return fmt.Errorf("entry at %x has invalid object digest: %w", path, err)
			}
			contentSize := 0
			switch entry.mode {
			case GitTreeModeDirectory:
				if entry.kind != GitTreeEntryKindTree {
					return fmt.Errorf("directory at %x has non-tree kind", path)
				}
				child, exists := objects.trees[entry.objectDigest]
				if !exists {
					return fmt.Errorf("referenced tree object %q is missing", entry.objectDigest)
				}
				contentSize = child.contentSize
			case GitTreeModeRegular, GitTreeModeExecutable, GitTreeModeSymlink:
				if entry.kind != GitTreeEntryKindBlob {
					return fmt.Errorf("blob mode at %x has non-blob kind", path)
				}
				blob, exists := objects.blobs[entry.objectDigest]
				if !exists {
					return fmt.Errorf("referenced blob object %q is missing", entry.objectDigest)
				}
				contentSize = blob.contentSize
			case GitTreeModeGitlink:
				return fmt.Errorf("gitlink at %x is unsupported", path)
			default:
				return fmt.Errorf("entry at %x has unsupported mode %q", path, entry.mode)
			}
			graphEntry := GitTreeGraphEntry{path: append([]byte{}, path...), mode: entry.mode, kind: entry.kind, objectDigest: entry.objectDigest, contentSizeBytes: contentSize}
			if err := writeGitTreeTraversalEntry(traversalHash, graphEntry, objects.algorithm); err != nil {
				return err
			}
			seenPaths[string(path)] = struct{}{}
			entries = append(entries, graphEntry)
			budget.entries++
			if entry.kind == GitTreeEntryKindBlob {
				if _, seen := seenBlobs[entry.objectDigest]; !seen {
					if budget.uniqueBlobs >= limits.maxUniqueBlobs {
						return fmt.Errorf("git tree graph exceeds %d unique blobs", limits.maxUniqueBlobs)
					}
					blob := objects.blobs[entry.objectDigest]
					if err := budget.addObjectBytes(int64(blob.contentSize), limits.maxTotalObjectBytes); err != nil {
						return err
					}
					budget.uniqueBlobs++
					seenBlobs[entry.objectDigest] = struct{}{}
				}
			} else if err := walkTree(entry.objectDigest, path, entryDepth); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walkTree(objects.rootTree, nil, 0); err != nil {
		return nil, gitTreeGraphStats{}, "", err
	}
	if len(seenTrees) != len(objects.trees) || len(seenBlobs) != len(objects.blobs) {
		return nil, gitTreeGraphStats{}, "", fmt.Errorf("git tree graph contains unreachable supplied objects")
	}
	return entries, gitTreeGraphStats{entryCount: budget.entries, uniqueTrees: budget.uniqueTrees, uniqueBlobs: budget.uniqueBlobs, totalObjectBytes: budget.totalObjectBytes}, hex.EncodeToString(traversalHash.Sum(nil)), nil
}

func validateGitTreeGraphLimits(limits gitTreeGraphLimits) error {
	if limits.maxDepth < 0 || limits.maxEntries < 0 || limits.maxUniqueTrees < 1 || limits.maxUniqueBlobs < 0 || limits.maxPathBytes < 0 || limits.maxTotalPathBytes < 0 || limits.maxTotalObjectBytes < 0 {
		return fmt.Errorf("git tree graph limits must be nonnegative and allow a root tree")
	}
	return nil
}

func checkedGraphAdd(current, added, limit int64) (int64, error) {
	if current < 0 || added < 0 || limit < 0 || current > limit || added > limit-current {
		return current, fmt.Errorf("git tree graph byte budget exceeds %d", limit)
	}
	return current + added, nil
}

func (b *gitTreeGraphBudget) addObjectBytes(size, limit int64) error {
	next, err := checkedGraphAdd(b.totalObjectBytes, size, limit)
	if err != nil {
		return err
	}
	b.totalObjectBytes = next
	return nil
}

func (b *gitTreeGraphBudget) addPathBytes(size, limit int64) error {
	next, err := checkedGraphAdd(b.totalPathBytes, size, limit)
	if err != nil {
		return err
	}
	b.totalPathBytes = next
	return nil
}

func validateGraphObjectDigest(digest string, algorithm RevisionAlgorithm) error {
	expected := sha1HexLength
	if algorithm == RevisionAlgorithmSHA256 {
		expected = sha256HexLength
	} else if algorithm != RevisionAlgorithmSHA1 {
		return fmt.Errorf("unsupported graph algorithm %q", algorithm)
	}
	if len(digest) != expected || strings.ToLower(digest) != digest {
		return fmt.Errorf("digest %q is not canonical %s", digest, algorithm)
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded)*2 != expected {
		return fmt.Errorf("digest %q is not canonical %s", digest, algorithm)
	}
	return nil
}

func equalGraphDigests(first, second string) bool {
	return len(first) == len(second) && subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}

func hashGitGraphObject(objectType string, content []byte, algorithm RevisionAlgorithm) (string, error) {
	var objectHash hash.Hash
	switch algorithm {
	case RevisionAlgorithmSHA1:
		objectHash = sha1.New()
	case RevisionAlgorithmSHA256:
		objectHash = sha256.New()
	default:
		return "", fmt.Errorf("unsupported graph algorithm %q", algorithm)
	}
	for _, part := range [][]byte{[]byte(objectType + " "), []byte(strconv.Itoa(len(content))), {0}, content} {
		written, err := objectHash.Write(part)
		if err != nil || written != len(part) {
			return "", fmt.Errorf("hash git %s object framing", objectType)
		}
	}
	return hex.EncodeToString(objectHash.Sum(nil)), nil
}

func writeGitTreeTraversalEntry(destination hash.Hash, entry GitTreeGraphEntry, algorithm RevisionAlgorithm) error {
	objectID, err := hex.DecodeString(entry.objectDigest)
	if err != nil {
		return fmt.Errorf("decode traversal object ID: %w", err)
	}
	expectedIDBytes := sha1HexLength / 2
	switch algorithm {
	case RevisionAlgorithmSHA1:
	case RevisionAlgorithmSHA256:
		expectedIDBytes = sha256.Size
	default:
		return fmt.Errorf("unsupported traversal algorithm %q", algorithm)
	}
	if len(objectID) != expectedIDBytes || uint64(len(entry.path)) > uint64(^uint32(0)) || len(entry.mode) > int(^uint8(0)) || entry.contentSizeBytes < 0 {
		return fmt.Errorf("invalid git tree traversal entry")
	}
	var pathLength [4]byte
	binary.BigEndian.PutUint32(pathLength[:], uint32(len(entry.path)))
	var contentSize [8]byte
	binary.BigEndian.PutUint64(contentSize[:], uint64(entry.contentSizeBytes))
	kindCode := byte(0)
	switch entry.kind {
	case GitTreeEntryKindBlob:
		kindCode = 1
	case GitTreeEntryKindTree:
		kindCode = 2
	default:
		return fmt.Errorf("unsupported traversal entry kind %q", entry.kind)
	}
	for _, part := range [][]byte{pathLength[:], entry.path, {byte(len(entry.mode))}, []byte(entry.mode), {kindCode}, objectID, contentSize[:]} {
		written, err := destination.Write(part)
		if err != nil || written != len(part) {
			return fmt.Errorf("hash git tree traversal entry")
		}
	}
	return nil
}

func cloneGitTreeGraphEntries(entries []GitTreeGraphEntry) []GitTreeGraphEntry {
	if entries == nil {
		return nil
	}
	result := make([]GitTreeGraphEntry, len(entries))
	for i, entry := range entries {
		result[i] = entry
		result[i].path = append([]byte{}, entry.path...)
	}
	return result
}

// Identity returns the versioned canonical SHA-256 identity.
func (g GitTreeGraph) Identity() string { return g.identity }

// GitCommitIdentity returns the exact parsed commit identity.
func (g GitTreeGraph) GitCommitIdentity() string { return g.gitCommitIdentity }

// RootTreeIdentity returns the exact parsed root tree identity.
func (g GitTreeGraph) RootTreeIdentity() string { return g.rootTreeIdentity }

// RootTreeVerificationIdentity returns the exact root tree verification identity.
func (g GitTreeGraph) RootTreeVerificationIdentity() string { return g.rootTreeVerificationIdentity }

// Algorithm returns the graph object digest algorithm.
func (g GitTreeGraph) Algorithm() RevisionAlgorithm { return g.algorithm }

// Entries returns defensive copies in canonical depth-first pre-order.
func (g GitTreeGraph) Entries() []GitTreeGraphEntry { return cloneGitTreeGraphEntries(g.entries) }

// EntryCount returns the expanded entry count.
func (g GitTreeGraph) EntryCount() int { return len(g.entries) }

// UniqueTreeObjectCount returns the number of unique verified trees including the root.
func (g GitTreeGraph) UniqueTreeObjectCount() int { return g.uniqueTreeObjectCount }

// UniqueBlobObjectCount returns the number of unique verified blobs.
func (g GitTreeGraph) UniqueBlobObjectCount() int { return g.uniqueBlobObjectCount }

// TotalObjectBytes returns unique root-tree, child-tree, and blob payload bytes.
func (g GitTreeGraph) TotalObjectBytes() int64 { return g.totalObjectBytes }

// TraversalDigest returns the canonical expanded traversal digest.
func (g GitTreeGraph) TraversalDigest() string { return g.traversalDigest }

// Path returns a defensive copy of the raw root-relative path.
func (e GitTreeGraphEntry) Path() []byte {
	if e.path == nil {
		return nil
	}
	return append([]byte{}, e.path...)
}

// PathHex returns lowercase hexadecimal raw path bytes.
func (e GitTreeGraphEntry) PathHex() string { return hex.EncodeToString(e.path) }

// Mode returns the exact canonical Git mode.
func (e GitTreeGraphEntry) Mode() GitTreeMode { return e.mode }

// Kind returns the object kind implied by the mode.
func (e GitTreeGraphEntry) Kind() GitTreeEntryKind { return e.kind }

// ObjectDigest returns the full lowercase verified object ID.
func (e GitTreeGraphEntry) ObjectDigest() string { return e.objectDigest }

// ContentSizeBytes returns the unframed verified object payload size.
func (e GitTreeGraphEntry) ContentSizeBytes() int { return e.contentSizeBytes }
