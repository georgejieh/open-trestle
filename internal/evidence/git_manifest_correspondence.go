package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"unicode/utf8"
)

const gitManifestPathEncoding = "utf8-exact-v1"

// GitManifestCorrespondence records exact Git leaf and repository manifest agreement.
type GitManifestCorrespondence struct {
	identity                   string
	gitTreeGraphIdentity       string
	repositoryManifestIdentity string
	gitCommitIdentity          string
	revisionIdentity           string
	fileCount                  int
	totalSizeBytes             int64
	pathEncoding               string
}

type gitManifestInputSnapshot struct {
	commitContent     []byte
	rootTreeContent   []byte
	childTreeContents map[string][]byte
	blobContents      map[string][]byte
}

// VerifyGitManifestCorrespondence verifies Git regular-file leaves against a manifest.
func VerifyGitManifestCorrespondence(revision RevisionIdentity, commitVerification GitCommitObjectVerification, commitContent []byte, commit GitCommit, rootTreeVerification GitTreeObjectVerification, rootTreeContent []byte, rootTree GitTree, childTreeContents map[string][]byte, blobContents map[string][]byte, graph GitTreeGraph, manifest RepositoryManifest) (GitManifestCorrespondence, error) {
	snapshot, err := snapshotGitManifestInputs(commitContent, rootTreeContent, childTreeContents, blobContents)
	if err != nil {
		return GitManifestCorrespondence{}, err
	}
	canonicalRevision, err := NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || revision != canonicalRevision {
		return GitManifestCorrespondence{}, fmt.Errorf("revision identity is not canonical")
	}
	canonicalGraph, err := VerifyGitTreeGraph(canonicalRevision, commitVerification, snapshot.commitContent, commit, rootTreeVerification, snapshot.rootTreeContent, rootTree, snapshot.childTreeContents, snapshot.blobContents)
	if err != nil || !gitTreeGraphValuesEqual(graph, canonicalGraph) {
		return GitManifestCorrespondence{}, fmt.Errorf("git tree graph does not match verified object content")
	}
	canonicalManifest, err := NewRepositoryManifest(manifest.Files())
	if err != nil || !repositoryManifestValuesEqual(manifest, canonicalManifest) {
		return GitManifestCorrespondence{}, fmt.Errorf("repository manifest is not canonical")
	}
	if len(canonicalGraph.entries) > maxGitTreeGraphEntries || canonicalManifest.FileCount() > maxRepositoryManifestFiles {
		return GitManifestCorrespondence{}, fmt.Errorf("git manifest correspondence exceeds file limits")
	}
	type rawBlobFact struct {
		digest    string
		sizeBytes int
	}
	derivedFiles := make(map[string]RepositoryFile, canonicalManifest.FileCount())
	rawBlobFacts := make(map[string]rawBlobFact, canonicalGraph.UniqueBlobObjectCount())
	var totalSizeBytes int64
	for _, entry := range canonicalGraph.entries {
		switch entry.mode {
		case GitTreeModeDirectory:
			if entry.kind != GitTreeEntryKindTree {
				return GitManifestCorrespondence{}, fmt.Errorf("directory graph entry has non-tree kind")
			}
			continue
		case GitTreeModeRegular, GitTreeModeExecutable:
			if entry.kind != GitTreeEntryKindBlob {
				return GitManifestCorrespondence{}, fmt.Errorf("file graph entry has non-blob kind")
			}
		case GitTreeModeSymlink:
			return GitManifestCorrespondence{}, fmt.Errorf("symlink graph entries cannot correspond to repository files")
		case GitTreeModeGitlink:
			return GitManifestCorrespondence{}, fmt.Errorf("gitlink graph entries are unsupported")
		default:
			return GitManifestCorrespondence{}, fmt.Errorf("unsupported graph entry mode %q", entry.mode)
		}
		path, err := gitGraphPathToRepositoryPath(entry.path)
		if err != nil {
			return GitManifestCorrespondence{}, fmt.Errorf("convert git graph path %x: %w", entry.path, err)
		}
		content, exists := snapshot.blobContents[entry.objectDigest]
		if !exists || len(content) != entry.contentSizeBytes {
			return GitManifestCorrespondence{}, fmt.Errorf("verified blob content for path %q is unavailable", path)
		}
		fact, cached := rawBlobFacts[entry.objectDigest]
		if !cached {
			rawDigest := sha256.Sum256(content)
			fact = rawBlobFact{digest: hex.EncodeToString(rawDigest[:]), sizeBytes: len(content)}
			rawBlobFacts[entry.objectDigest] = fact
		}
		identity, err := repositoryFileIdentity(path, fact.digest, fact.sizeBytes)
		if err != nil {
			return GitManifestCorrespondence{}, fmt.Errorf("construct repository file identity for path %q: %w", path, err)
		}
		file := RepositoryFile{identity: identity, path: path, digest: fact.digest, sizeBytes: fact.sizeBytes}
		file, err = canonicalRepositoryFile(file)
		if err != nil {
			return GitManifestCorrespondence{}, fmt.Errorf("canonicalize repository file for path %q: %w", path, err)
		}
		if _, duplicate := derivedFiles[path]; duplicate {
			return GitManifestCorrespondence{}, fmt.Errorf("duplicate derived repository path %q", path)
		}
		totalSizeBytes, err = checkedCorrespondenceSizeAdd(totalSizeBytes, int64(file.SizeBytes()))
		if err != nil {
			return GitManifestCorrespondence{}, err
		}
		derivedFiles[path] = file
	}
	if len(derivedFiles) != canonicalManifest.FileCount() || totalSizeBytes != canonicalManifest.TotalSizeBytes() {
		return GitManifestCorrespondence{}, fmt.Errorf("git file set does not match repository manifest")
	}
	for _, manifestFile := range canonicalManifest.files {
		derivedFile, exists := derivedFiles[manifestFile.Path()]
		if !exists || derivedFile != manifestFile {
			return GitManifestCorrespondence{}, fmt.Errorf("git file %q does not match repository manifest", manifestFile.Path())
		}
	}
	preimage := struct {
		Contract                   string        `json:"contract"`
		SchemaVersion              int           `json:"schema_version"`
		RevisionIdentity           string        `json:"revision_identity"`
		GitCommitIdentity          string        `json:"git_commit_identity"`
		GitTreeGraphIdentity       string        `json:"git_tree_graph_identity"`
		RepositoryManifestIdentity string        `json:"repository_manifest_identity"`
		PathEncoding               string        `json:"path_encoding"`
		IncludedModes              []GitTreeMode `json:"included_modes"`
		FileCount                  int           `json:"file_count"`
		TotalSizeBytes             int64         `json:"total_size_bytes"`
	}{
		Contract:                   "open-trestle/git-manifest-correspondence",
		SchemaVersion:              1,
		RevisionIdentity:           canonicalRevision.Identity(),
		GitCommitIdentity:          canonicalGraph.GitCommitIdentity(),
		GitTreeGraphIdentity:       canonicalGraph.Identity(),
		RepositoryManifestIdentity: canonicalManifest.Identity(),
		PathEncoding:               gitManifestPathEncoding,
		IncludedModes:              []GitTreeMode{GitTreeModeRegular, GitTreeModeExecutable},
		FileCount:                  len(derivedFiles),
		TotalSizeBytes:             totalSizeBytes,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitManifestCorrespondence{}, fmt.Errorf("encode git manifest correspondence identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitManifestCorrespondence{
		identity:                   hex.EncodeToString(identityDigest[:]),
		gitTreeGraphIdentity:       canonicalGraph.Identity(),
		repositoryManifestIdentity: canonicalManifest.Identity(),
		gitCommitIdentity:          canonicalGraph.GitCommitIdentity(),
		revisionIdentity:           canonicalRevision.Identity(),
		fileCount:                  len(derivedFiles),
		totalSizeBytes:             totalSizeBytes,
		pathEncoding:               gitManifestPathEncoding,
	}, nil
}

func snapshotGitManifestInputs(commitContent, rootTreeContent []byte, childTreeContents, blobContents map[string][]byte) (gitManifestInputSnapshot, error) {
	if len(commitContent) > maxGitCommitObjectBytes {
		return gitManifestInputSnapshot{}, fmt.Errorf("git commit object exceeds %d bytes", maxGitCommitObjectBytes)
	}
	if len(rootTreeContent) > maxGitTreeObjectBytes {
		return gitManifestInputSnapshot{}, fmt.Errorf("root git tree object exceeds %d bytes", maxGitTreeObjectBytes)
	}
	if len(childTreeContents) >= maxGitTreeGraphUniqueTrees || len(blobContents) > maxGitTreeGraphUniqueBlobs {
		return gitManifestInputSnapshot{}, fmt.Errorf("git manifest correspondence has too many unique objects")
	}
	totalObjectBytes := int64(len(rootTreeContent))
	for _, content := range childTreeContents {
		if len(content) > maxGitTreeObjectBytes {
			return gitManifestInputSnapshot{}, fmt.Errorf("child git tree object exceeds %d bytes", maxGitTreeObjectBytes)
		}
		next, err := checkedGraphAdd(totalObjectBytes, int64(len(content)), maxGitTreeGraphTotalObjectBytes)
		if err != nil {
			return gitManifestInputSnapshot{}, err
		}
		totalObjectBytes = next
	}
	for _, content := range blobContents {
		if len(content) > maxGitBlobObjectBytes {
			return gitManifestInputSnapshot{}, fmt.Errorf("git blob object exceeds %d bytes", maxGitBlobObjectBytes)
		}
		next, err := checkedGraphAdd(totalObjectBytes, int64(len(content)), maxGitTreeGraphTotalObjectBytes)
		if err != nil {
			return gitManifestInputSnapshot{}, err
		}
		totalObjectBytes = next
	}
	snapshot := gitManifestInputSnapshot{
		commitContent:     append([]byte{}, commitContent...),
		rootTreeContent:   append([]byte{}, rootTreeContent...),
		childTreeContents: make(map[string][]byte, len(childTreeContents)),
		blobContents:      make(map[string][]byte, len(blobContents)),
	}
	for digest, content := range childTreeContents {
		snapshot.childTreeContents[digest] = append([]byte{}, content...)
	}
	for digest, content := range blobContents {
		snapshot.blobContents[digest] = append([]byte{}, content...)
	}
	return snapshot, nil
}

func gitGraphPathToRepositoryPath(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", fmt.Errorf("git path must be valid UTF-8")
	}
	path := string(raw)
	if len(path) > maxRepositoryFilePathBytes {
		return "", fmt.Errorf("git path exceeds %d bytes", maxRepositoryFilePathBytes)
	}
	if err := validateSourcePath(path); err != nil {
		return "", err
	}
	if !bytes.Equal([]byte(path), raw) {
		return "", fmt.Errorf("git path bytes changed during UTF-8 conversion")
	}
	return path, nil
}

func gitTreeGraphValuesEqual(first, second GitTreeGraph) bool {
	if (first.entries == nil) != (second.entries == nil) || first.identity != second.identity || first.gitCommitIdentity != second.gitCommitIdentity || first.rootTreeIdentity != second.rootTreeIdentity || first.rootTreeVerificationIdentity != second.rootTreeVerificationIdentity || first.algorithm != second.algorithm || first.uniqueTreeObjectCount != second.uniqueTreeObjectCount || first.uniqueBlobObjectCount != second.uniqueBlobObjectCount || first.totalObjectBytes != second.totalObjectBytes || first.traversalDigest != second.traversalDigest || len(first.entries) != len(second.entries) {
		return false
	}
	for i := range first.entries {
		if !gitTreeGraphEntryValuesEqual(first.entries[i], second.entries[i]) {
			return false
		}
	}
	return true
}

func gitTreeGraphEntryValuesEqual(first, second GitTreeGraphEntry) bool {
	return (first.path == nil) == (second.path == nil) && bytes.Equal(first.path, second.path) && first.mode == second.mode && first.kind == second.kind && first.objectDigest == second.objectDigest && first.contentSizeBytes == second.contentSizeBytes
}

func checkedCorrespondenceSizeAdd(current, added int64) (int64, error) {
	if current < 0 || added < 0 || added > math.MaxInt64-current {
		return current, fmt.Errorf("git manifest correspondence total size overflows int64")
	}
	return current + added, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (c GitManifestCorrespondence) Identity() string {
	return c.identity
}

// GitTreeGraphIdentity returns the exact verified graph identity.
func (c GitManifestCorrespondence) GitTreeGraphIdentity() string {
	return c.gitTreeGraphIdentity
}

// RepositoryManifestIdentity returns the exact canonical manifest identity.
func (c GitManifestCorrespondence) RepositoryManifestIdentity() string {
	return c.repositoryManifestIdentity
}

// GitCommitIdentity returns the exact parsed Git commit identity.
func (c GitManifestCorrespondence) GitCommitIdentity() string {
	return c.gitCommitIdentity
}

// RevisionIdentity returns the exact revision identity.
func (c GitManifestCorrespondence) RevisionIdentity() string {
	return c.revisionIdentity
}

// FileCount returns the number of corresponding regular and executable files.
func (c GitManifestCorrespondence) FileCount() int {
	return c.fileCount
}

// TotalSizeBytes returns the checked sum of corresponding raw file bytes.
func (c GitManifestCorrespondence) TotalSizeBytes() int64 {
	return c.totalSizeBytes
}

// PathEncoding returns the exact Git-to-manifest path conversion contract.
func (c GitManifestCorrespondence) PathEncoding() string {
	return c.pathEncoding
}
