package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// Bounds sorting and identity construction while allowing large repositories.
const maxRepositoryManifestFiles = 1 << 16

// RepositoryManifest is a canonical set of supplied repository-file facts.
type RepositoryManifest struct {
	identity       string
	files          []RepositoryFile
	totalSizeBytes int64
}

// NewRepositoryManifest creates an immutable canonical file manifest.
func NewRepositoryManifest(files []RepositoryFile) (RepositoryManifest, error) {
	if len(files) > maxRepositoryManifestFiles {
		return RepositoryManifest{}, fmt.Errorf("repository manifest exceeds %d files", maxRepositoryManifestFiles)
	}
	canonicalFiles := make([]RepositoryFile, len(files))
	seenIdentities := make(map[string]struct{}, len(files))
	seenPaths := make(map[string]struct{}, len(files))
	var totalSizeBytes int64
	for i, file := range files {
		canonical, err := canonicalRepositoryFile(file)
		if err != nil {
			return RepositoryManifest{}, fmt.Errorf("repository file %d: %w", i, err)
		}
		if _, exists := seenIdentities[canonical.Identity()]; exists {
			return RepositoryManifest{}, fmt.Errorf("duplicate repository file identity at index %d", i)
		}
		if _, exists := seenPaths[canonical.Path()]; exists {
			return RepositoryManifest{}, fmt.Errorf("duplicate repository file path %q", canonical.Path())
		}
		sizeBytes := int64(canonical.SizeBytes())
		if sizeBytes > math.MaxInt64-totalSizeBytes {
			return RepositoryManifest{}, fmt.Errorf("repository manifest total size overflows int64")
		}
		totalSizeBytes += sizeBytes
		seenIdentities[canonical.Identity()] = struct{}{}
		seenPaths[canonical.Path()] = struct{}{}
		canonicalFiles[i] = canonical
	}
	sort.Slice(canonicalFiles, func(i, j int) bool {
		return canonicalFiles[i].Path() < canonicalFiles[j].Path()
	})
	wireFiles := make([]repositoryManifestFileWire, len(canonicalFiles))
	for i, file := range canonicalFiles {
		wireFiles[i] = repositoryManifestFileWire{Path: file.Path(), RepositoryFileIdentity: file.Identity()}
	}
	preimage := struct {
		Contract      string                       `json:"contract"`
		SchemaVersion int                          `json:"schema_version"`
		Files         []repositoryManifestFileWire `json:"files"`
	}{
		Contract:      "open-trestle/repository-manifest",
		SchemaVersion: 1,
		Files:         wireFiles,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryManifest{}, fmt.Errorf("encode repository manifest identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryManifest{
		identity:       hex.EncodeToString(digest[:]),
		files:          canonicalFiles,
		totalSizeBytes: totalSizeBytes,
	}, nil
}

type repositoryManifestFileWire struct {
	Path                   string `json:"path"`
	RepositoryFileIdentity string `json:"repository_file_identity"`
}

// Identity returns the versioned canonical SHA-256 identity.
func (m RepositoryManifest) Identity() string {
	return m.identity
}

// Files returns repository-file facts in canonical path order.
func (m RepositoryManifest) Files() []RepositoryFile {
	result := make([]RepositoryFile, len(m.files))
	copy(result, m.files)
	return result
}

// File returns one exact repository-file fact.
func (m RepositoryManifest) File(path string) (RepositoryFile, bool) {
	index := sort.Search(len(m.files), func(i int) bool {
		return m.files[i].Path() >= path
	})
	if index == len(m.files) || m.files[index].Path() != path {
		return RepositoryFile{}, false
	}
	return m.files[index], true
}

// FileCount returns the number of supplied file facts.
func (m RepositoryManifest) FileCount() int {
	return len(m.files)
}

// TotalSizeBytes returns the checked sum of file byte sizes.
func (m RepositoryManifest) TotalSizeBytes() int64 {
	return m.totalSizeBytes
}
