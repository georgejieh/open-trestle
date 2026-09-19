package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// FileExtensionFact records exact path-extension inventory totals.
type FileExtensionFact struct {
	extension      string
	fileCount      int
	totalSizeBytes int64
}

// RepositoryProfile records deterministic inventory facts for one manifest.
type RepositoryProfile struct {
	identity         string
	manifestIdentity string
	fileCount        int
	totalSizeBytes   int64
	extensionFacts   []FileExtensionFact
}

// NewRepositoryProfile derives exact inventory facts from a canonical manifest.
func NewRepositoryProfile(manifest evidence.RepositoryManifest) (RepositoryProfile, error) {
	files := manifest.Files()
	canonicalManifest, err := evidence.NewRepositoryManifest(files)
	if err != nil || canonicalManifest.Identity() != manifest.Identity() {
		return RepositoryProfile{}, fmt.Errorf("repository manifest is not canonical")
	}
	factsByExtension := make(map[string]FileExtensionFact)
	maxInt := int(^uint(0) >> 1)
	var derivedFileCount int
	var derivedTotalSize int64
	for _, file := range canonicalManifest.Files() {
		extension := path.Ext(file.Path())
		fact := factsByExtension[extension]
		if fact.fileCount == maxInt || derivedFileCount == maxInt {
			return RepositoryProfile{}, fmt.Errorf("repository profile file count overflows int")
		}
		sizeBytes := int64(file.SizeBytes())
		if sizeBytes > math.MaxInt64-fact.totalSizeBytes || sizeBytes > math.MaxInt64-derivedTotalSize {
			return RepositoryProfile{}, fmt.Errorf("repository profile total size overflows int64")
		}
		fact.extension = extension
		fact.fileCount++
		fact.totalSizeBytes += sizeBytes
		factsByExtension[extension] = fact
		derivedFileCount++
		derivedTotalSize += sizeBytes
	}
	if derivedFileCount != canonicalManifest.FileCount() || derivedTotalSize != canonicalManifest.TotalSizeBytes() {
		return RepositoryProfile{}, fmt.Errorf("repository profile totals do not match manifest")
	}
	extensions := make([]string, 0, len(factsByExtension))
	for extension := range factsByExtension {
		extensions = append(extensions, extension)
	}
	sort.Strings(extensions)
	extensionFacts := make([]FileExtensionFact, len(extensions))
	wireExtensions := make([]fileExtensionFactWire, len(extensions))
	for i, extension := range extensions {
		fact := factsByExtension[extension]
		extensionFacts[i] = fact
		wireExtensions[i] = fileExtensionFactWire{
			Extension:      fact.extension,
			FileCount:      fact.fileCount,
			TotalSizeBytes: fact.totalSizeBytes,
		}
	}
	preimage := struct {
		Contract         string                  `json:"contract"`
		SchemaVersion    int                     `json:"schema_version"`
		ManifestIdentity string                  `json:"manifest_identity"`
		FileCount        int                     `json:"file_count"`
		TotalSizeBytes   int64                   `json:"total_size_bytes"`
		Extensions       []fileExtensionFactWire `json:"extensions"`
	}{
		Contract:         "open-trestle/repository-profile",
		SchemaVersion:    1,
		ManifestIdentity: canonicalManifest.Identity(),
		FileCount:        derivedFileCount,
		TotalSizeBytes:   derivedTotalSize,
		Extensions:       wireExtensions,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryProfile{}, fmt.Errorf("encode repository profile identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryProfile{
		identity:         hex.EncodeToString(digest[:]),
		manifestIdentity: canonicalManifest.Identity(),
		fileCount:        derivedFileCount,
		totalSizeBytes:   derivedTotalSize,
		extensionFacts:   extensionFacts,
	}, nil
}

type fileExtensionFactWire struct {
	Extension      string `json:"extension"`
	FileCount      int    `json:"file_count"`
	TotalSizeBytes int64  `json:"total_size_bytes"`
}

// Identity returns the versioned canonical SHA-256 identity.
func (p RepositoryProfile) Identity() string {
	return p.identity
}

// ManifestIdentity returns the exact source manifest identity.
func (p RepositoryProfile) ManifestIdentity() string {
	return p.manifestIdentity
}

// FileCount returns the exact manifest file count.
func (p RepositoryProfile) FileCount() int {
	return p.fileCount
}

// TotalSizeBytes returns the exact manifest byte total.
func (p RepositoryProfile) TotalSizeBytes() int64 {
	return p.totalSizeBytes
}

// ExtensionFacts returns facts in exact lexical extension order.
func (p RepositoryProfile) ExtensionFacts() []FileExtensionFact {
	result := make([]FileExtensionFact, len(p.extensionFacts))
	copy(result, p.extensionFacts)
	return result
}

// Extension returns the fact for one exact extension.
func (p RepositoryProfile) Extension(extension string) (FileExtensionFact, bool) {
	index := sort.Search(len(p.extensionFacts), func(i int) bool {
		return p.extensionFacts[i].extension >= extension
	})
	if index == len(p.extensionFacts) || p.extensionFacts[index].extension != extension {
		return FileExtensionFact{}, false
	}
	return p.extensionFacts[index], true
}

// Extension returns the exact path extension.
func (f FileExtensionFact) Extension() string {
	return f.extension
}

// FileCount returns the number of files in the extension bucket.
func (f FileExtensionFact) FileCount() int {
	return f.fileCount
}

// TotalSizeBytes returns the extension bucket's byte total.
func (f FileExtensionFact) TotalSizeBytes() int64 {
	return f.totalSizeBytes
}
