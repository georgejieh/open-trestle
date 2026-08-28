package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	fileClassificationName    = "exact-path-and-nul-signals"
	fileClassificationVersion = "1"
)

// FileContentSignal identifies exact NUL-byte presence.
type FileContentSignal string

const (
	// FileContentNULFree indicates that no supplied content byte is zero.
	FileContentNULFree FileContentSignal = "nul_free"
	// FileContentContainsNUL indicates that at least one content byte is zero.
	FileContentContainsNUL FileContentSignal = "contains_nul"
)

// FileClassificationReceipt records exact manifest-bound path and byte signals.
type FileClassificationReceipt struct {
	identity               string
	manifestIdentity       string
	repositoryFileIdentity string
	path                   string
	extension              string
	contentSignal          FileContentSignal
	vendorPath             bool
	goTestPath             bool
	classifierVersion      string
}

// ClassifyRepositoryFile derives exact path and NUL signals for one manifest file.
func ClassifyRepositoryFile(manifest evidence.RepositoryManifest, filePath string, content []byte) (FileClassificationReceipt, error) {
	canonicalManifest, err := evidence.NewRepositoryManifest(manifest.Files())
	if err != nil || canonicalManifest.Identity() != manifest.Identity() {
		return FileClassificationReceipt{}, fmt.Errorf("repository manifest is not canonical")
	}
	manifestFile, ok := canonicalManifest.File(filePath)
	if !ok {
		return FileClassificationReceipt{}, fmt.Errorf("repository manifest does not contain path %q", filePath)
	}
	exactFile, err := evidence.NewRepositoryFile(filePath, content)
	if err != nil {
		return FileClassificationReceipt{}, fmt.Errorf("validate repository file: %w", err)
	}
	if exactFile.Identity() != manifestFile.Identity() || exactFile.Digest() != manifestFile.Digest() || exactFile.SizeBytes() != manifestFile.SizeBytes() {
		return FileClassificationReceipt{}, fmt.Errorf("content does not match repository file %q", filePath)
	}
	contentSignal := FileContentNULFree
	if bytes.IndexByte(content, 0) >= 0 {
		contentSignal = FileContentContainsNUL
	}
	extension := path.Ext(filePath)
	vendorPath := hasExactPathSegment(filePath, "vendor")
	goTestPath := strings.HasSuffix(path.Base(filePath), "_test.go")
	preimage := struct {
		Contract               string            `json:"contract"`
		SchemaVersion          int               `json:"schema_version"`
		Classifier             string            `json:"classifier"`
		ClassifierVersion      string            `json:"classifier_version"`
		ManifestIdentity       string            `json:"manifest_identity"`
		RepositoryFileIdentity string            `json:"repository_file_identity"`
		Path                   string            `json:"path"`
		Extension              string            `json:"extension"`
		ContentSignal          FileContentSignal `json:"content_signal"`
		VendorPath             bool              `json:"vendor_path"`
		GoTestPath             bool              `json:"go_test_path"`
	}{
		Contract:               "open-trestle/file-classification-receipt",
		SchemaVersion:          1,
		Classifier:             fileClassificationName,
		ClassifierVersion:      fileClassificationVersion,
		ManifestIdentity:       canonicalManifest.Identity(),
		RepositoryFileIdentity: manifestFile.Identity(),
		Path:                   filePath,
		Extension:              extension,
		ContentSignal:          contentSignal,
		VendorPath:             vendorPath,
		GoTestPath:             goTestPath,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return FileClassificationReceipt{}, fmt.Errorf("encode file classification receipt identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return FileClassificationReceipt{
		identity:               hex.EncodeToString(digest[:]),
		manifestIdentity:       canonicalManifest.Identity(),
		repositoryFileIdentity: manifestFile.Identity(),
		path:                   filePath,
		extension:              extension,
		contentSignal:          contentSignal,
		vendorPath:             vendorPath,
		goTestPath:             goTestPath,
		classifierVersion:      fileClassificationVersion,
	}, nil
}

func hasExactPathSegment(filePath, segment string) bool {
	for _, candidate := range strings.Split(filePath, "/") {
		if candidate == segment {
			return true
		}
	}
	return false
}

// Identity returns the versioned canonical SHA-256 identity.
func (r FileClassificationReceipt) Identity() string {
	return r.identity
}

// ManifestIdentity returns the exact source manifest identity.
func (r FileClassificationReceipt) ManifestIdentity() string {
	return r.manifestIdentity
}

// RepositoryFileIdentity returns the exact classified file identity.
func (r FileClassificationReceipt) RepositoryFileIdentity() string {
	return r.repositoryFileIdentity
}

// Path returns the exact workspace-relative file path.
func (r FileClassificationReceipt) Path() string {
	return r.path
}

// Extension returns the exact path extension.
func (r FileClassificationReceipt) Extension() string {
	return r.extension
}

// ContentSignal returns exact NUL-byte presence.
func (r FileClassificationReceipt) ContentSignal() FileContentSignal {
	return r.contentSignal
}

// IsVendorPath reports whether an exact lowercase vendor segment exists.
func (r FileClassificationReceipt) IsVendorPath() bool {
	return r.vendorPath
}

// IsGoTestPath reports whether the basename ends exactly in _test.go.
func (r FileClassificationReceipt) IsGoTestPath() bool {
	return r.goTestPath
}

// ClassifierVersion returns the identity-bound classifier version.
func (r FileClassificationReceipt) ClassifierVersion() string {
	return r.classifierVersion
}
