package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

type validatedFileClassifier func(string, evidence.RepositoryFile, []byte) (FileClassificationReceipt, error)

// RepositoryClassificationReceipt records complete exact-signal coverage for a manifest.
type RepositoryClassificationReceipt struct {
	identity          string
	manifestIdentity  string
	classifierVersion string
	files             []FileClassificationReceipt
}

// ClassifyRepositoryManifest classifies every canonical manifest file exactly once.
func ClassifyRepositoryManifest(manifest evidence.RepositoryManifest, contents map[string][]byte) (RepositoryClassificationReceipt, error) {
	validatedManifest, err := validateClassificationManifest(manifest)
	if err != nil {
		return RepositoryClassificationReceipt{}, err
	}
	return buildRepositoryClassification(validatedManifest, contents, classifyValidatedRepositoryFile)
}

func buildRepositoryClassification(validatedManifest evidence.RepositoryManifest, contents map[string][]byte, classify validatedFileClassifier) (RepositoryClassificationReceipt, error) {
	files := validatedManifest.Files()
	if len(contents) != len(files) {
		return RepositoryClassificationReceipt{}, fmt.Errorf("content manifest has %d entries, want %d", len(contents), len(files))
	}
	for _, file := range files {
		if _, ok := contents[file.Path()]; !ok {
			return RepositoryClassificationReceipt{}, fmt.Errorf("content manifest does not contain path %q", file.Path())
		}
	}
	if classify == nil {
		return RepositoryClassificationReceipt{}, fmt.Errorf("file classifier is required")
	}
	classifications := make([]FileClassificationReceipt, len(files))
	identities := make(map[string]struct{}, len(files))
	for i, file := range files {
		classification, err := classify(validatedManifest.Identity(), file, contents[file.Path()])
		if err != nil {
			return RepositoryClassificationReceipt{}, fmt.Errorf("classify repository file %q: %w", file.Path(), err)
		}
		if err := validateFileClassificationReceipt(validatedManifest.Identity(), file, contents[file.Path()], classification); err != nil {
			return RepositoryClassificationReceipt{}, err
		}
		if _, ok := identities[classification.Identity()]; ok {
			return RepositoryClassificationReceipt{}, fmt.Errorf("duplicate file classification identity %q", classification.Identity())
		}
		identities[classification.Identity()] = struct{}{}
		classifications[i] = classification
	}
	return newRepositoryClassificationReceipt(validatedManifest.Identity(), classifications)
}

func newRepositoryClassificationReceipt(manifestIdentity string, files []FileClassificationReceipt) (RepositoryClassificationReceipt, error) {
	type identityFile struct {
		Path                   string `json:"path"`
		ClassificationIdentity string `json:"classification_identity"`
	}
	identityFiles := make([]identityFile, len(files))
	for i, file := range files {
		identityFiles[i] = identityFile{Path: file.Path(), ClassificationIdentity: file.Identity()}
	}
	preimage := struct {
		Contract          string         `json:"contract"`
		SchemaVersion     int            `json:"schema_version"`
		Classifier        string         `json:"classifier"`
		ClassifierVersion string         `json:"classifier_version"`
		ManifestIdentity  string         `json:"manifest_identity"`
		Files             []identityFile `json:"files"`
	}{
		Contract:          "open-trestle/repository-classification-receipt",
		SchemaVersion:     1,
		Classifier:        fileClassificationName,
		ClassifierVersion: fileClassificationVersion,
		ManifestIdentity:  manifestIdentity,
		Files:             identityFiles,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryClassificationReceipt{}, fmt.Errorf("encode repository classification receipt identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryClassificationReceipt{
		identity:          hex.EncodeToString(digest[:]),
		manifestIdentity:  manifestIdentity,
		classifierVersion: fileClassificationVersion,
		files:             append([]FileClassificationReceipt{}, files...),
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (r RepositoryClassificationReceipt) Identity() string {
	return r.identity
}

// ManifestIdentity returns the exact classified manifest identity.
func (r RepositoryClassificationReceipt) ManifestIdentity() string {
	return r.manifestIdentity
}

// ClassifierVersion returns the identity-bound classifier version.
func (r RepositoryClassificationReceipt) ClassifierVersion() string {
	return r.classifierVersion
}

// Files returns classified files in canonical path order.
func (r RepositoryClassificationReceipt) Files() []FileClassificationReceipt {
	return append([]FileClassificationReceipt{}, r.files...)
}

// File returns the classification for an exact path.
func (r RepositoryClassificationReceipt) File(filePath string) (FileClassificationReceipt, bool) {
	index := sort.Search(len(r.files), func(i int) bool {
		return r.files[i].Path() >= filePath
	})
	if index == len(r.files) || r.files[index].Path() != filePath {
		return FileClassificationReceipt{}, false
	}
	return r.files[index], true
}

// FileCount returns the number of classified manifest files.
func (r RepositoryClassificationReceipt) FileCount() int {
	return len(r.files)
}
