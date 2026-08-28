package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Aligns repository facts with the accepted bounded source-path intake.
const maxRepositoryFilePathBytes = 4096

// RepositoryFile records exact supplied-byte metadata for one file path.
type RepositoryFile struct {
	identity  string
	path      string
	digest    string
	sizeBytes int
}

// NewRepositoryFile creates immutable metadata from exact supplied bytes.
func NewRepositoryFile(path string, content []byte) (RepositoryFile, error) {
	if len(path) > maxRepositoryFilePathBytes {
		return RepositoryFile{}, fmt.Errorf("source path exceeds %d bytes", maxRepositoryFilePathBytes)
	}
	if err := validateSourcePath(path); err != nil {
		return RepositoryFile{}, err
	}
	contentDigest := sha256.Sum256(content)
	digest := hex.EncodeToString(contentDigest[:])
	identity, err := repositoryFileIdentity(path, digest, len(content))
	if err != nil {
		return RepositoryFile{}, err
	}
	return RepositoryFile{identity: identity, path: path, digest: digest, sizeBytes: len(content)}, nil
}

func canonicalRepositoryFile(file RepositoryFile) (RepositoryFile, error) {
	if len(file.path) > maxRepositoryFilePathBytes {
		return RepositoryFile{}, fmt.Errorf("source path exceeds %d bytes", maxRepositoryFilePathBytes)
	}
	if err := validateSourcePath(file.path); err != nil {
		return RepositoryFile{}, err
	}
	if len(file.digest) != sha256HexLength || file.digest != strings.ToLower(file.digest) {
		return RepositoryFile{}, fmt.Errorf("repository file digest must be a lowercase SHA-256 digest")
	}
	if _, err := hex.DecodeString(file.digest); err != nil {
		return RepositoryFile{}, fmt.Errorf("invalid repository file digest: %w", err)
	}
	if file.sizeBytes < 0 {
		return RepositoryFile{}, fmt.Errorf("repository file size must be non-negative")
	}
	identity, err := repositoryFileIdentity(file.path, file.digest, file.sizeBytes)
	if err != nil || identity != file.identity {
		return RepositoryFile{}, fmt.Errorf("repository file is not canonical")
	}
	return RepositoryFile{identity: identity, path: file.path, digest: file.digest, sizeBytes: file.sizeBytes}, nil
}

func repositoryFileIdentity(path, digest string, sizeBytes int) (string, error) {
	preimage := struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Path          string `json:"path"`
		Digest        string `json:"digest"`
		SizeBytes     int    `json:"size_bytes"`
	}{
		Contract:      "open-trestle/repository-file",
		SchemaVersion: 1,
		Path:          path,
		Digest:        digest,
		SizeBytes:     sizeBytes,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", fmt.Errorf("encode repository file identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return hex.EncodeToString(identityDigest[:]), nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (f RepositoryFile) Identity() string {
	return f.identity
}

// Path returns the exact workspace-relative path.
func (f RepositoryFile) Path() string {
	return f.path
}

// Digest returns the SHA-256 digest of the exact supplied bytes.
func (f RepositoryFile) Digest() string {
	return f.digest
}

// SizeBytes returns the exact supplied content size.
func (f RepositoryFile) SizeBytes() int {
	return f.sizeBytes
}
