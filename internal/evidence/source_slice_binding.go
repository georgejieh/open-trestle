package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	maxSourceSliceFileBytes = 64 << 20
	maxSourceSliceBytes     = 1 << 20
)

var (
	// ErrSourceSliceFileMismatch identifies bytes or a path inconsistent with repository-file metadata.
	ErrSourceSliceFileMismatch = errors.New("source slice file mismatch")
	// ErrSourceSliceRangeOutOfBounds identifies a range beyond the physical file lines.
	ErrSourceSliceRangeOutOfBounds = errors.New("source slice range out of bounds")
	// ErrSourceSliceMismatch identifies slice bytes other than the exact physical lines.
	ErrSourceSliceMismatch = errors.New("source slice mismatch")
	// ErrInvalidSourceSliceBinding identifies malformed immutable binding fields.
	ErrInvalidSourceSliceBinding = errors.New("invalid source slice binding")
	// ErrInvalidSourceSliceBindingIdentity identifies content inconsistent with its identity.
	ErrInvalidSourceSliceBindingIdentity = errors.New("invalid source slice binding identity")
)

// SourceSliceBinding proves that snippet bytes were exact physical lines of a repository file.
type SourceSliceBinding struct {
	identity               string
	repositoryFileIdentity string
	repositoryFileDigest   string
	sourceRange            SourceRange
	sliceDigest            string
	sliceBytes             int
}

// BindSourceSlice validates full-file metadata and an exact physical-line extraction.
func BindSourceSlice(file RepositoryFile, fileContent []byte, sourceRange SourceRange, sliceContent []byte) (SourceSliceBinding, error) {
	binding, expected, err := bindSourceRange(file, fileContent, sourceRange)
	if err != nil {
		return SourceSliceBinding{}, err
	}
	if !bytes.Equal(sliceContent, expected) {
		return SourceSliceBinding{}, ErrSourceSliceMismatch
	}
	return binding, nil
}

// BindSourceRange reconstructs a binding from the exact physical lines of a repository file.
func BindSourceRange(file RepositoryFile, fileContent []byte, sourceRange SourceRange) (SourceSliceBinding, error) {
	binding, _, err := bindSourceRange(file, fileContent, sourceRange)
	return binding, err
}

func bindSourceRange(file RepositoryFile, fileContent []byte, sourceRange SourceRange) (SourceSliceBinding, []byte, error) {
	canonicalFile, err := canonicalRepositoryFile(file)
	if err != nil {
		return SourceSliceBinding{}, nil, ErrSourceSliceFileMismatch
	}
	if len(fileContent) > maxSourceSliceFileBytes || len(fileContent) != canonicalFile.SizeBytes() {
		return SourceSliceBinding{}, nil, ErrSourceSliceFileMismatch
	}
	fileDigest := sha256.Sum256(fileContent)
	if hex.EncodeToString(fileDigest[:]) != canonicalFile.Digest() {
		return SourceSliceBinding{}, nil, ErrSourceSliceFileMismatch
	}
	canonicalRange, err := NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
	if err != nil || canonicalRange != sourceRange || canonicalRange.Path() != canonicalFile.Path() {
		return SourceSliceBinding{}, nil, ErrSourceSliceFileMismatch
	}
	expected, ok := physicalLineSlice(fileContent, canonicalRange.StartLine(), canonicalRange.EndLine())
	if !ok {
		return SourceSliceBinding{}, nil, ErrSourceSliceRangeOutOfBounds
	}
	if len(expected) == 0 || len(expected) > maxSourceSliceBytes {
		return SourceSliceBinding{}, nil, ErrSourceSliceMismatch
	}
	sliceDigest := sha256.Sum256(expected)
	binding := SourceSliceBinding{
		repositoryFileIdentity: canonicalFile.Identity(), repositoryFileDigest: canonicalFile.Digest(),
		sourceRange: canonicalRange, sliceDigest: hex.EncodeToString(sliceDigest[:]), sliceBytes: len(expected),
	}
	binding.identity = deriveSourceSliceBindingIdentity(binding)
	return binding, expected, nil
}

func physicalLineSlice(content []byte, startLine, endLine int) ([]byte, bool) {
	if len(content) == 0 || startLine < 1 || endLine < startLine {
		return nil, false
	}
	line := 1
	startOffset := -1
	if startLine == 1 {
		startOffset = 0
	}
	for offset, value := range content {
		if value != '\n' {
			continue
		}
		if line == endLine && startOffset >= 0 {
			return content[startOffset : offset+1], true
		}
		line++
		if line == startLine && offset+1 < len(content) {
			startOffset = offset + 1
		}
	}
	if line == endLine && startOffset >= 0 && startOffset < len(content) {
		return content[startOffset:], true
	}
	return nil, false
}

func (b SourceSliceBinding) Identity() string               { return b.identity }
func (b SourceSliceBinding) RepositoryFileIdentity() string { return b.repositoryFileIdentity }
func (b SourceSliceBinding) RepositoryFileDigest() string   { return b.repositoryFileDigest }
func (b SourceSliceBinding) SourceRange() SourceRange       { return b.sourceRange }
func (b SourceSliceBinding) SliceDigest() string            { return b.sliceDigest }
func (b SourceSliceBinding) SliceBytes() int                { return b.sliceBytes }
func (b SourceSliceBinding) String() string                 { return "source slice binding" }
func (b SourceSliceBinding) GoString() string               { return "evidence.SourceSliceBinding{<redacted>}" }
func (b SourceSliceBinding) Format(state fmt.State, verb rune) {
	formatted := "source slice binding"
	if verb == 'q' {
		formatted = `"source slice binding"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "evidence.SourceSliceBinding{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies bounded canonical metadata and content-derived identity.
func (b SourceSliceBinding) Validate() error {
	canonicalRange, err := NewSourceRange(b.sourceRange.Path(), b.sourceRange.StartLine(), b.sourceRange.EndLine())
	validRange := err == nil && canonicalRange == b.sourceRange
	validFileIdentity := validSourceSliceDigest(b.repositoryFileIdentity)
	validFileDigest := validSourceSliceDigest(b.repositoryFileDigest)
	validSliceDigest := validSourceSliceDigest(b.sliceDigest)
	validSize := b.sliceBytes > 0 && b.sliceBytes <= maxSourceSliceBytes
	if !validRange || !validFileIdentity || !validFileDigest || !validSliceDigest || !validSize {
		return ErrInvalidSourceSliceBinding
	}
	if b.identity != deriveSourceSliceBindingIdentity(b) {
		return ErrInvalidSourceSliceBindingIdentity
	}
	return nil
}

func validSourceSliceDigest(value string) bool {
	if len(value) != sha256HexLength || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func deriveSourceSliceBindingIdentity(binding SourceSliceBinding) string {
	preimage := struct {
		Contract    string `json:"contract"`
		Version     int    `json:"version"`
		File        string `json:"file"`
		FileDigest  string `json:"file_digest"`
		Path        string `json:"path"`
		Start       int    `json:"start"`
		End         int    `json:"end"`
		SliceDigest string `json:"slice_digest"`
		SliceBytes  int    `json:"slice_bytes"`
	}{
		Contract: "open-trestle/source-slice-binding", Version: 1, File: binding.repositoryFileIdentity,
		FileDigest: binding.repositoryFileDigest, Path: binding.sourceRange.Path(), Start: binding.sourceRange.StartLine(),
		End: binding.sourceRange.EndLine(), SliceDigest: binding.sliceDigest, SliceBytes: binding.sliceBytes,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
