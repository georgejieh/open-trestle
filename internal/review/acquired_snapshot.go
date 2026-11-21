package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maxAcquiredReviewWorkspaceBytes = 4 << 10

var (
	// ErrInvalidAcquiredReviewWorkspace identifies an empty, excessive, or control-bearing workspace ID.
	ErrInvalidAcquiredReviewWorkspace = errors.New("invalid acquired review workspace")
	// ErrInvalidAcquiredReviewManifest identifies noncanonical manifest metadata.
	ErrInvalidAcquiredReviewManifest = errors.New("invalid acquired review manifest")
	// ErrAcquiredReviewRangeNotInHead identifies a requested path absent from the head.
	ErrAcquiredReviewRangeNotInHead = errors.New("acquired review range is not in head manifest")
	// ErrInvalidAcquiredReviewRanges identifies an empty, excessive, or noncanonical range set.
	ErrInvalidAcquiredReviewRanges = errors.New("invalid acquired review ranges")
	// ErrDuplicateAcquiredReviewRange identifies a repeated physical range.
	ErrDuplicateAcquiredReviewRange = errors.New("duplicate acquired review range")
)

// NewAcquiredReviewPipelineSnapshot creates the aggregate snapshot consumed by model review.
func NewAcquiredReviewPipelineSnapshot(workspace string, headManifest evidence.RepositoryManifest, ranges []evidence.SourceRange) (ReviewSnapshot, error) {
	if !validAcquiredReviewWorkspace(workspace) {
		return ReviewSnapshot{}, ErrInvalidAcquiredReviewWorkspace
	}
	canonicalManifest, err := canonicalAcquiredReviewManifest(headManifest)
	if err != nil {
		return ReviewSnapshot{}, err
	}
	// No head range is valid only for a change that only removes files, whose
	// packet then holds removed base lines alone.
	if len(ranges) > maxSelectedContextSources {
		return ReviewSnapshot{}, ErrInvalidAcquiredReviewRanges
	}
	canonicalRanges := append([]evidence.SourceRange(nil), ranges...)
	sort.Slice(canonicalRanges, func(i, j int) bool {
		if canonicalRanges[i].Path() != canonicalRanges[j].Path() {
			return canonicalRanges[i].Path() < canonicalRanges[j].Path()
		}
		if canonicalRanges[i].StartLine() != canonicalRanges[j].StartLine() {
			return canonicalRanges[i].StartLine() < canonicalRanges[j].StartLine()
		}
		return canonicalRanges[i].EndLine() < canonicalRanges[j].EndLine()
	})
	for index, sourceRange := range canonicalRanges {
		rebuilt, rangeErr := evidence.NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
		if rangeErr != nil || rebuilt != sourceRange {
			return ReviewSnapshot{}, ErrInvalidAcquiredReviewRanges
		}
		if index > 0 && canonicalRanges[index-1] == sourceRange {
			return ReviewSnapshot{}, ErrDuplicateAcquiredReviewRange
		}
		if _, exists := canonicalManifest.File(sourceRange.Path()); !exists {
			return ReviewSnapshot{}, ErrAcquiredReviewRangeNotInHead
		}
	}
	revision, err := deriveAcquiredReviewRangeRevision(canonicalManifest, canonicalRanges)
	if err != nil {
		return ReviewSnapshot{}, err
	}
	return NewReviewSnapshot(workspace, revision, canonicalRanges)
}

func canonicalAcquiredReviewManifest(manifest evidence.RepositoryManifest) (evidence.RepositoryManifest, error) {
	canonical, err := evidence.NewRepositoryManifest(manifest.Files())
	if err != nil || canonical.Identity() != manifest.Identity() {
		return evidence.RepositoryManifest{}, ErrInvalidAcquiredReviewManifest
	}
	return canonical, nil
}
func validAcquiredReviewWorkspace(workspace string) bool {
	if len(workspace) == 0 || len(workspace) > maxAcquiredReviewWorkspaceBytes || !utf8.ValidString(workspace) || strings.ContainsRune(workspace, 0) {
		return false
	}
	for _, character := range workspace {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func deriveAcquiredReviewRangeRevision(manifest evidence.RepositoryManifest, ranges []evidence.SourceRange) (string, error) {
	type rangeWire struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
		File  string `json:"file"`
	}
	preimage := struct {
		Contract string      `json:"contract"`
		Version  int         `json:"version"`
		Manifest string      `json:"manifest"`
		Ranges   []rangeWire `json:"ranges"`
	}{Contract: "open-trestle/acquired-review-range-set", Version: 1, Manifest: manifest.Identity(), Ranges: make([]rangeWire, len(ranges))}
	for index, sourceRange := range ranges {
		file, exists := manifest.File(sourceRange.Path())
		if !exists {
			return "", ErrAcquiredReviewRangeNotInHead
		}
		preimage.Ranges[index] = rangeWire{sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine(), file.Identity()}
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
