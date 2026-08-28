package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// FileChange describes changed head-side ranges in one modified text file.
type FileChange struct {
	identity   string
	path       string
	baseDigest string
	headDigest string
	ranges     []SourceRange
}

// NewFileChange creates a canonical modified-file descriptor.
func NewFileChange(path, baseDigest, headDigest string, ranges []SourceRange) (FileChange, error) {
	if err := validateSourcePath(path); err != nil {
		return FileChange{}, err
	}
	if err := validateFileChangeDigest("base", baseDigest); err != nil {
		return FileChange{}, err
	}
	if err := validateFileChangeDigest("head", headDigest); err != nil {
		return FileChange{}, err
	}
	if baseDigest == headDigest {
		return FileChange{}, fmt.Errorf("base and head digests must differ")
	}
	canonicalRanges, err := canonicalFileChangeRanges(path, ranges)
	if err != nil {
		return FileChange{}, err
	}
	canonical := struct {
		Contract      string                `json:"contract"`
		SchemaVersion int                   `json:"schema_version"`
		Path          string                `json:"path"`
		BaseDigest    string                `json:"base_digest"`
		HeadDigest    string                `json:"head_digest"`
		Ranges        []fileChangeRangeWire `json:"ranges"`
	}{
		Contract:      "open-trestle/file-change",
		SchemaVersion: 1,
		Path:          path,
		BaseDigest:    baseDigest,
		HeadDigest:    headDigest,
		Ranges:        make([]fileChangeRangeWire, len(canonicalRanges)),
	}
	for i, sourceRange := range canonicalRanges {
		canonical.Ranges[i] = fileChangeRangeWire{
			StartLine: sourceRange.StartLine(),
			EndLine:   sourceRange.EndLine(),
		}
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return FileChange{}, fmt.Errorf("encode file change identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return FileChange{
		identity:   hex.EncodeToString(digest[:]),
		path:       path,
		baseDigest: baseDigest,
		headDigest: headDigest,
		ranges:     append([]SourceRange(nil), canonicalRanges...),
	}, nil
}

type fileChangeRangeWire struct {
	StartLine int `json:"start_line"`
	EndLine   int `json:"end_line"`
}

func validateFileChangeDigest(name, digest string) error {
	if len(digest) != sha256HexLength || digest != strings.ToLower(digest) {
		return fmt.Errorf("%s digest must be a lowercase SHA-256 digest", name)
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("invalid %s digest: %w", name, err)
	}
	return nil
}

func canonicalFileChangeRanges(path string, ranges []SourceRange) ([]SourceRange, error) {
	if len(ranges) == 0 {
		return []SourceRange{}, nil
	}
	canonical := make([]SourceRange, 0, len(ranges))
	previousStart := 0
	for i, sourceRange := range ranges {
		validated, err := NewSourceRange(sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
		if err != nil {
			return nil, fmt.Errorf("validate changed range %d: %w", i, err)
		}
		if validated.Path() != path {
			return nil, fmt.Errorf("changed range %d path %q does not match file path %q", i, validated.Path(), path)
		}
		if i > 0 && validated.StartLine() < previousStart {
			return nil, fmt.Errorf("changed ranges must be ordered by start line")
		}
		previousStart = validated.StartLine()
		if len(canonical) == 0 {
			canonical = append(canonical, validated)
			continue
		}
		last := canonical[len(canonical)-1]
		if validated.StartLine() <= last.EndLine() {
			return nil, fmt.Errorf("changed ranges overlap or duplicate at line %d", validated.StartLine())
		}
		if validated.StartLine()-1 == last.EndLine() {
			merged, err := NewSourceRange(path, last.StartLine(), validated.EndLine())
			if err != nil {
				return nil, fmt.Errorf("merge adjacent changed ranges: %w", err)
			}
			canonical[len(canonical)-1] = merged
			continue
		}
		canonical = append(canonical, validated)
	}
	return canonical, nil
}

// Identity returns the canonical SHA-256 descriptor identity.
func (c FileChange) Identity() string {
	return c.identity
}

// Path returns the workspace-relative file path.
func (c FileChange) Path() string {
	return c.path
}

// BaseDigest returns the lowercase SHA-256 base-content digest.
func (c FileChange) BaseDigest() string {
	return c.baseDigest
}

// HeadDigest returns the lowercase SHA-256 head-content digest.
func (c FileChange) HeadDigest() string {
	return c.headDigest
}

// ChangedRanges returns a copy of the canonical head-side ranges.
func (c FileChange) ChangedRanges() []SourceRange {
	return append([]SourceRange(nil), c.ranges...)
}
