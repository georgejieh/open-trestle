package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// HunkKind identifies the shape of one normalized edit block.
type HunkKind string

const (
	// HunkKindAddition adds head lines without replacing base lines.
	HunkKindAddition HunkKind = "addition"
	// HunkKindDeletion removes base lines without adding head lines.
	HunkKindDeletion HunkKind = "deletion"
	// HunkKindModification replaces base lines with head lines.
	HunkKindModification HunkKind = "modification"
)

// Hunk describes one contiguous edit bound to a modified file.
type Hunk struct {
	identity           string
	fileChangeIdentity string
	path               string
	baseStartLine      int
	baseLineCount      int
	headStartLine      int
	headLineCount      int
	kind               HunkKind
}

// NewHunk creates a normalized edit block owned by a FileChange.
func NewHunk(change FileChange, baseStartLine, baseLineCount, headStartLine, headLineCount int) (Hunk, error) {
	hunk, err := newHunkWithoutRangeCheck(change, baseStartLine, baseLineCount, headStartLine, headLineCount)
	if err != nil {
		return Hunk{}, err
	}
	if headLineCount > 0 {
		headEndLine, _ := hunkInclusiveEnd(headStartLine, headLineCount)
		if !fileChangeContainsHeadSpan(change, headStartLine, headEndLine) {
			return Hunk{}, fmt.Errorf("head span %d-%d is not contained in one changed range", headStartLine, headEndLine)
		}
	}
	return hunk, nil
}

// Collection constructors use this after proving exact range coverage.
func newHunkWithoutRangeCheck(change FileChange, baseStartLine, baseLineCount, headStartLine, headLineCount int) (Hunk, error) {
	if change.Identity() == "" || change.Path() == "" {
		return Hunk{}, fmt.Errorf("file change is required")
	}
	if baseStartLine < 1 {
		return Hunk{}, fmt.Errorf("base start line must be positive: %d", baseStartLine)
	}
	if headStartLine < 1 {
		return Hunk{}, fmt.Errorf("head start line must be positive: %d", headStartLine)
	}
	if baseLineCount < 0 {
		return Hunk{}, fmt.Errorf("base line count must be non-negative: %d", baseLineCount)
	}
	if headLineCount < 0 {
		return Hunk{}, fmt.Errorf("head line count must be non-negative: %d", headLineCount)
	}
	if baseLineCount == 0 && headLineCount == 0 {
		return Hunk{}, fmt.Errorf("hunk must add, delete, or modify at least one line")
	}
	if _, err := hunkInclusiveEnd(baseStartLine, baseLineCount); err != nil {
		return Hunk{}, fmt.Errorf("base coordinates: %w", err)
	}
	if _, err := hunkInclusiveEnd(headStartLine, headLineCount); err != nil {
		return Hunk{}, fmt.Errorf("head coordinates: %w", err)
	}
	kind := deriveHunkKind(baseLineCount, headLineCount)
	canonical := struct {
		Contract           string   `json:"contract"`
		SchemaVersion      int      `json:"schema_version"`
		FileChangeIdentity string   `json:"file_change_identity"`
		Path               string   `json:"path"`
		BaseStartLine      int      `json:"base_start_line"`
		BaseLineCount      int      `json:"base_line_count"`
		HeadStartLine      int      `json:"head_start_line"`
		HeadLineCount      int      `json:"head_line_count"`
		Kind               HunkKind `json:"kind"`
	}{
		Contract:           "open-trestle/hunk",
		SchemaVersion:      1,
		FileChangeIdentity: change.Identity(),
		Path:               change.Path(),
		BaseStartLine:      baseStartLine,
		BaseLineCount:      baseLineCount,
		HeadStartLine:      headStartLine,
		HeadLineCount:      headLineCount,
		Kind:               kind,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return Hunk{}, fmt.Errorf("encode hunk identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return Hunk{
		identity:           hex.EncodeToString(digest[:]),
		fileChangeIdentity: change.Identity(),
		path:               change.Path(),
		baseStartLine:      baseStartLine,
		baseLineCount:      baseLineCount,
		headStartLine:      headStartLine,
		headLineCount:      headLineCount,
		kind:               kind,
	}, nil
}

func hunkInclusiveEnd(startLine, lineCount int) (int, error) {
	if lineCount == 0 {
		return startLine, nil
	}
	maxInt := int(^uint(0) >> 1)
	if lineCount > maxInt-startLine+1 {
		return 0, fmt.Errorf("inclusive end line overflows int")
	}
	return startLine + lineCount - 1, nil
}

func fileChangeContainsHeadSpan(change FileChange, startLine, endLine int) bool {
	index := sort.Search(len(change.ranges), func(i int) bool {
		return change.ranges[i].EndLine() >= startLine
	})
	return index < len(change.ranges) && startLine >= change.ranges[index].StartLine() && endLine <= change.ranges[index].EndLine()
}

func deriveHunkKind(baseLineCount, headLineCount int) HunkKind {
	if baseLineCount == 0 {
		return HunkKindAddition
	}
	if headLineCount == 0 {
		return HunkKindDeletion
	}
	return HunkKindModification
}

// Identity returns the versioned canonical SHA-256 identity.
func (h Hunk) Identity() string {
	return h.identity
}

// FileChangeIdentity returns the owning file-change identity.
func (h Hunk) FileChangeIdentity() string {
	return h.fileChangeIdentity
}

// Path returns the owning workspace-relative path.
func (h Hunk) Path() string {
	return h.path
}

// BaseStartLine returns the 1-based base cursor position.
func (h Hunk) BaseStartLine() int {
	return h.baseStartLine
}

// BaseLineCount returns the number of replaced base lines.
func (h Hunk) BaseLineCount() int {
	return h.baseLineCount
}

// HeadStartLine returns the 1-based head cursor position.
func (h Hunk) HeadStartLine() int {
	return h.headStartLine
}

// HeadLineCount returns the number of resulting head lines.
func (h Hunk) HeadLineCount() int {
	return h.headLineCount
}

// Kind returns the derived edit shape.
func (h Hunk) Kind() HunkKind {
	return h.kind
}
