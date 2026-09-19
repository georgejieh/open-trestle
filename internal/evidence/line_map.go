package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// LineMap maps unchanged lines between one base file and its head version.
type LineMap struct {
	identity           string
	fileChangeIdentity string
	path               string
	baseLineCount      int
	headLineCount      int
	hunks              []Hunk
}

// NewLineMap creates a canonical line map for one modified file.
func NewLineMap(change FileChange, baseLineCount, headLineCount int, hunks []Hunk) (LineMap, error) {
	if err := validateLineMapChange(change); err != nil {
		return LineMap{}, err
	}
	maxInt := int(^uint(0) >> 1)
	if baseLineCount < 0 || baseLineCount == maxInt {
		return LineMap{}, fmt.Errorf("base line count must be between 0 and %d: %d", maxInt-1, baseLineCount)
	}
	if headLineCount < 0 || headLineCount == maxInt {
		return LineMap{}, fmt.Errorf("head line count must be between 0 and %d: %d", maxInt-1, headLineCount)
	}
	if len(hunks) == 0 {
		return LineMap{}, fmt.Errorf("at least one hunk is required")
	}

	canonicalHunks := append([]Hunk(nil), hunks...)
	seen := make(map[string]struct{}, len(canonicalHunks))
	baseCursor := int64(1)
	headCursor := int64(1)
	baseChanged := int64(0)
	headChanged := int64(0)
	for i, hunk := range canonicalHunks {
		canonical, err := newHunkWithoutRangeCheck(change, hunk.BaseStartLine(), hunk.BaseLineCount(), hunk.HeadStartLine(), hunk.HeadLineCount())
		if err != nil || canonical != hunk {
			return LineMap{}, fmt.Errorf("hunk %d is not canonical for the file change", i)
		}
		if _, exists := seen[hunk.Identity()]; exists {
			return LineMap{}, fmt.Errorf("duplicate hunk identity at index %d", i)
		}
		seen[hunk.Identity()] = struct{}{}
		if err := validateLineMapHunkBounds(hunk, baseLineCount, headLineCount); err != nil {
			return LineMap{}, fmt.Errorf("hunk %d: %w", i, err)
		}

		baseStart := int64(hunk.BaseStartLine())
		headStart := int64(hunk.HeadStartLine())
		baseGap := baseStart - baseCursor
		headGap := headStart - headCursor
		if baseGap < 0 || headGap < 0 {
			return LineMap{}, fmt.Errorf("hunk %d overlaps or moves backward", i)
		}
		if baseGap != headGap {
			return LineMap{}, fmt.Errorf("hunk %d has unequal unchanged gaps", i)
		}
		if i > 0 && baseGap == 0 {
			return LineMap{}, fmt.Errorf("hunk %d is directly adjacent to the previous hunk", i)
		}
		baseCursor = baseStart + int64(hunk.BaseLineCount())
		headCursor = headStart + int64(hunk.HeadLineCount())
		baseChanged += int64(hunk.BaseLineCount())
		headChanged += int64(hunk.HeadLineCount())
	}

	if headChanged-baseChanged != int64(headLineCount)-int64(baseLineCount) {
		return LineMap{}, fmt.Errorf("file line-count delta does not match hunk delta")
	}
	baseTail := int64(baseLineCount) + 1 - baseCursor
	headTail := int64(headLineCount) + 1 - headCursor
	if baseTail < 0 || headTail < 0 || baseTail != headTail {
		return LineMap{}, fmt.Errorf("base and head have unequal unchanged tails")
	}
	if err := validateLineMapCoverage(change, canonicalHunks); err != nil {
		return LineMap{}, err
	}

	hunkIdentities := make([]string, len(canonicalHunks))
	for i, hunk := range canonicalHunks {
		hunkIdentities[i] = hunk.Identity()
	}
	canonical := struct {
		Contract           string   `json:"contract"`
		SchemaVersion      int      `json:"schema_version"`
		FileChangeIdentity string   `json:"file_change_identity"`
		Path               string   `json:"path"`
		BaseLineCount      int      `json:"base_line_count"`
		HeadLineCount      int      `json:"head_line_count"`
		HunkIdentities     []string `json:"hunk_identities"`
	}{
		Contract:           "open-trestle/line-map",
		SchemaVersion:      1,
		FileChangeIdentity: change.Identity(),
		Path:               change.Path(),
		BaseLineCount:      baseLineCount,
		HeadLineCount:      headLineCount,
		HunkIdentities:     hunkIdentities,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return LineMap{}, fmt.Errorf("encode line map identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return LineMap{
		identity:           hex.EncodeToString(digest[:]),
		fileChangeIdentity: change.Identity(),
		path:               change.Path(),
		baseLineCount:      baseLineCount,
		headLineCount:      headLineCount,
		hunks:              canonicalHunks,
	}, nil
}

func validateLineMapChange(change FileChange) error {
	if change.Identity() == "" || change.Path() == "" {
		return fmt.Errorf("file change is required")
	}
	canonical, err := NewFileChange(change.Path(), change.BaseDigest(), change.HeadDigest(), change.ChangedRanges())
	if err != nil || canonical.Identity() != change.Identity() {
		return fmt.Errorf("file change is not canonical")
	}
	return nil
}

func validateLineMapHunkBounds(hunk Hunk, baseLineCount, headLineCount int) error {
	baseStart := int64(hunk.BaseStartLine())
	baseCount := int64(hunk.BaseLineCount())
	headStart := int64(hunk.HeadStartLine())
	headCount := int64(hunk.HeadLineCount())
	if baseCount == 0 {
		if baseStart > int64(baseLineCount)+1 {
			return fmt.Errorf("base cursor %d is past end of file", baseStart)
		}
	} else if baseStart+baseCount-1 > int64(baseLineCount) {
		return fmt.Errorf("base span is past end of file")
	}
	if headCount == 0 {
		if headStart > int64(headLineCount)+1 {
			return fmt.Errorf("head cursor %d is past end of file", headStart)
		}
	} else if headStart+headCount-1 > int64(headLineCount) {
		return fmt.Errorf("head span is past end of file")
	}
	return nil
}

func validateLineMapCoverage(change FileChange, hunks []Hunk) error {
	projected := make([]SourceRange, 0, len(hunks))
	for _, hunk := range hunks {
		if hunk.HeadLineCount() == 0 {
			continue
		}
		endLine, err := hunkInclusiveEnd(hunk.HeadStartLine(), hunk.HeadLineCount())
		if err != nil {
			return fmt.Errorf("project hunk head span: %w", err)
		}
		sourceRange, err := NewSourceRange(change.Path(), hunk.HeadStartLine(), endLine)
		if err != nil {
			return fmt.Errorf("project hunk head span: %w", err)
		}
		projected = append(projected, sourceRange)
	}
	canonical, err := canonicalFileChangeRanges(change.Path(), projected)
	if err != nil {
		return fmt.Errorf("canonicalize hunk coverage: %w", err)
	}
	changedRanges := change.ChangedRanges()
	if len(canonical) != len(changedRanges) {
		return fmt.Errorf("hunk head spans do not cover changed ranges")
	}
	for i := range canonical {
		if canonical[i] != changedRanges[i] {
			return fmt.Errorf("hunk head spans do not cover changed range %d", i)
		}
	}
	return nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (m LineMap) Identity() string {
	return m.identity
}

// FileChangeIdentity returns the owning file-change identity.
func (m LineMap) FileChangeIdentity() string {
	return m.fileChangeIdentity
}

// Path returns the owning workspace-relative path.
func (m LineMap) Path() string {
	return m.path
}

// BaseLineCount returns the total number of base lines.
func (m LineMap) BaseLineCount() int {
	return m.baseLineCount
}

// HeadLineCount returns the total number of head lines.
func (m LineMap) HeadLineCount() int {
	return m.headLineCount
}

// Hunks returns a copy of the canonical edit blocks.
func (m LineMap) Hunks() []Hunk {
	return append([]Hunk(nil), m.hunks...)
}

// MapBaseLineToHead maps an unchanged base line to the head file.
func (m LineMap) MapBaseLineToHead(line int) (mapped int, exact bool, err error) {
	if line < 1 || line > m.baseLineCount {
		return 0, false, fmt.Errorf("base line %d is outside the file", line)
	}
	candidate := int64(line)
	delta := int64(0)
	for _, hunk := range m.hunks {
		start := int64(hunk.BaseStartLine())
		count := int64(hunk.BaseLineCount())
		if candidate < start {
			return int(candidate + delta), true, nil
		}
		if count > 0 && candidate < start+count {
			return 0, false, nil
		}
		delta += int64(hunk.HeadLineCount()) - count
	}
	return int(candidate + delta), true, nil
}

// MapHeadLineToBase maps an unchanged head line to the base file.
func (m LineMap) MapHeadLineToBase(line int) (mapped int, exact bool, err error) {
	if line < 1 || line > m.headLineCount {
		return 0, false, fmt.Errorf("head line %d is outside the file", line)
	}
	candidate := int64(line)
	delta := int64(0)
	for _, hunk := range m.hunks {
		start := int64(hunk.HeadStartLine())
		count := int64(hunk.HeadLineCount())
		if candidate < start {
			return int(candidate + delta), true, nil
		}
		if count > 0 && candidate < start+count {
			return 0, false, nil
		}
		delta += int64(hunk.BaseLineCount()) - count
	}
	return int(candidate + delta), true, nil
}
