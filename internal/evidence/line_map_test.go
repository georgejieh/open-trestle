package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestLineMapMapsSingleModification(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 3, 5)})
	hunk := mustHunk(t, change, 3, 2, 3, 3)
	lineMap := mustLineMap(t, change, 8, 9, []Hunk{hunk})

	if lineMap.FileChangeIdentity() != change.Identity() || lineMap.Path() != change.Path() {
		t.Fatalf("LineMap owner = (%q, %q), want (%q, %q)", lineMap.FileChangeIdentity(), lineMap.Path(), change.Identity(), change.Path())
	}
	if lineMap.BaseLineCount() != 8 || lineMap.HeadLineCount() != 9 {
		t.Fatalf("LineMap totals = (%d, %d), want (8, 9)", lineMap.BaseLineCount(), lineMap.HeadLineCount())
	}
	assertBaseMapping(t, lineMap, 1, 1, true)
	assertBaseMapping(t, lineMap, 2, 2, true)
	assertBaseMapping(t, lineMap, 3, 0, false)
	assertBaseMapping(t, lineMap, 4, 0, false)
	assertBaseMapping(t, lineMap, 5, 6, true)
	assertBaseMapping(t, lineMap, 8, 9, true)
	assertHeadMapping(t, lineMap, 1, 1, true)
	assertHeadMapping(t, lineMap, 3, 0, false)
	assertHeadMapping(t, lineMap, 5, 0, false)
	assertHeadMapping(t, lineMap, 6, 5, true)
	assertHeadMapping(t, lineMap, 9, 8, true)
}

func TestLineMapMapsInsertionsAtFileBoundariesAndMiddle(t *testing.T) {
	testCases := []struct {
		name          string
		baseLines     int
		headLines     int
		baseStartLine int
		headStartLine int
		headLineCount int
		changedStart  int
		changedEnd    int
		baseMappings  [][2]int
		addedLines    []int
	}{
		{
			name: "beginning", baseLines: 3, headLines: 5, baseStartLine: 1,
			headStartLine: 1, headLineCount: 2, changedStart: 1, changedEnd: 2,
			baseMappings: [][2]int{{1, 3}, {3, 5}}, addedLines: []int{1, 2},
		},
		{
			name: "middle", baseLines: 4, headLines: 5, baseStartLine: 3,
			headStartLine: 3, headLineCount: 1, changedStart: 3, changedEnd: 3,
			baseMappings: [][2]int{{1, 1}, {2, 2}, {3, 4}, {4, 5}}, addedLines: []int{3},
		},
		{
			name: "end", baseLines: 2, headLines: 4, baseStartLine: 3,
			headStartLine: 3, headLineCount: 2, changedStart: 3, changedEnd: 4,
			baseMappings: [][2]int{{1, 1}, {2, 2}}, addedLines: []int{3, 4},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", testCase.changedStart, testCase.changedEnd)})
			hunk := mustHunk(t, change, testCase.baseStartLine, 0, testCase.headStartLine, testCase.headLineCount)
			lineMap := mustLineMap(t, change, testCase.baseLines, testCase.headLines, []Hunk{hunk})
			for _, mapping := range testCase.baseMappings {
				assertBaseMapping(t, lineMap, mapping[0], mapping[1], true)
				assertHeadMapping(t, lineMap, mapping[1], mapping[0], true)
			}
			for _, line := range testCase.addedLines {
				assertHeadMapping(t, lineMap, line, 0, false)
			}
		})
	}
}

func TestLineMapMapsDeletionsAtFileBoundariesAndMiddle(t *testing.T) {
	testCases := []struct {
		name          string
		baseLines     int
		headLines     int
		baseStartLine int
		baseLineCount int
		headStartLine int
		baseMappings  [][2]int
		deletedLines  []int
	}{
		{
			name: "beginning", baseLines: 5, headLines: 3,
			baseStartLine: 1, baseLineCount: 2, headStartLine: 1,
			baseMappings: [][2]int{{3, 1}, {5, 3}}, deletedLines: []int{1, 2},
		},
		{
			name: "middle", baseLines: 5, headLines: 4,
			baseStartLine: 3, baseLineCount: 1, headStartLine: 3,
			baseMappings: [][2]int{{1, 1}, {2, 2}, {4, 3}, {5, 4}}, deletedLines: []int{3},
		},
		{
			name: "end", baseLines: 4, headLines: 2,
			baseStartLine: 3, baseLineCount: 2, headStartLine: 3,
			baseMappings: [][2]int{{1, 1}, {2, 2}}, deletedLines: []int{3, 4},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, nil)
			hunk := mustHunk(t, change, testCase.baseStartLine, testCase.baseLineCount, testCase.headStartLine, 0)
			lineMap := mustLineMap(t, change, testCase.baseLines, testCase.headLines, []Hunk{hunk})
			for _, mapping := range testCase.baseMappings {
				assertBaseMapping(t, lineMap, mapping[0], mapping[1], true)
				assertHeadMapping(t, lineMap, mapping[1], mapping[0], true)
			}
			for _, line := range testCase.deletedLines {
				assertBaseMapping(t, lineMap, line, 0, false)
			}
		})
	}
}

func TestLineMapSupportsEmptyBaseOrHead(t *testing.T) {
	additionChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 2)})
	addition := mustLineMap(t, additionChange, 0, 2, []Hunk{mustHunk(t, additionChange, 1, 0, 1, 2)})
	for _, line := range []int{1, 2} {
		assertHeadMapping(t, addition, line, 0, false)
	}
	if _, _, err := addition.MapBaseLineToHead(1); err == nil {
		t.Fatal("MapBaseLineToHead() error = nil for empty base")
	}

	deletionChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, nil)
	deletion := mustLineMap(t, deletionChange, 2, 0, []Hunk{mustHunk(t, deletionChange, 1, 2, 1, 0)})
	for _, line := range []int{1, 2} {
		assertBaseMapping(t, deletion, line, 0, false)
	}
	if _, _, err := deletion.MapHeadLineToBase(1); err == nil {
		t.Fatal("MapHeadLineToBase() error = nil for empty head")
	}
}

func TestLineMapMapsMultipleHunks(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{
		mustSourceRange(t, "main.go", 2, 2),
		mustSourceRange(t, "main.go", 5, 6),
	})
	hunks := []Hunk{
		mustHunk(t, change, 2, 2, 2, 1),
		mustHunk(t, change, 6, 0, 5, 2),
		mustHunk(t, change, 8, 1, 9, 0),
	}
	lineMap := mustLineMap(t, change, 12, 12, hunks)

	for _, mapping := range [][2]int{{1, 1}, {4, 3}, {5, 4}, {6, 7}, {7, 8}, {9, 9}, {12, 12}} {
		assertBaseMapping(t, lineMap, mapping[0], mapping[1], true)
		assertHeadMapping(t, lineMap, mapping[1], mapping[0], true)
	}
	for _, line := range []int{2, 3, 8} {
		assertBaseMapping(t, lineMap, line, 0, false)
	}
	for _, line := range []int{2, 5, 6} {
		assertHeadMapping(t, lineMap, line, 0, false)
	}
}

func TestLineMapRejectsOutOfRangeQueries(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 2)})
	lineMap := mustLineMap(t, change, 3, 3, []Hunk{mustHunk(t, change, 2, 1, 2, 1)})
	for _, line := range []int{-1, 0, 4} {
		if _, _, err := lineMap.MapBaseLineToHead(line); err == nil {
			t.Fatalf("MapBaseLineToHead(%d) error = nil", line)
		}
		if _, _, err := lineMap.MapHeadLineToBase(line); err == nil {
			t.Fatalf("MapHeadLineToBase(%d) error = nil", line)
		}
	}
}

func TestNewLineMapRejectsInvalidOwnerOrHunks(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 2)})
	hunk := mustHunk(t, change, 2, 1, 2, 1)
	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	other := mustFileChange(t, "main.go", testBaseDigest, otherHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 2)})
	otherHunk := mustHunk(t, other, 2, 1, 2, 1)
	forgedPath := hunk
	forgedPath.path = "other.go"

	testCases := []struct {
		name   string
		change FileChange
		hunks  []Hunk
	}{
		{name: "zero owner", hunks: []Hunk{hunk}},
		{name: "empty hunks", change: change},
		{name: "zero hunk", change: change, hunks: []Hunk{{}}},
		{name: "other owner", change: change, hunks: []Hunk{otherHunk}},
		{name: "path mismatch", change: change, hunks: []Hunk{forgedPath}},
		{name: "duplicate hunk", change: change, hunks: []Hunk{hunk, hunk}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewLineMap(testCase.change, 3, 3, testCase.hunks); err == nil {
				t.Fatal("NewLineMap() error = nil, want validation error")
			}
		})
	}
}

func TestNewLineMapValidatesTotalsAndCoordinateBounds(t *testing.T) {
	additionChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 1)})
	addition := mustHunk(t, additionChange, 1, 0, 1, 1)
	deletionChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, nil)
	deletion := mustHunk(t, deletionChange, 1, 1, 1, 0)
	basePastEOF := mustHunk(t, additionChange, 5, 2, 1, 1)
	headPastEOFChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 5, 6)})
	headPastEOF := mustHunk(t, headPastEOFChange, 1, 1, 5, 2)
	baseCursorPastEOF := mustHunk(t, additionChange, 3, 0, 1, 1)
	headCursorPastEOF := mustHunk(t, deletionChange, 1, 1, 3, 0)
	maxInt := int(^uint(0) >> 1)

	testCases := []struct {
		name      string
		change    FileChange
		baseLines int
		headLines int
		hunks     []Hunk
	}{
		{name: "negative base total", change: additionChange, baseLines: -1, headLines: 1, hunks: []Hunk{addition}},
		{name: "negative head total", change: deletionChange, baseLines: 1, headLines: -1, hunks: []Hunk{deletion}},
		{name: "base total cursor overflow", change: additionChange, baseLines: maxInt, headLines: maxInt, hunks: []Hunk{addition}},
		{name: "head total cursor overflow", change: additionChange, baseLines: maxInt - 1, headLines: maxInt, hunks: []Hunk{addition}},
		{name: "base span past EOF", change: additionChange, baseLines: 5, headLines: 1, hunks: []Hunk{basePastEOF}},
		{name: "head span past EOF", change: headPastEOFChange, baseLines: 1, headLines: 5, hunks: []Hunk{headPastEOF}},
		{name: "base cursor past EOF", change: additionChange, baseLines: 1, headLines: 2, hunks: []Hunk{baseCursorPastEOF}},
		{name: "head cursor past EOF", change: deletionChange, baseLines: 2, headLines: 1, hunks: []Hunk{headCursorPastEOF}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewLineMap(testCase.change, testCase.baseLines, testCase.headLines, testCase.hunks); err == nil {
				t.Fatal("NewLineMap() error = nil, want bounds error")
			}
		})
	}

	largeChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 1)})
	large := mustLineMap(t, largeChange, maxInt-1, maxInt-1, []Hunk{mustHunk(t, largeChange, 1, 1, 1, 1)})
	assertBaseMapping(t, large, maxInt-1, maxInt-1, true)
	if _, _, err := large.MapBaseLineToHead(maxInt); err == nil {
		t.Fatal("MapBaseLineToHead(MaxInt) error = nil")
	}
}

func TestNewLineMapRejectsNonCanonicalOrderAndGaps(t *testing.T) {
	wideChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 5)})
	testCases := []struct {
		name      string
		baseLines int
		headLines int
		hunks     []Hunk
	}{
		{name: "reversed base order", baseLines: 7, headLines: 7, hunks: []Hunk{mustHunk(t, wideChange, 5, 1, 2, 1), mustHunk(t, wideChange, 2, 1, 5, 1)}},
		{name: "reversed head order", baseLines: 7, headLines: 7, hunks: []Hunk{mustHunk(t, wideChange, 2, 1, 5, 1), mustHunk(t, wideChange, 5, 1, 2, 1)}},
		{name: "overlap", baseLines: 7, headLines: 7, hunks: []Hunk{mustHunk(t, wideChange, 2, 2, 2, 2), mustHunk(t, wideChange, 3, 1, 5, 1)}},
		{name: "unequal prefix", baseLines: 7, headLines: 7, hunks: []Hunk{mustHunk(t, wideChange, 2, 1, 3, 1)}},
		{name: "unequal inter-hunk gap", baseLines: 7, headLines: 7, hunks: []Hunk{mustHunk(t, wideChange, 2, 1, 2, 1), mustHunk(t, wideChange, 5, 1, 4, 1)}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewLineMap(wideChange, testCase.baseLines, testCase.headLines, testCase.hunks); err == nil {
				t.Fatal("NewLineMap() error = nil, want ordering error")
			}
		})
	}

	adjacentChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 3)})
	adjacent := []Hunk{mustHunk(t, adjacentChange, 2, 1, 2, 1), mustHunk(t, adjacentChange, 3, 1, 3, 1)}
	if _, err := NewLineMap(adjacentChange, 5, 5, adjacent); err == nil {
		t.Fatal("NewLineMap(adjacent hunks) error = nil")
	}
}

func TestNewLineMapRejectsTailAndDeltaMismatch(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 3)})
	hunk := mustHunk(t, change, 2, 1, 2, 2)
	for _, totals := range [][2]int{{5, 5}, {5, 7}} {
		if _, err := NewLineMap(change, totals[0], totals[1], []Hunk{hunk}); err == nil {
			t.Fatalf("NewLineMap(%d, %d) error = nil, want tail or delta error", totals[0], totals[1])
		}
	}
}

func TestNewLineMapRequiresExactChangedRangeCoverage(t *testing.T) {
	missingChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{
		mustSourceRange(t, "main.go", 2, 2),
		mustSourceRange(t, "main.go", 5, 5),
	})
	partialChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 4)})
	testCases := []struct {
		name   string
		change FileChange
		hunk   Hunk
	}{
		{name: "missing range", change: missingChange, hunk: mustHunk(t, missingChange, 2, 1, 2, 1)},
		{name: "partial range", change: partialChange, hunk: mustHunk(t, partialChange, 2, 2, 2, 2)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewLineMap(testCase.change, 6, 6, []Hunk{testCase.hunk}); err == nil {
				t.Fatal("NewLineMap() error = nil, want coverage error")
			}
		})
	}

	deletionChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, nil)
	mustLineMap(t, deletionChange, 3, 2, []Hunk{mustHunk(t, deletionChange, 2, 1, 2, 0)})

	crossRangeChange := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{
		mustSourceRange(t, "main.go", 2, 2),
		mustSourceRange(t, "main.go", 5, 5),
	})
	crossRangeHunk, err := newHunkWithoutRangeCheck(crossRangeChange, 2, 1, 2, 4)
	if err != nil {
		t.Fatalf("newHunkWithoutRangeCheck() error = %v", err)
	}
	if _, err := NewLineMap(crossRangeChange, 6, 9, []Hunk{crossRangeHunk}); err == nil {
		t.Fatal("NewLineMap(cross-range hunk) error = nil")
	}
}

func TestLineMapIdentityUsesVersionedCanonicalPreimage(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 3, 5)})
	hunk := mustHunk(t, change, 3, 2, 3, 3)
	lineMap := mustLineMap(t, change, 8, 9, []Hunk{hunk})
	preimage := fmt.Sprintf(
		`{"contract":"open-trestle/line-map","schema_version":1,"file_change_identity":"%s","path":"main.go","base_line_count":8,"head_line_count":9,"hunk_identities":["%s"]}`,
		change.Identity(), hunk.Identity(),
	)
	digest := sha256.Sum256([]byte(preimage))
	want := hex.EncodeToString(digest[:])
	if lineMap.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", lineMap.Identity(), preimage)
	}
	second := mustLineMap(t, change, 8, 9, []Hunk{hunk})
	if second.Identity() != lineMap.Identity() {
		t.Fatalf("repeated identities = %q and %q", lineMap.Identity(), second.Identity())
	}
	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	otherChange := mustFileChange(t, "main.go", testBaseDigest, otherHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 3, 5)})
	other := mustLineMap(t, otherChange, 8, 9, []Hunk{mustHunk(t, otherChange, 3, 2, 3, 3)})
	if other.Identity() == lineMap.Identity() {
		t.Fatal("changing owner did not change identity")
	}
	larger := mustLineMap(t, change, 9, 10, []Hunk{hunk})
	if larger.Identity() == lineMap.Identity() {
		t.Fatal("changing totals did not change identity")
	}
}

func TestLineMapDoesNotExposeMutableHunks(t *testing.T) {
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 2, 2)})
	hunk := mustHunk(t, change, 2, 1, 2, 1)
	input := []Hunk{hunk}
	lineMap := mustLineMap(t, change, 3, 3, input)
	identity := lineMap.Identity()

	input[0] = Hunk{}
	returned := lineMap.Hunks()
	returned[0] = Hunk{}

	if lineMap.Identity() != identity || len(lineMap.Hunks()) != 1 || lineMap.Hunks()[0] != hunk {
		t.Fatal("caller or accessor mutation changed LineMap")
	}
	assertBaseMapping(t, lineMap, 3, 3, true)
}

func mustLineMap(t *testing.T, change FileChange, baseLineCount, headLineCount int, hunks []Hunk) LineMap {
	t.Helper()
	lineMap, err := NewLineMap(change, baseLineCount, headLineCount, hunks)
	if err != nil {
		t.Fatalf("NewLineMap() error = %v", err)
	}
	return lineMap
}

func assertBaseMapping(t *testing.T, lineMap LineMap, baseLine, wantHead int, wantExact bool) {
	t.Helper()
	gotHead, exact, err := lineMap.MapBaseLineToHead(baseLine)
	if err != nil {
		t.Fatalf("MapBaseLineToHead(%d) error = %v", baseLine, err)
	}
	if gotHead != wantHead || exact != wantExact {
		t.Fatalf("MapBaseLineToHead(%d) = (%d, %t), want (%d, %t)", baseLine, gotHead, exact, wantHead, wantExact)
	}
}

func assertHeadMapping(t *testing.T, lineMap LineMap, headLine, wantBase int, wantExact bool) {
	t.Helper()
	gotBase, exact, err := lineMap.MapHeadLineToBase(headLine)
	if err != nil {
		t.Fatalf("MapHeadLineToBase(%d) error = %v", headLine, err)
	}
	if gotBase != wantBase || exact != wantExact {
		t.Fatalf("MapHeadLineToBase(%d) = (%d, %t), want (%d, %t)", headLine, gotBase, exact, wantBase, wantExact)
	}
}
