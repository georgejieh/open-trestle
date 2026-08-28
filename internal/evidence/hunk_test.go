package evidence

import (
	"strings"
	"testing"
)

func TestNewHunkCreatesNormalizedKinds(t *testing.T) {
	modified := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 20)})
	deletionOnly := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, nil)
	testCases := []struct {
		name          string
		change        FileChange
		baseStartLine int
		baseLineCount int
		headStartLine int
		headLineCount int
		wantKind      HunkKind
	}{
		{name: "modification", change: modified, baseStartLine: 4, baseLineCount: 2, headStartLine: 4, headLineCount: 3, wantKind: HunkKindModification},
		{name: "addition", change: modified, baseStartLine: 1, baseLineCount: 0, headStartLine: 1, headLineCount: 2, wantKind: HunkKindAddition},
		{name: "deletion", change: deletionOnly, baseStartLine: 7, baseLineCount: 3, headStartLine: 7, headLineCount: 0, wantKind: HunkKindDeletion},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			hunk, err := NewHunk(testCase.change, testCase.baseStartLine, testCase.baseLineCount, testCase.headStartLine, testCase.headLineCount)
			if err != nil {
				t.Fatalf("NewHunk() error = %v", err)
			}
			if hunk.FileChangeIdentity() != testCase.change.Identity() || hunk.Path() != testCase.change.Path() {
				t.Fatalf("Hunk owner = (%q, %q), want (%q, %q)", hunk.FileChangeIdentity(), hunk.Path(), testCase.change.Identity(), testCase.change.Path())
			}
			if hunk.BaseStartLine() != testCase.baseStartLine || hunk.BaseLineCount() != testCase.baseLineCount || hunk.HeadStartLine() != testCase.headStartLine || hunk.HeadLineCount() != testCase.headLineCount {
				t.Fatalf("Hunk coordinates do not match constructor values: %#v", hunk)
			}
			if hunk.Kind() != testCase.wantKind {
				t.Fatalf("Kind() = %q, want %q", hunk.Kind(), testCase.wantKind)
			}
			if len(hunk.Identity()) != 64 || hunk.Identity() != strings.ToLower(hunk.Identity()) {
				t.Fatalf("Identity() = %q, want lowercase SHA-256", hunk.Identity())
			}
		})
	}
}

func TestNewHunkRetainsZeroCountCursorPositions(t *testing.T) {
	modified := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 20)})
	deletionOnly := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, nil)
	for _, cursor := range []int{1, 7, 20} {
		addition, err := NewHunk(modified, cursor, 0, 1, 1)
		if err != nil {
			t.Fatalf("NewHunk(addition cursor %d) error = %v", cursor, err)
		}
		if addition.BaseStartLine() != cursor || addition.BaseLineCount() != 0 {
			t.Fatalf("addition cursor = (%d, %d), want (%d, 0)", addition.BaseStartLine(), addition.BaseLineCount(), cursor)
		}

		deletion, err := NewHunk(deletionOnly, 1, 1, cursor, 0)
		if err != nil {
			t.Fatalf("NewHunk(deletion cursor %d) error = %v", cursor, err)
		}
		if deletion.HeadStartLine() != cursor || deletion.HeadLineCount() != 0 {
			t.Fatalf("deletion cursor = (%d, %d), want (%d, 0)", deletion.HeadStartLine(), deletion.HeadLineCount(), cursor)
		}
	}
}

func TestNewHunkRejectsInvalidCoordinatesAndOwner(t *testing.T) {
	owner := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 20)})
	maxInt := int(^uint(0) >> 1)
	testCases := []struct {
		name          string
		change        FileChange
		baseStartLine int
		baseLineCount int
		headStartLine int
		headLineCount int
	}{
		{name: "zero owner", baseStartLine: 1, baseLineCount: 1, headStartLine: 1, headLineCount: 1},
		{name: "zero base start", change: owner, baseLineCount: 1, headStartLine: 1, headLineCount: 1},
		{name: "zero head start", change: owner, baseStartLine: 1, baseLineCount: 1, headLineCount: 1},
		{name: "negative base count", change: owner, baseStartLine: 1, baseLineCount: -1, headStartLine: 1, headLineCount: 1},
		{name: "negative head count", change: owner, baseStartLine: 1, baseLineCount: 1, headStartLine: 1, headLineCount: -1},
		{name: "empty edit", change: owner, baseStartLine: 1, headStartLine: 1},
		{name: "base end overflow", change: owner, baseStartLine: maxInt, baseLineCount: 2, headStartLine: 1, headLineCount: 1},
		{name: "head end overflow", change: owner, baseStartLine: 1, baseLineCount: 1, headStartLine: maxInt, headLineCount: 2},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewHunk(testCase.change, testCase.baseStartLine, testCase.baseLineCount, testCase.headStartLine, testCase.headLineCount); err == nil {
				t.Fatal("NewHunk() error = nil, want validation error")
			}
		})
	}
}

func TestNewHunkRequiresHeadSpanWithinOneChangedRange(t *testing.T) {
	owner := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{
		mustSourceRange(t, "main.go", 2, 4),
		mustSourceRange(t, "main.go", 8, 10),
	})
	testCases := []struct {
		name          string
		headStartLine int
		headLineCount int
		wantError     bool
	}{
		{name: "first range", headStartLine: 2, headLineCount: 3},
		{name: "second range", headStartLine: 9, headLineCount: 2},
		{name: "before ranges", headStartLine: 1, headLineCount: 1, wantError: true},
		{name: "between ranges", headStartLine: 6, headLineCount: 1, wantError: true},
		{name: "crosses ranges", headStartLine: 4, headLineCount: 5, wantError: true},
		{name: "after ranges", headStartLine: 11, headLineCount: 1, wantError: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewHunk(owner, 1, 1, testCase.headStartLine, testCase.headLineCount)
			if testCase.wantError && err == nil {
				t.Fatal("NewHunk() error = nil, want containment error")
			}
			if !testCase.wantError && err != nil {
				t.Fatalf("NewHunk() error = %v", err)
			}
		})
	}
}

func TestHunkIdentityBindsOwnerAndCoordinates(t *testing.T) {
	owner := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 20)})
	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	otherOwner := mustFileChange(t, "main.go", testBaseDigest, otherHeadDigest, []SourceRange{mustSourceRange(t, "main.go", 1, 20)})
	otherPathOwner := mustFileChange(t, "nested/main.go", testBaseDigest, testHeadDigest, []SourceRange{mustSourceRange(t, "nested/main.go", 1, 20)})
	base := mustHunk(t, owner, 4, 2, 4, 3)
	repeated := mustHunk(t, owner, 4, 2, 4, 3)
	if base.Identity() != repeated.Identity() {
		t.Fatalf("identical Hunk identities = %q and %q, want equality", base.Identity(), repeated.Identity())
	}

	variants := []Hunk{
		mustHunk(t, otherOwner, 4, 2, 4, 3),
		mustHunk(t, otherPathOwner, 4, 2, 4, 3),
		mustHunk(t, owner, 3, 2, 4, 3),
		mustHunk(t, owner, 4, 3, 4, 3),
		mustHunk(t, owner, 4, 2, 3, 3),
		mustHunk(t, owner, 4, 2, 4, 4),
	}
	for i, variant := range variants {
		if variant.Identity() == base.Identity() {
			t.Fatalf("variant %d identity = %q, want change from %q", i, variant.Identity(), base.Identity())
		}
	}
}

func mustHunk(t *testing.T, change FileChange, baseStartLine, baseLineCount, headStartLine, headLineCount int) Hunk {
	t.Helper()
	hunk, err := NewHunk(change, baseStartLine, baseLineCount, headStartLine, headLineCount)
	if err != nil {
		t.Fatalf("NewHunk() error = %v", err)
	}
	return hunk
}
