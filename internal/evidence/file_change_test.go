package evidence

import (
	"strings"
	"testing"
)

const (
	testBaseDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHeadDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestNewFileChangeCreatesStableModifiedFileDescriptor(t *testing.T) {
	ranges := []SourceRange{
		mustSourceRange(t, "main.go", 2, 3),
		mustSourceRange(t, "main.go", 7, 9),
	}

	first, err := NewFileChange("main.go", testBaseDigest, testHeadDigest, ranges)
	if err != nil {
		t.Fatalf("NewFileChange() error = %v", err)
	}
	second, err := NewFileChange("main.go", testBaseDigest, testHeadDigest, ranges)
	if err != nil {
		t.Fatalf("second NewFileChange() error = %v", err)
	}

	if first.Path() != "main.go" || first.BaseDigest() != testBaseDigest || first.HeadDigest() != testHeadDigest {
		t.Fatalf("FileChange fields = (%q, %q, %q), want supplied values", first.Path(), first.BaseDigest(), first.HeadDigest())
	}
	if len(first.Identity()) != 64 || first.Identity() != strings.ToLower(first.Identity()) || first.Identity() != second.Identity() {
		t.Fatalf("FileChange identities = %q and %q, want stable lowercase SHA-256", first.Identity(), second.Identity())
	}
	if got := first.ChangedRanges(); len(got) != 2 || got[0] != ranges[0] || got[1] != ranges[1] {
		t.Fatalf("ChangedRanges() = %#v, want %#v", got, ranges)
	}
}

func TestFileChangeIdentityBindsEveryField(t *testing.T) {
	baseRanges := []SourceRange{mustSourceRange(t, "main.go", 2, 3)}
	base := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, baseRanges)
	otherBaseDigest := "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	testCases := []struct {
		name       string
		path       string
		baseDigest string
		headDigest string
		ranges     []SourceRange
	}{
		{name: "path", path: "nested/main.go", baseDigest: testBaseDigest, headDigest: testHeadDigest, ranges: []SourceRange{mustSourceRange(t, "nested/main.go", 2, 3)}},
		{name: "base digest", path: "main.go", baseDigest: otherBaseDigest, headDigest: testHeadDigest, ranges: baseRanges},
		{name: "head digest", path: "main.go", baseDigest: testBaseDigest, headDigest: otherHeadDigest, ranges: baseRanges},
		{name: "range start", path: "main.go", baseDigest: testBaseDigest, headDigest: testHeadDigest, ranges: []SourceRange{mustSourceRange(t, "main.go", 1, 3)}},
		{name: "range end", path: "main.go", baseDigest: testBaseDigest, headDigest: testHeadDigest, ranges: []SourceRange{mustSourceRange(t, "main.go", 2, 4)}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			changed := mustFileChange(t, testCase.path, testCase.baseDigest, testCase.headDigest, testCase.ranges)
			if changed.Identity() == base.Identity() {
				t.Fatalf("changed identity = %q, want change from %q", changed.Identity(), base.Identity())
			}
		})
	}
}

func TestNewFileChangeRejectsInvalidDigests(t *testing.T) {
	ranges := []SourceRange{mustSourceRange(t, "main.go", 1, 1)}
	testCases := []struct {
		name       string
		baseDigest string
		headDigest string
	}{
		{name: "empty base", headDigest: testHeadDigest},
		{name: "short base", baseDigest: "0123", headDigest: testHeadDigest},
		{name: "non-hex base", baseDigest: strings.Repeat("z", 64), headDigest: testHeadDigest},
		{name: "uppercase base", baseDigest: strings.ToUpper(testBaseDigest), headDigest: testHeadDigest},
		{name: "empty head", baseDigest: testBaseDigest},
		{name: "short head", baseDigest: testBaseDigest, headDigest: "0123"},
		{name: "non-hex head", baseDigest: testBaseDigest, headDigest: strings.Repeat("z", 64)},
		{name: "uppercase head", baseDigest: testBaseDigest, headDigest: strings.ToUpper(testHeadDigest)},
		{name: "equal digests", baseDigest: testBaseDigest, headDigest: testBaseDigest},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewFileChange("main.go", testCase.baseDigest, testCase.headDigest, ranges); err == nil {
				t.Fatal("NewFileChange() error = nil, want digest validation error")
			}
		})
	}
}

func TestNewFileChangeValidatesPathAndRanges(t *testing.T) {
	mainRange := mustSourceRange(t, "main.go", 1, 2)
	for _, sourcePath := range []string{"", "/main.go", "../main.go", "nested/../main.go", `nested\main.go`, "bad\x00.go", "bad\nname.go", "bad\u202ename.go"} {
		t.Run("path "+sourcePath, func(t *testing.T) {
			if _, err := NewFileChange(sourcePath, testBaseDigest, testHeadDigest, []SourceRange{mainRange}); err == nil {
				t.Fatal("NewFileChange() error = nil, want path validation error")
			}
		})
	}

	testCases := []struct {
		name   string
		ranges []SourceRange
	}{
		{name: "zero value", ranges: []SourceRange{{}}},
		{name: "path mismatch", ranges: []SourceRange{mustSourceRange(t, "other.go", 1, 1)}},
		{name: "unsorted", ranges: []SourceRange{mustSourceRange(t, "main.go", 5, 5), mustSourceRange(t, "main.go", 2, 2)}},
		{name: "duplicate", ranges: []SourceRange{mustSourceRange(t, "main.go", 2, 3), mustSourceRange(t, "main.go", 2, 3)}},
		{name: "overlap", ranges: []SourceRange{mustSourceRange(t, "main.go", 2, 4), mustSourceRange(t, "main.go", 4, 5)}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewFileChange("main.go", testBaseDigest, testHeadDigest, testCase.ranges); err == nil {
				t.Fatal("NewFileChange() error = nil, want range validation error")
			}
		})
	}
}

func TestNewFileChangeAcceptsDeletionOnlyChange(t *testing.T) {
	withNil, err := NewFileChange("main.go", testBaseDigest, testHeadDigest, nil)
	if err != nil {
		t.Fatalf("NewFileChange(nil ranges) error = %v", err)
	}
	withEmpty, err := NewFileChange("main.go", testBaseDigest, testHeadDigest, []SourceRange{})
	if err != nil {
		t.Fatalf("NewFileChange(empty ranges) error = %v", err)
	}
	if withNil.Identity() != withEmpty.Identity() {
		t.Fatalf("deletion-only identities = %q and %q, want equality", withNil.Identity(), withEmpty.Identity())
	}
	if len(withNil.ChangedRanges()) != 0 || len(withEmpty.ChangedRanges()) != 0 {
		t.Fatalf("deletion-only ranges = %#v and %#v, want empty", withNil.ChangedRanges(), withEmpty.ChangedRanges())
	}
	returned := withNil.ChangedRanges()
	returned = append(returned, mustSourceRange(t, "main.go", 1, 1))
	if len(withNil.ChangedRanges()) != 0 {
		t.Fatal("mutating returned ranges changed deletion-only FileChange")
	}
}

func TestNewFileChangeCanonicalizesAdjacentRanges(t *testing.T) {
	partitioned := []SourceRange{
		mustSourceRange(t, "main.go", 2, 2),
		mustSourceRange(t, "main.go", 3, 4),
		mustSourceRange(t, "main.go", 5, 5),
	}
	combined := []SourceRange{mustSourceRange(t, "main.go", 2, 5)}

	first := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, partitioned)
	second := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, combined)

	if first.Identity() != second.Identity() {
		t.Fatalf("adjacent partition identities = %q and %q, want equality", first.Identity(), second.Identity())
	}
	if ranges := first.ChangedRanges(); len(ranges) != 1 || ranges[0] != combined[0] {
		t.Fatalf("ChangedRanges() = %#v, want %#v", ranges, combined)
	}
}

func TestFileChangeDoesNotExposeMutableRanges(t *testing.T) {
	ranges := []SourceRange{mustSourceRange(t, "main.go", 2, 3)}
	change := mustFileChange(t, "main.go", testBaseDigest, testHeadDigest, ranges)
	identity := change.Identity()

	ranges[0] = SourceRange{}
	returned := change.ChangedRanges()
	returned[0] = SourceRange{}

	if change.ChangedRanges()[0].Path() != "main.go" || change.Identity() != identity {
		t.Fatal("caller or accessor mutation changed FileChange")
	}
}

func TestNewFileChangeAcceptsPrintableUnicodePath(t *testing.T) {
	path := "docs/naïve file.go"
	ranges := []SourceRange{mustSourceRange(t, path, 1, 1)}
	if _, err := NewFileChange(path, testBaseDigest, testHeadDigest, ranges); err != nil {
		t.Fatalf("NewFileChange() error = %v", err)
	}
}

func mustSourceRange(t *testing.T, path string, startLine, endLine int) SourceRange {
	t.Helper()
	sourceRange, err := NewSourceRange(path, startLine, endLine)
	if err != nil {
		t.Fatalf("NewSourceRange() error = %v", err)
	}
	return sourceRange
}

func mustFileChange(t *testing.T, path, baseDigest, headDigest string, ranges []SourceRange) FileChange {
	t.Helper()
	change, err := NewFileChange(path, baseDigest, headDigest, ranges)
	if err != nil {
		t.Fatalf("NewFileChange() error = %v", err)
	}
	return change
}
