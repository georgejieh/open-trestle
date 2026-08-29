package evidence

import (
	"bytes"
	"errors"
	"testing"
)

func TestGenerateUnifiedFileDiffExactPatchesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		path string
		base []byte
		head []byte
		want string
	}{
		{name: "replacement", path: "file.txt", base: []byte("one\nold\nthree\n"), head: []byte("one\nnew\nthree\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -2,1 +2,1 @@\n-old\n+new\n"},
		{name: "insertion", path: "file.txt", base: []byte("a\nb\n"), head: []byte("a\nx\nb\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -1,0 +2,1 @@\n+x\n"},
		{name: "deletion", path: "file.txt", base: []byte("a\nx\nb\n"), head: []byte("a\nb\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -2,1 +1,0 @@\n-x\n"},
		{name: "empty base", path: "file.txt", base: []byte{}, head: []byte("a\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -0,0 +1,1 @@\n+a\n"},
		{name: "empty head", path: "file.txt", base: []byte("a\n"), head: []byte{}, want: "--- a/file.txt\n+++ b/file.txt\n@@ -1,1 +0,0 @@\n-a\n"},
		{name: "separated hunks", path: "file.txt", base: []byte("a\nold\nmiddle\nold2\nz\n"), head: []byte("a\nnew\nmiddle\nnew2\nz\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -2,1 +2,1 @@\n-old\n+new\n@@ -4,1 +4,1 @@\n-old2\n+new2\n"},
		{name: "missing final LF", path: "file.txt", base: []byte("a"), head: []byte("a\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -1,1 +1,1 @@\n-a\n\\ No newline at end of file\n+a\n"},
		{name: "CRLF", path: "file.txt", base: []byte("a\r\nold\r\n"), head: []byte("a\r\nnew\r\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -2,1 +2,1 @@\n-old\r\n+new\r\n"},
		{name: "record prefixes", path: "file.txt", base: []byte("+plus\n-minus\n\\slash\n"), head: []byte("+plus\nchanged\n\\slash\n"), want: "--- a/file.txt\n+++ b/file.txt\n@@ -2,1 +2,1 @@\n--minus\n+changed\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseBefore := append([]byte(nil), test.base...)
			headBefore := append([]byte(nil), test.head...)
			patch, err := GenerateUnifiedFileDiff(test.path, test.base, test.head)
			if err != nil || string(patch) != test.want {
				t.Fatalf("GenerateUnifiedFileDiff() = (%q, %v), want %q", patch, err, test.want)
			}
			change, lineMap, err := ParseUnifiedFileDiff(test.path, test.base, test.head, patch)
			if err != nil || change.Identity() == "" || lineMap.Identity() == "" || change.BaseDigest() == change.HeadDigest() || lineMap.Path() != test.path {
				t.Fatalf("ParseUnifiedFileDiff() = (%#v, %#v, %v)", change, lineMap, err)
			}
			if !bytes.Equal(test.base, baseBefore) || !bytes.Equal(test.head, headBefore) {
				t.Fatal("generator mutated input")
			}
			repeated, err := GenerateUnifiedFileDiff(test.path, test.base, test.head)
			if err != nil || !bytes.Equal(repeated, patch) {
				t.Fatalf("repeat = (%q, %v), want %q", repeated, err, patch)
			}
			patch[0] = 'X'
			again, err := GenerateUnifiedFileDiff(test.path, test.base, test.head)
			if err != nil || again[0] != '-' {
				t.Fatal("returned patch mutation affected a later call")
			}
		})
	}
}

func TestGenerateUnifiedFileDiffBuildsExactEvidenceCoordinates(t *testing.T) {
	base := []byte("one\nold\nthree\n")
	head := []byte("one\nnew\nthree\n")
	patch, err := GenerateUnifiedFileDiff("file.txt", base, head)
	if err != nil {
		t.Fatal(err)
	}
	change, lineMap, err := ParseUnifiedFileDiff("file.txt", base, head, patch)
	if err != nil {
		t.Fatal(err)
	}
	ranges := change.ChangedRanges()
	hunks := lineMap.Hunks()
	if len(ranges) != 1 || ranges[0].StartLine() != 2 || ranges[0].EndLine() != 2 || lineMap.BaseLineCount() != 3 || lineMap.HeadLineCount() != 3 || len(hunks) != 1 || hunks[0].BaseStartLine() != 2 || hunks[0].BaseLineCount() != 1 || hunks[0].HeadStartLine() != 2 || hunks[0].HeadLineCount() != 1 {
		t.Fatalf("evidence = %#v %#v", change, lineMap)
	}
	if mapped, exact, err := lineMap.MapBaseLineToHead(1); err != nil || !exact || mapped != 1 {
		t.Fatalf("MapBaseLineToHead(1) = (%d, %v, %v)", mapped, exact, err)
	}
	if mapped, exact, err := lineMap.MapBaseLineToHead(2); err != nil || exact || mapped != 0 {
		t.Fatalf("MapBaseLineToHead(2) = (%d, %v, %v)", mapped, exact, err)
	}
	if mapped, exact, err := lineMap.MapHeadLineToBase(3); err != nil || !exact || mapped != 3 {
		t.Fatalf("MapHeadLineToBase(3) = (%d, %v, %v)", mapped, exact, err)
	}
}

func TestGenerateUnifiedFileDiffSmallInputsAlwaysRoundTrip(t *testing.T) {
	contents := [][]byte{
		{}, []byte("a"), []byte("a\n"), []byte("b\n"), []byte("a\nb\n"),
		[]byte("b\na\n"), []byte("a\na\n"), []byte("a\n\n"), []byte("\n"),
	}
	for baseIndex, base := range contents {
		for headIndex, head := range contents {
			if bytes.Equal(base, head) {
				continue
			}
			patch, err := GenerateUnifiedFileDiff("file", base, head)
			if err != nil {
				t.Fatalf("case %d/%d generation error = %v", baseIndex, headIndex, err)
			}
			if _, _, err := ParseUnifiedFileDiff("file", base, head, patch); err != nil {
				t.Fatalf("case %d/%d parse error = %v, patch %q", baseIndex, headIndex, err, patch)
			}
		}
	}
}

func TestGenerateUnifiedFileDiffUsesDeletionFirstTieBreak(t *testing.T) {
	base := []byte("a\nb\na\n")
	head := []byte("a\na\nb\n")
	patch, err := GenerateUnifiedFileDiff("repeat.txt", base, head)
	if err != nil {
		t.Fatal(err)
	}
	const want = "--- a/repeat.txt\n+++ b/repeat.txt\n@@ -2,1 +1,0 @@\n-b\n@@ -3,0 +3,1 @@\n+b\n"
	if string(patch) != want {
		t.Fatalf("patch = %q, want %q", patch, want)
	}
	if _, _, err := ParseUnifiedFileDiff("repeat.txt", base, head, patch); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateUnifiedFileDiffRejectsUnsupportedInput(t *testing.T) {
	oversized := make([]byte, maxUnifiedDiffContentBytes+1)
	tooManyLines := bytes.Repeat([]byte("\n"), maxUnifiedDiffPhysicalLines+1)
	tests := []struct {
		name string
		path string
		base []byte
		head []byte
		want error
	}{
		{name: "no change", path: "file", base: []byte("same"), head: []byte("same"), want: UnifiedDiffGenerationNoChange},
		{name: "invalid path", path: "../file", base: []byte("a"), head: []byte("b"), want: UnifiedDiffGenerationUnsupportedContent},
		{name: "base NUL", path: "file", base: []byte{'a', 0}, head: []byte("b"), want: UnifiedDiffGenerationUnsupportedContent},
		{name: "head NUL", path: "file", base: []byte("a"), head: []byte{'b', 0}, want: UnifiedDiffGenerationUnsupportedContent},
		{name: "base bytes", path: "file", base: oversized, head: []byte("b"), want: UnifiedDiffGenerationResourceLimit},
		{name: "head bytes", path: "file", base: []byte("a"), head: oversized, want: UnifiedDiffGenerationResourceLimit},
		{name: "base lines", path: "file", base: tooManyLines, head: []byte("b"), want: UnifiedDiffGenerationResourceLimit},
		{name: "head lines", path: "file", base: []byte("a"), head: tooManyLines, want: UnifiedDiffGenerationResourceLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patch, err := GenerateUnifiedFileDiff(test.path, test.base, test.head)
			if !errors.Is(err, test.want) || patch != nil {
				t.Fatalf("GenerateUnifiedFileDiff() = (%q, %v), want nil, %v", patch, err, test.want)
			}
		})
	}
}

func TestGenerateUnifiedFileDiffEnforcesPrivateBudgets(t *testing.T) {
	base := []byte("a\nold\nmiddle\nold2\n")
	head := []byte("a\nnew\nmiddle\nnew2\n")
	standard := standardUnifiedDiffGenerationLimits()
	tests := []struct {
		name   string
		limits unifiedDiffGenerationLimits
	}{
		{name: "content", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxContentBytes = 3 })},
		{name: "lines", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxLines = 2 })},
		{name: "edit distance", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxEditDistance = 1 })},
		{name: "work", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxWork = 1 })},
		{name: "trace", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxTraceCells = 1 })},
		{name: "hunks", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxHunks = 1 })},
		{name: "patch", limits: withGenerationLimit(standard, func(l *unifiedDiffGenerationLimits) { l.maxPatchBytes = 10 })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			patch, err := generateUnifiedFileDiff("file", base, head, test.limits)
			if !errors.Is(err, UnifiedDiffGenerationResourceLimit) || patch != nil {
				t.Fatalf("generateUnifiedFileDiff() = (%q, %v)", patch, err)
			}
		})
	}
}

func TestGenerateUnifiedFileDiffTerminatesAtEditBudget(t *testing.T) {
	var base, head bytes.Buffer
	for i := 0; i < maxUnifiedDiffGenerationEditDistance+1; i++ {
		base.WriteString("base\n")
		head.WriteString("head\n")
	}
	patch, err := GenerateUnifiedFileDiff("file", base.Bytes(), head.Bytes())
	if !errors.Is(err, UnifiedDiffGenerationResourceLimit) || patch != nil {
		t.Fatalf("GenerateUnifiedFileDiff() = (%q, %v)", patch, err)
	}
}

func withGenerationLimit(limits unifiedDiffGenerationLimits, alter func(*unifiedDiffGenerationLimits)) unifiedDiffGenerationLimits {
	alter(&limits)
	return limits
}
