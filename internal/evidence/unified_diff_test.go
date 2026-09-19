package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func TestParseUnifiedFileDiffBuildsReplacementEvidence(t *testing.T) {
	base := []byte("a\nb\nc\nd\n")
	head := []byte("a\nB\nc\nd\n")
	patch := unifiedPatch("main.go", "@@ -1,3 +1,3 @@ handler\n a\n-b\n+B\n c\n")
	change, lineMap := mustParseUnifiedFileDiff(t, "main.go", base, head, patch)

	if change.Path() != "main.go" || change.BaseDigest() != testContentDigest(base) || change.HeadDigest() != testContentDigest(head) {
		t.Fatalf("FileChange fields = (%q, %q, %q)", change.Path(), change.BaseDigest(), change.HeadDigest())
	}
	if ranges := change.ChangedRanges(); len(ranges) != 1 || ranges[0] != mustSourceRange(t, "main.go", 2, 2) {
		t.Fatalf("ChangedRanges() = %#v, want main.go:2", ranges)
	}
	if lineMap.FileChangeIdentity() != change.Identity() || lineMap.BaseLineCount() != 4 || lineMap.HeadLineCount() != 4 {
		t.Fatalf("LineMap owner/totals = (%q, %d, %d)", lineMap.FileChangeIdentity(), lineMap.BaseLineCount(), lineMap.HeadLineCount())
	}
	hunks := lineMap.Hunks()
	if len(hunks) != 1 || hunks[0].BaseStartLine() != 2 || hunks[0].BaseLineCount() != 1 || hunks[0].HeadStartLine() != 2 || hunks[0].HeadLineCount() != 1 {
		t.Fatalf("Hunks() = %#v, want one replacement at line 2", hunks)
	}
	assertBaseMapping(t, lineMap, 1, 1, true)
	assertBaseMapping(t, lineMap, 2, 0, false)
	assertBaseMapping(t, lineMap, 4, 4, true)
	assertHeadMapping(t, lineMap, 2, 0, false)
}

func TestParseUnifiedFileDiffNormalizesInsertionsAndDeletions(t *testing.T) {
	testCases := []struct {
		name      string
		base      string
		head      string
		hunk      string
		baseStart int
		baseCount int
		headStart int
		headCount int
	}{
		{name: "insert beginning", base: "b\nc\n", head: "a\nb\nc\n", hunk: "@@ -0,0 +1 @@\n+a\n", baseStart: 1, headStart: 1, headCount: 1},
		{name: "insert middle", base: "a\nc\n", head: "a\nb\nc\n", hunk: "@@ -1,0 +2 @@\n+b\n", baseStart: 2, headStart: 2, headCount: 1},
		{name: "insert end", base: "a\nb\n", head: "a\nb\nc\n", hunk: "@@ -2,0 +3 @@\n+c\n", baseStart: 3, headStart: 3, headCount: 1},
		{name: "delete beginning", base: "a\nb\nc\n", head: "b\nc\n", hunk: "@@ -1 +0,0 @@\n-a\n", baseStart: 1, baseCount: 1, headStart: 1},
		{name: "delete middle", base: "a\nb\nc\n", head: "a\nc\n", hunk: "@@ -2 +1,0 @@\n-b\n", baseStart: 2, baseCount: 1, headStart: 2},
		{name: "delete end", base: "a\nb\nc\n", head: "a\nb\n", hunk: "@@ -3 +2,0 @@\n-c\n", baseStart: 3, baseCount: 1, headStart: 3},
		{name: "empty to nonempty", head: "a\nb\n", hunk: "@@ -0,0 +1,2 @@\n+a\n+b\n", baseStart: 1, headStart: 1, headCount: 2},
		{name: "nonempty to empty", base: "a\nb\n", hunk: "@@ -1,2 +0,0 @@\n-a\n-b\n", baseStart: 1, baseCount: 2, headStart: 1},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, lineMap := mustParseUnifiedFileDiff(t, "main.go", []byte(testCase.base), []byte(testCase.head), unifiedPatch("main.go", testCase.hunk))
			hunks := lineMap.Hunks()
			if len(hunks) != 1 {
				t.Fatalf("len(Hunks()) = %d, want 1", len(hunks))
			}
			hunk := hunks[0]
			if hunk.BaseStartLine() != testCase.baseStart || hunk.BaseLineCount() != testCase.baseCount || hunk.HeadStartLine() != testCase.headStart || hunk.HeadLineCount() != testCase.headCount {
				t.Fatalf("Hunk coordinates = (%d, %d, %d, %d)", hunk.BaseStartLine(), hunk.BaseLineCount(), hunk.HeadStartLine(), hunk.HeadLineCount())
			}
		})
	}
}

func TestParseUnifiedFileDiffNormalizesMultipleEditRuns(t *testing.T) {
	base := []byte("a\nb\nc\nd\ne\n")
	head := []byte("a\nB\nc\nD\ne\n")
	oneHeader := unifiedPatch("main.go", "@@ -1,5 +1,5 @@\n a\n-b\n+B\n c\n-d\n+D\n e\n")
	multipleHeaders := unifiedPatch("main.go", "@@ -2 +2 @@\n-b\n+B\n@@ -4 +4 @@\n-d\n+D\n")
	change, lineMap := mustParseUnifiedFileDiff(t, "main.go", base, head, oneHeader)
	otherChange, otherMap := mustParseUnifiedFileDiff(t, "main.go", base, head, multipleHeaders)

	if change.Identity() != otherChange.Identity() || lineMap.Identity() != otherMap.Identity() {
		t.Fatalf("equivalent patch identities differ: (%q, %q), (%q, %q)", change.Identity(), lineMap.Identity(), otherChange.Identity(), otherMap.Identity())
	}
	hunks := lineMap.Hunks()
	if len(hunks) != 2 || hunks[0].HeadStartLine() != 2 || hunks[1].HeadStartLine() != 4 {
		t.Fatalf("Hunks() = %#v, want edits at lines 2 and 4", hunks)
	}
	assertBaseMapping(t, lineMap, 3, 3, true)
	assertBaseMapping(t, lineMap, 4, 0, false)
}

func TestParseUnifiedFileDiffMergesAdjacentRawEditRuns(t *testing.T) {
	base := []byte("a\nb\n")
	head := []byte("A\nB\n")
	patch := unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+A\n@@ -2 +2 @@\n-b\n+B\n")
	change, lineMap := mustParseUnifiedFileDiff(t, "main.go", base, head, patch)
	hunks := lineMap.Hunks()
	if len(hunks) != 1 || hunks[0].BaseStartLine() != 1 || hunks[0].BaseLineCount() != 2 || hunks[0].HeadStartLine() != 1 || hunks[0].HeadLineCount() != 2 {
		t.Fatalf("Hunks() = %#v, want one merged replacement", hunks)
	}
	if ranges := change.ChangedRanges(); len(ranges) != 1 || ranges[0] != mustSourceRange(t, "main.go", 1, 2) {
		t.Fatalf("ChangedRanges() = %#v, want 1-2", ranges)
	}
}

func TestParseUnifiedFileDiffCanonicalizesEquivalentSyntax(t *testing.T) {
	base := []byte("a\nb\nc\n")
	head := []byte("a\nB\nc\n")
	patches := [][]byte{
		unifiedPatch("main.go", "@@ -2 +2 @@\n-b\n+B\n"),
		unifiedPatch("main.go", "@@ -2,1 +2,1 @@ section\n-b\n+B\n"),
		unifiedPatch("main.go", "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"),
	}
	firstChange, firstMap := mustParseUnifiedFileDiff(t, "main.go", base, head, patches[0])
	for i, patch := range patches[1:] {
		change, lineMap := mustParseUnifiedFileDiff(t, "main.go", base, head, patch)
		if change.Identity() != firstChange.Identity() || lineMap.Identity() != firstMap.Identity() || lineMap.Hunks()[0].Identity() != firstMap.Hunks()[0].Identity() {
			t.Fatalf("patch %d produced different evidence identities", i+1)
		}
	}
}

func TestParseUnifiedFileDiffHandlesTerminalNewlines(t *testing.T) {
	testCases := []struct {
		name string
		base string
		head string
		hunk string
	}{
		{
			name: "both missing", base: "a\nold", head: "a\nnew",
			hunk: "@@ -2 +2 @@\n-old\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n",
		},
		{
			name: "add terminal newline", base: "a", head: "a\n",
			hunk: "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+a\n",
		},
		{
			name: "remove terminal newline", base: "a\n", head: "a",
			hunk: "@@ -1 +1 @@\n-a\n+a\n\\ No newline at end of file\n",
		},
		{
			name: "missing newline context", base: "a\nz", head: "A\nz",
			hunk: "@@ -1,2 +1,2 @@\n-a\n+A\n z\n\\ No newline at end of file\n",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, lineMap := mustParseUnifiedFileDiff(t, "main.go", []byte(testCase.base), []byte(testCase.head), unifiedPatch("main.go", testCase.hunk))
			if lineMap.BaseLineCount() != physicalLineCount([]byte(testCase.base)) || lineMap.HeadLineCount() != physicalLineCount([]byte(testCase.head)) {
				t.Fatalf("LineMap totals = (%d, %d)", lineMap.BaseLineCount(), lineMap.HeadLineCount())
			}
		})
	}
}

func TestParseUnifiedFileDiffAcceptsUnicodePath(t *testing.T) {
	path := "docs/naïve file.go"
	change, _ := mustParseUnifiedFileDiff(t, path, []byte("a\n"), []byte("b\n"), unifiedPatch(path, "@@ -1 +1 @@\n-a\n+b\n"))
	if change.Path() != path {
		t.Fatalf("Path() = %q, want %q", change.Path(), path)
	}
}

func TestParseUnifiedFileDiffRejectsInvalidPathsAndUnsupportedForms(t *testing.T) {
	base := []byte("a\n")
	head := []byte("b\n")
	body := "@@ -1 +1 @@\n-a\n+b\n"
	testCases := []struct {
		name  string
		path  string
		patch []byte
	}{
		{name: "unclean path", path: "../main.go", patch: unifiedPatch("../main.go", body)},
		{name: "base path mismatch", path: "main.go", patch: []byte("--- a/other.go\n+++ b/main.go\n" + body)},
		{name: "head path mismatch", path: "main.go", patch: []byte("--- a/main.go\n+++ b/other.go\n" + body)},
		{name: "added file", path: "main.go", patch: []byte("--- /dev/null\n+++ b/main.go\n" + body)},
		{name: "deleted file", path: "main.go", patch: []byte("--- a/main.go\n+++ /dev/null\n" + body)},
		{name: "quoted path", path: "main.go", patch: []byte("--- \"a/main.go\"\n+++ \"b/main.go\"\n" + body)},
		{name: "git metadata", path: "main.go", patch: []byte("diff --git a/main.go b/main.go\n" + string(unifiedPatch("main.go", body)))},
		{name: "index metadata", path: "main.go", patch: []byte("index 1234567..abcdef0 100644\n" + string(unifiedPatch("main.go", body)))},
		{name: "binary", path: "main.go", patch: []byte("Binary files a/main.go and b/main.go differ\n")},
		{name: "combined", path: "main.go", patch: unifiedPatch("main.go", "@@@ -1 -1 +1 @@@\n-a\n+b\n")},
		{name: "multiple files", path: "main.go", patch: []byte(string(unifiedPatch("main.go", body)) + string(unifiedPatch("main.go", body)))},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertUnifiedParseError(t, testCase.path, base, head, testCase.patch)
		})
	}
}

func TestParseUnifiedFileDiffRejectsMalformedOrMismatchedPatch(t *testing.T) {
	base := []byte("a\nb\nc\n")
	head := []byte("a\nB\nc\n")
	testCases := []struct {
		name string
		hunk string
	}{
		{name: "no hunk", hunk: ""},
		{name: "malformed marker", hunk: "@ -2 +2 @@\n-b\n+B\n"},
		{name: "numeric overflow", hunk: "@@ -" + strings.Repeat("9", 100) + " +2 @@\n-b\n+B\n"},
		{name: "leading zero start", hunk: "@@ -02 +2 @@\n-b\n+B\n"},
		{name: "leading zero count", hunk: "@@ -2,01 +2 @@\n-b\n+B\n"},
		{name: "raw zero positive count", hunk: "@@ -0 +2 @@\n-b\n+B\n"},
		{name: "both zero", hunk: "@@ -1,0 +1,0 @@\n"},
		{name: "context-only hunk", hunk: "@@ -1 +1 @@\n a\n@@ -2 +2 @@\n-b\n+B\n"},
		{name: "base count short", hunk: "@@ -2,2 +2 @@\n-b\n+B\n"},
		{name: "head count short", hunk: "@@ -2 +2,2 @@\n-b\n+B\n"},
		{name: "base count long", hunk: "@@ -2 +2 @@\n-b\n-c\n+B\n"},
		{name: "wrong context", hunk: "@@ -1,2 +1,2 @@\n x\n-b\n+B\n"},
		{name: "wrong deletion", hunk: "@@ -2 +2 @@\n-x\n+B\n"},
		{name: "wrong addition", hunk: "@@ -2 +2 @@\n-b\n+X\n"},
		{name: "invalid body prefix", hunk: "@@ -2 +2 @@\nb\n-b\n+B\n"},
		{name: "addition before deletion", hunk: "@@ -2 +2 @@\n+B\n-b\n"},
		{name: "unexpected marker", hunk: "@@ -2 +2 @@\n\\ No newline at end of file\n-b\n+B\n"},
		{name: "extra marker", hunk: "@@ -2 +2 @@\n-b\n\\ No newline at end of file\n+B\n"},
		{name: "out of order", hunk: "@@ -2 +2 @@\n-b\n+B\n@@ -1 +1 @@\n-a\n+a\n"},
		{name: "trailing garbage", hunk: "@@ -2 +2 @@\n-b\n+B\ngarbage\n"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertUnifiedParseError(t, "main.go", base, head, unifiedPatch("main.go", testCase.hunk))
		})
	}

	assertUnifiedParseError(t, "main.go", base, []byte("a\nB\nX\n"), unifiedPatch("main.go", "@@ -2 +2 @@\n-b\n+B\n"))
	assertUnifiedParseError(t, "main.go", base, head, bytes.TrimSuffix(unifiedPatch("main.go", "@@ -2 +2 @@\n-b\n+B\n"), []byte("\n")))
	assertUnifiedParseError(t, "main.go", []byte("a\n"), []byte("a\n"), unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+a\n"))
}

func TestParseUnifiedFileDiffValidatesNoNewlineMarkers(t *testing.T) {
	testCases := []struct {
		name string
		base string
		head string
		hunk string
	}{
		{name: "missing base marker", base: "old", head: "new\n", hunk: "@@ -1 +1 @@\n-old\n+new\n"},
		{name: "missing head marker", base: "old\n", head: "new", hunk: "@@ -1 +1 @@\n-old\n+new\n"},
		{name: "marker on terminated base", base: "old\n", head: "new\n", hunk: "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n+new\n"},
		{name: "duplicate marker", base: "old", head: "new", hunk: "@@ -1 +1 @@\n-old\n\\ No newline at end of file\n\\ No newline at end of file\n+new\n\\ No newline at end of file\n"},
		{name: "context terminal mismatch", base: "a\nz", head: "A\nz\n", hunk: "@@ -1,2 +1,2 @@\n-a\n+A\n z\n\\ No newline at end of file\n"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertUnifiedParseError(t, "main.go", []byte(testCase.base), []byte(testCase.head), unifiedPatch("main.go", testCase.hunk))
		})
	}
}

func TestParseUnifiedFileDiffRejectsBinaryAndOversizedPaths(t *testing.T) {
	validPatch := unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+b\n")
	assertUnifiedParseError(t, "main.go", []byte{'a', 0, '\n'}, []byte("b\n"), validPatch)
	assertUnifiedParseError(t, "main.go", []byte("a\n"), []byte{'b', 0, '\n'}, validPatch)
	patchWithNUL := append([]byte(nil), validPatch...)
	patchWithNUL[len(patchWithNUL)-2] = 0
	assertUnifiedParseError(t, "main.go", []byte("a\n"), []byte("b\n"), patchWithNUL)

	atLimitPath := strings.Repeat("a", maxUnifiedDiffPathBytes)
	mustParseUnifiedFileDiff(t, atLimitPath, []byte("a\n"), []byte("b\n"), unifiedPatch(atLimitPath, "@@ -1 +1 @@\n-a\n+b\n"))
	longPath := strings.Repeat("a", maxUnifiedDiffPathBytes+1)
	assertUnifiedParseError(t, longPath, []byte("a\n"), []byte("b\n"), unifiedPatch(longPath, "@@ -1 +1 @@\n-a\n+b\n"))
	invalidPath := string([]byte{'b', 'a', 'd', 0xff, '.', 'g', 'o'})
	assertUnifiedParseError(t, invalidPath, []byte("a\n"), []byte("b\n"), unifiedPatch(invalidPath, "@@ -1 +1 @@\n-a\n+b\n"))
}

func TestParseUnifiedFileDiffErrorsDoNotEchoBodyContent(t *testing.T) {
	sentinel := "UNIQUE_BODY_SENTINEL_7f3a"
	patch := unifiedPatch("main.go", "@@ -1 +1 @@\n-"+sentinel+"\n+b\n")
	_, _, err := ParseUnifiedFileDiff("main.go", []byte("a\n"), []byte("b\n"), patch)
	if err == nil {
		t.Fatal("ParseUnifiedFileDiff() error = nil")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error exposed body content: %v", err)
	}
}

func TestParseUnifiedFileDiffEnforcesHunkLimit(t *testing.T) {
	base, head, atLimit := manyUnifiedHunks(maxUnifiedDiffHunks)
	_, lineMap := mustParseUnifiedFileDiff(t, "main.go", base, head, atLimit)
	if len(lineMap.Hunks()) != maxUnifiedDiffHunks {
		t.Fatalf("len(Hunks()) = %d, want %d", len(lineMap.Hunks()), maxUnifiedDiffHunks)
	}
	base, head, overLimit := manyUnifiedHunks(maxUnifiedDiffHunks + 1)
	assertUnifiedParseError(t, "main.go", base, head, overLimit)
}

func TestParseUnifiedFileDiffEnforcesPhysicalLineLimit(t *testing.T) {
	base := bytes.Repeat([]byte("a\n"), maxUnifiedDiffPhysicalLines)
	head := append([]byte(nil), base...)
	head[0] = 'b'
	mustParseUnifiedFileDiff(t, "main.go", base, head, unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+b\n"))

	overLimit := bytes.Repeat([]byte("a\n"), maxUnifiedDiffPhysicalLines+1)
	assertUnifiedParseError(t, "main.go", overLimit, []byte("b\n"), unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+b\n"))
}

func TestParseUnifiedFileDiffEnforcesInputLimits(t *testing.T) {
	headerPrefix := "@@ -1 +1 @@ "
	atHeaderLimit := headerPrefix + strings.Repeat("x", maxUnifiedHunkHeaderBytes-len(headerPrefix)) + "\n-a\n+b\n"
	mustParseUnifiedFileDiff(t, "main.go", []byte("a\n"), []byte("b\n"), unifiedPatch("main.go", atHeaderLimit))
	overHeaderLimit := headerPrefix + strings.Repeat("x", maxUnifiedHunkHeaderBytes-len(headerPrefix)+1) + "\n-a\n+b\n"
	assertUnifiedParseError(t, "main.go", []byte("a\n"), []byte("b\n"), unifiedPatch("main.go", overHeaderLimit))

	oversized := bytes.Repeat([]byte{'x'}, maxUnifiedDiffContentBytes+1)
	assertUnifiedParseError(t, "main.go", oversized, []byte("b\n"), unifiedPatch("main.go", "@@ -1 +1 @@\n-x\n+b\n"))
	assertUnifiedParseError(t, "main.go", []byte("a\n"), oversized, unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+x\n"))
	assertUnifiedParseError(t, "main.go", []byte("a\n"), []byte("b\n"), bytes.Repeat([]byte{'x'}, maxUnifiedDiffPatchBytes+1))

	base := bytes.Repeat([]byte{'a'}, maxUnifiedDiffContentBytes)
	head := append([]byte(nil), base...)
	head[0] = 'b'
	bodyPrefix := "@@ -1 +1 @@"
	bodySuffix := "\n-" + string(base) + "\n\\ No newline at end of file\n+" + string(head) + "\n\\ No newline at end of file\n"
	patchWithoutSection := unifiedPatch("main.go", bodyPrefix+bodySuffix)
	padding := maxUnifiedDiffPatchBytes - len(patchWithoutSection) - 1
	if padding < 1 || len(bodyPrefix)+1+padding > maxUnifiedHunkHeaderBytes {
		t.Fatalf("invalid patch limit fixture padding %d", padding)
	}
	atLimit := unifiedPatch("main.go", bodyPrefix+" "+strings.Repeat("x", padding)+bodySuffix)
	if len(atLimit) != maxUnifiedDiffPatchBytes {
		t.Fatalf("patch length = %d, want %d", len(atLimit), maxUnifiedDiffPatchBytes)
	}
	mustParseUnifiedFileDiff(t, "main.go", base, head, atLimit)
	assertUnifiedParseError(t, "main.go", base, head, append(atLimit, 'x'))
}

func TestParseUnifiedFileDiffDoesNotRetainInputBuffers(t *testing.T) {
	base := []byte("a\nb\n")
	head := []byte("a\nB\n")
	patch := unifiedPatch("main.go", "@@ -2 +2 @@\n-b\n+B\n")
	change, lineMap := mustParseUnifiedFileDiff(t, "main.go", base, head, patch)
	changeIdentity := change.Identity()
	mapIdentity := lineMap.Identity()

	for i := range base {
		base[i] = 'x'
	}
	for i := range head {
		head[i] = 'y'
	}
	for i := range patch {
		patch[i] = 'z'
	}
	if change.Identity() != changeIdentity || lineMap.Identity() != mapIdentity {
		t.Fatal("mutating inputs changed returned evidence")
	}
	assertBaseMapping(t, lineMap, 1, 1, true)
}

func manyUnifiedHunks(count int) ([]byte, []byte, []byte) {
	var base strings.Builder
	var head strings.Builder
	var hunks strings.Builder
	for i := 0; i < count; i++ {
		line := 2*i + 1
		base.WriteString("a\n")
		head.WriteString("b\n")
		hunks.WriteString("@@ -")
		hunks.WriteString(strconv.Itoa(line))
		hunks.WriteString(" +")
		hunks.WriteString(strconv.Itoa(line))
		hunks.WriteString(" @@\n-a\n+b\n")
		if i+1 < count {
			base.WriteString("same\n")
			head.WriteString("same\n")
		}
	}
	return []byte(base.String()), []byte(head.String()), unifiedPatch("main.go", hunks.String())
}

func BenchmarkParseUnifiedFileDiffManyHunks(b *testing.B) {
	for _, count := range []int{128, 256, 512, 1024} {
		base, head, patch := manyUnifiedHunks(count)
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, err := ParseUnifiedFileDiff("main.go", base, head, patch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func FuzzParseUnifiedFileDiff(f *testing.F) {
	f.Add("main.go", []byte("a\n"), []byte("b\n"), unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n+b\n"))
	f.Add("main.go", []byte("a"), []byte("b"), unifiedPatch("main.go", "@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n"))
	f.Add("../bad.go", []byte{}, []byte{}, []byte("not a patch\n"))
	f.Fuzz(func(t *testing.T, path string, base, head, patch []byte) {
		change, lineMap, err := ParseUnifiedFileDiff(path, base, head, patch)
		repeatedChange, repeatedMap, repeatedErr := ParseUnifiedFileDiff(path, base, head, patch)
		if (err == nil) != (repeatedErr == nil) {
			t.Fatalf("repeated parse errors = %v and %v", err, repeatedErr)
		}
		if err != nil {
			if change.Identity() != "" || lineMap.Identity() != "" || repeatedChange.Identity() != "" || repeatedMap.Identity() != "" {
				t.Fatal("failed parse returned non-zero evidence")
			}
			return
		}
		if change.Identity() != repeatedChange.Identity() || lineMap.Identity() != repeatedMap.Identity() {
			t.Fatal("repeated parse changed evidence identity")
		}
	})
}

func unifiedPatch(path, hunks string) []byte {
	return []byte("--- a/" + path + "\n+++ b/" + path + "\n" + hunks)
}

func mustParseUnifiedFileDiff(t *testing.T, path string, base, head, patch []byte) (FileChange, LineMap) {
	t.Helper()
	change, lineMap, err := ParseUnifiedFileDiff(path, base, head, patch)
	if err != nil {
		t.Fatalf("ParseUnifiedFileDiff() error = %v", err)
	}
	return change, lineMap
}

func assertUnifiedParseError(t *testing.T, path string, base, head, patch []byte) {
	t.Helper()
	change, lineMap, err := ParseUnifiedFileDiff(path, base, head, patch)
	if err == nil {
		t.Fatal("ParseUnifiedFileDiff() error = nil")
	}
	if change.Identity() != "" || change.Path() != "" || len(change.ChangedRanges()) != 0 {
		t.Fatalf("ParseUnifiedFileDiff() change = %#v, want zero value", change)
	}
	if lineMap.Identity() != "" || lineMap.Path() != "" || len(lineMap.Hunks()) != 0 {
		t.Fatalf("ParseUnifiedFileDiff() line map = %#v, want zero value", lineMap)
	}
}

func testContentDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func physicalLineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	return bytes.Count(content, []byte{'\n'}) + boolInt(content[len(content)-1] != '\n')
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
