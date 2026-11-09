package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func sliceDigest(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

// The live deletion-only shape: a zero guard removed from Div, no head line
// changed. The head lines around the deletion point are bound as reviewable
// context, the deletion point is recorded, and the removed guard is bound to
// the exact base file as removed-lines evidence (version 7).
func TestHandlerBindsDeletionPointContextForRemovedGuard(t *testing.T) {
	base := "package calc\n\nfunc Div(a, b int) int {\n\tif b == 0 {\n\t\treturn 0\n\t}\n\treturn a / b\n}\n"
	head := "package calc\n\nfunc Div(a, b int) int {\n\treturn a / b\n}\n"
	output, change, baseArtifact, headArtifact := deletionAnalysisFixture(t, map[string][]byte{"calc.go": []byte(base)}, map[string][]byte{"calc.go": []byte(head)})
	result, err := ParseResultArtifact(output, change, baseArtifact, headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion() != 7 || len(result.Items()) != 1 || len(result.RemovedLines()) != 1 || len(result.Gaps()) != 1 || len(result.Observations()) != 0 {
		t.Fatalf("deletion context result: version=%d items=%d removed=%d gaps=%d", result.SchemaVersion(), len(result.Items()), len(result.RemovedLines()), len(result.Gaps()))
	}
	item := result.Items()[0]
	if item.Path() != "calc.go" || item.StartLine() != 1 || item.EndLine() != 5 {
		t.Fatalf("context item %s:%d-%d, want the whole 5-line head file", item.Path(), item.StartLine(), item.EndLine())
	}
	gap := result.Gaps()[0]
	if gap.Reason() != analysiscodec.DeletionContextReason || gap.StartLine() != 3 || gap.EndLine() != 4 {
		t.Fatalf("deletion point %s %d-%d, want deleted_lines between head lines 3 and 4", gap.Reason(), gap.StartLine(), gap.EndLine())
	}
	baseFile, _ := evidence.NewRepositoryFile("calc.go", []byte(base))
	removed := result.RemovedLines()[0]
	if removed.Path() != "calc.go" || removed.StartLine() != 4 || removed.EndLine() != 6 || removed.Digest() != sliceDigest("\tif b == 0 {\n\t\treturn 0\n\t}\n") {
		t.Fatalf("removed lines %s:%d-%d, want the guard at base lines 4-6", removed.Path(), removed.StartLine(), removed.EndLine())
	}
	if removed.FileIdentity() != baseFile.Identity() || removed.FileDigest() != baseFile.Digest() || removed.FileIdentity() == item.FileIdentity() {
		t.Fatal("removed lines are not bound to the exact base file")
	}
	if check := result.Checks()[0]; check.State() != CheckNotApplicable || check.ApplicableRanges() != 0 {
		t.Fatal("deletion context was counted as a changed range for the static check")
	}
}

func TestHandlerDeletionContextWindowsAndFileEnd(t *testing.T) {
	lines := make([]string, 40)
	for i := range lines {
		lines[i] = "line " + string(rune('A'+i%26)) + strings.Repeat("x", i)
	}
	base := strings.Join(lines, "\n") + "\n"
	// Remove base line 5 and the last base line: two deletion points far apart.
	headLines := append(append([]string{}, lines[:4]...), lines[5:39]...)
	head := strings.Join(headLines, "\n") + "\n"
	output, change, baseArtifact, headArtifact := deletionAnalysisFixture(t, map[string][]byte{"a.txt": []byte(base)}, map[string][]byte{"a.txt": []byte(head)})
	result, err := ParseResultArtifact(output, change, baseArtifact, headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion() != 7 || len(result.Items()) != 2 || len(result.Gaps()) != 2 || len(result.RemovedLines()) != 2 {
		t.Fatalf("version=%d items=%d gaps=%d removed=%d", result.SchemaVersion(), len(result.Items()), len(result.Gaps()), len(result.RemovedLines()))
	}
	first, last := result.Items()[0], result.Items()[1]
	// Head has 38 lines. The first deletion's cursor is head line 5; the
	// second is at end of file (cursor 39), so its window ends at line 38.
	if first.StartLine() != 1 || first.EndLine() != 12 || last.StartLine() != 31 || last.EndLine() != 38 {
		t.Fatalf("windows %d-%d and %d-%d", first.StartLine(), first.EndLine(), last.StartLine(), last.EndLine())
	}
	if g := result.Gaps(); g[0].StartLine() != 4 || g[0].EndLine() != 5 || g[1].StartLine() != 38 || g[1].EndLine() != 38 {
		t.Fatalf("deletion points %d-%d and %d-%d", g[0].StartLine(), g[0].EndLine(), g[1].StartLine(), g[1].EndLine())
	}
	removed := result.RemovedLines()
	if removed[0].StartLine() != 5 || removed[0].EndLine() != 5 || removed[0].Digest() != sliceDigest(lines[4]+"\n") || removed[1].StartLine() != 40 || removed[1].EndLine() != 40 || removed[1].Digest() != sliceDigest(lines[39]+"\n") {
		t.Fatalf("removed base ranges %d-%d and %d-%d", removed[0].StartLine(), removed[0].EndLine(), removed[1].StartLine(), removed[1].EndLine())
	}
	// Each removed range names the head line of its deletion point.
	if removed[0].HeadLine() != 4 || removed[1].HeadLine() != 38 {
		t.Fatalf("removed head lines %d and %d", removed[0].HeadLine(), removed[1].HeadLine())
	}
}

// Deletions before and after the only line of a one-line head file share one
// deletion-point marker. The marker is recorded once; each removed base range
// is still bound separately.
func TestHandlerDeletionPointsSharingAMarker(t *testing.T) {
	output, change, baseArtifact, headArtifact := deletionAnalysisFixture(t, map[string][]byte{"a.txt": []byte("first\nkeep\nlast\n")}, map[string][]byte{"a.txt": []byte("keep\n")})
	result, err := ParseResultArtifact(output, change, baseArtifact, headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion() != 7 || len(result.Items()) != 1 || len(result.Gaps()) != 1 || len(result.RemovedLines()) != 2 {
		t.Fatalf("version=%d items=%d gaps=%d removed=%d", result.SchemaVersion(), len(result.Items()), len(result.Gaps()), len(result.RemovedLines()))
	}
	if gap := result.Gaps()[0]; gap.Reason() != analysiscodec.DeletionContextReason || gap.StartLine() != 1 || gap.EndLine() != 1 {
		t.Fatalf("shared deletion point %s %d-%d", gap.Reason(), gap.StartLine(), gap.EndLine())
	}
	if removed := result.RemovedLines(); removed[0].StartLine() != 1 || removed[0].EndLine() != 1 || removed[1].StartLine() != 3 || removed[1].EndLine() != 3 || removed[0].HeadLine() != 1 || removed[1].HeadLine() != 1 {
		t.Fatalf("removed base ranges %d-%d and %d-%d", removed[0].StartLine(), removed[0].EndLine(), removed[1].StartLine(), removed[1].EndLine())
	}
}

// Removed text past the per-point line or byte bound, or past the per-entry
// byte bound, is recorded whole as a removed_lines_limit gap at its base range
// and never truncated.
func TestHandlerRemovedLinesPastBoundsAreExplicitGaps(t *testing.T) {
	block := func(prefix string, count, width int) []string {
		lines := make([]string, count)
		for i := range lines {
			lines[i] = prefix + strings.Repeat("y", width)
		}
		return lines
	}
	keep := func(name string) []string { return []string{"keep " + name} }
	var base, head []string
	// Point 1 (base line 2): 65 short lines, past the 64-line bound.
	base = append(append(append(base, keep("a")...), block("long", removedLinesPerPoint+1, 4)...), keep("b")...)
	head = append(append(head, keep("a")...), keep("b")...)
	// Point 2: one line just under the per-point byte bound (bound).
	near := block("near", 1, removedBytesPerPoint-6)
	base = append(append(base, near...), keep("c")...)
	head = append(head, keep("c")...)
	// Point 3: one line over the per-point byte bound.
	base = append(append(base, block("wide", 1, removedBytesPerPoint)...), keep("d")...)
	head = append(head, keep("d")...)
	// Points 4-7: four more near-bound lines; the entry bound admits four such
	// points in total, so points 4, 5 and 6 fit and point 7 does not.
	for _, name := range []string{"e", "f", "g", "h"} {
		base = append(append(base, block("near", 1, removedBytesPerPoint-6)...), keep(name)...)
		head = append(head, keep(name)...)
	}
	baseText, headText := strings.Join(base, "\n")+"\n", strings.Join(head, "\n")+"\n"
	output, change, baseArtifact, headArtifact := deletionAnalysisFixture(t, map[string][]byte{"big.txt": []byte(baseText)}, map[string][]byte{"big.txt": []byte(headText)})
	result, err := ParseResultArtifact(output, change, baseArtifact, headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion() != 7 {
		t.Fatalf("version=%d", result.SchemaVersion())
	}
	var limits []Gap
	for _, gap := range result.Gaps() {
		if gap.Reason() == analysiscodec.RemovedLinesLimitReason {
			limits = append(limits, gap)
		}
	}
	removed := result.RemovedLines()
	if len(limits) != 3 || len(removed) != 4 {
		t.Fatalf("limit gaps=%d removed=%d, want 3 and 4", len(limits), len(removed))
	}
	// Base line numbers: keep a (1), 65 long lines (2-66), keep b (67), near
	// (68), keep c (69), wide (70), keep d (71), near (72), keep e (73), near
	// (74), keep f (75), near (76), keep g (77), near (78), keep h (79).
	wantLimits := [][2]int{{2, 66}, {70, 70}, {78, 78}}
	for index, want := range wantLimits {
		if limits[index].StartLine() != want[0] || limits[index].EndLine() != want[1] {
			t.Fatalf("limit gap %d at base %d-%d, want %d-%d", index, limits[index].StartLine(), limits[index].EndLine(), want[0], want[1])
		}
	}
	for index, want := range []int{68, 72, 74, 76} {
		if removed[index].StartLine() != want || removed[index].EndLine() != want || removed[index].SliceBytes() > removedBytesPerPoint {
			t.Fatalf("removed record %d at base %d-%d", index, removed[index].StartLine(), removed[index].EndLine())
		}
	}
}
