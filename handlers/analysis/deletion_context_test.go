package analysis

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/analysiscodec"
)

// The live deletion-only shape: a zero guard removed from Div, no head line
// changed. The head lines around the deletion point are bound as reviewable
// context and the deletion point is recorded; the removed text is not.
func TestHandlerBindsDeletionPointContextForRemovedGuard(t *testing.T) {
	base := "package calc\n\nfunc Div(a, b int) int {\n\tif b == 0 {\n\t\treturn 0\n\t}\n\treturn a / b\n}\n"
	head := "package calc\n\nfunc Div(a, b int) int {\n\treturn a / b\n}\n"
	output, change, baseArtifact, headArtifact := deletionAnalysisFixture(t, map[string][]byte{"calc.go": []byte(base)}, map[string][]byte{"calc.go": []byte(head)})
	result, err := ParseResultArtifact(output, change, baseArtifact, headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion() != 6 || len(result.Items()) != 1 || len(result.Gaps()) != 1 || len(result.Observations()) != 0 {
		t.Fatalf("deletion context result: version=%d items=%d gaps=%d", result.SchemaVersion(), len(result.Items()), len(result.Gaps()))
	}
	item := result.Items()[0]
	if item.Path() != "calc.go" || item.StartLine() != 1 || item.EndLine() != 5 {
		t.Fatalf("context item %s:%d-%d, want the whole 5-line head file", item.Path(), item.StartLine(), item.EndLine())
	}
	gap := result.Gaps()[0]
	if gap.Reason() != analysiscodec.DeletionContextReason || gap.StartLine() != 3 || gap.EndLine() != 4 {
		t.Fatalf("deletion point %s %d-%d, want deleted_lines between head lines 3 and 4", gap.Reason(), gap.StartLine(), gap.EndLine())
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
	if result.SchemaVersion() != 6 || len(result.Items()) != 2 || len(result.Gaps()) != 2 {
		t.Fatalf("version=%d items=%d gaps=%d", result.SchemaVersion(), len(result.Items()), len(result.Gaps()))
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
}
