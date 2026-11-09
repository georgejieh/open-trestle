package analysis

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/analysiscodec"
)

// A file over the 1 MiB change-model diff bound is a resource_limit entry
// whatever its kind. A change that removes or empties such a file beside a
// small Go change completes analysis: the Go change is bound, the large file
// is one whole-entry resource_limit gap, and its removed text is one
// whole-entry removed_lines_limit gap, unread.
func TestSizeLimitedEntriesAreResourceLimitGapsWhateverTheirKind(t *testing.T) {
	large := budgetLines(2048)
	goBase := []byte("package calc\n\nfunc Div(a, b int) int { if b == 0 { return 0 }; return a / b }\n")
	goHead := []byte("package calc\n\nfunc Div(a, b int) int { return a / b }\n")
	for _, tc := range []struct {
		name         string
		base, head   map[string][]byte
		removedLimit bool
	}{
		{"removed", map[string][]byte{"calc.go": goBase, "large.txt": large}, map[string][]byte{"calc.go": goHead}, true},
		{"emptied", map[string][]byte{"calc.go": goBase, "large.txt": large}, map[string][]byte{"calc.go": goHead, "large.txt": {}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, change, base, head := deletionAnalysisFixture(t, tc.base, tc.head)
			result, err := ParseResultArtifact(output, change, base, head)
			if err != nil {
				t.Fatal(err)
			}
			bound := false
			for _, item := range result.Items() {
				bound = bound || item.Path() == "calc.go"
			}
			if !bound {
				t.Fatal("the small Go change was not bound")
			}
			reasons := map[string]bool{}
			for _, gap := range result.Gaps() {
				if gap.Path() != "large.txt" {
					continue
				}
				if gap.StartLine() != 0 || gap.EndLine() != 0 {
					t.Fatalf("large.txt gap %s at %d-%d, want whole-entry", gap.Reason(), gap.StartLine(), gap.EndLine())
				}
				reasons[gap.Reason()] = true
			}
			want := map[string]bool{"resource_limit": true}
			if tc.removedLimit {
				want[analysiscodec.RemovedLinesLimitReason] = true
			}
			if len(reasons) != len(want) {
				t.Fatalf("large.txt gaps %v, want %v", reasons, want)
			}
			for reason := range want {
				if !reasons[reason] {
					t.Fatalf("large.txt gaps %v, want %v", reasons, want)
				}
			}
			for _, item := range result.RemovedLines() {
				if item.Path() == "large.txt" {
					t.Fatal("removed text of a size-limited file was bound")
				}
			}
		})
	}
}
