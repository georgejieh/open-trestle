package review

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestContainsDebugOutputRequiresGoCallExpression(t *testing.T) {
	testCases := []struct {
		name       string
		sourcePath string
		content    string
		line       int
		want       bool
	}{
		{name: "call", sourcePath: "main.go", content: "package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n}\n", line: 4, want: true},
		{name: "aliased import", sourcePath: "main.go", content: "package sample\nimport f \"fmt\"\nfunc main() {\n\tf.Println(\"debug\")\n}\n", line: 4, want: true},
		{name: "shadowed import", sourcePath: "main.go", content: "package sample\nimport \"fmt\"\ntype noop struct{}\nfunc (noop) Println(string) {}\nfunc demo() {\n\tvar fmt noop\n\tfmt.Println(\"debug\")\n}\n", line: 7},
		{name: "unrelated aliased import", sourcePath: "main.go", content: "package sample\nimport fmt \"strings\"\nfunc demo() {\n\tfmt.Println(\"debug\")\n}\n", line: 4},
		{name: "shadowed package name", sourcePath: "main.go", content: "package sample\n\ntype noop struct{}\nfunc (noop) Println(string) {}\nfunc demo() {\n\tvar fmt noop\n\tfmt.Println(\"debug\")\n}\n", line: 7},
		{name: "wrong function", sourcePath: "main.go", content: "package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Printf(\"debug\")\n}\n", line: 4},
		{name: "wrong arity", sourcePath: "main.go", content: "package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\", \"extra\")\n}\n", line: 4},
		{name: "non-literal argument", sourcePath: "main.go", content: "package sample\nimport \"fmt\"\nfunc main() {\n\tmessage := \"debug\"\n\tfmt.Println(message)\n}\n", line: 5},
		{name: "block comment", sourcePath: "main.go", content: "package sample\n/*\nfmt.Println(\"debug\")\n*/\n", line: 3},
		{name: "raw string", sourcePath: "main.go", content: "package sample\nvar message = `\nfmt.Println(\"debug\")\n`\n", line: 3},
		{name: "interpreted string", sourcePath: "main.go", content: "package sample\nvar message = \"fmt.Println(\\\"debug\\\")\"\n", line: 2},
		{name: "non-Go source", sourcePath: "README.md", content: "fmt.Println(\"debug\")\n", line: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sourceRange, err := evidence.NewSourceRange(testCase.sourcePath, testCase.line, testCase.line)
			if err != nil {
				t.Fatalf("evidence.NewSourceRange() error = %v", err)
			}
			got, err := containsDebugOutput([]byte(testCase.content), sourceRange)
			if err != nil {
				t.Fatalf("containsDebugOutput() error = %v", err)
			}
			if got != testCase.want {
				t.Fatalf("containsDebugOutput() = %t, want %t", got, testCase.want)
			}
		})
	}
}

func TestContainsDebugOutputReportsParseError(t *testing.T) {
	sourceRange, err := evidence.NewSourceRange("main.go", 1, 1)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	if _, err := containsDebugOutput([]byte("package sample\nfunc {\n"), sourceRange); err == nil {
		t.Fatal("containsDebugOutput() error = nil, want parse error")
	}
}

func TestReviewDebugOutputsReturnsExactOrderedFindings(t *testing.T) {
	source := []byte("package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n\tfmt.Println(\n\t\t\"debug\",\n\t)\n}\n")
	selection, err := evidence.NewSourceRange("main.go", 1, 8)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	findings, items, err := reviewDebugOutputs(source, selection)
	if err != nil {
		t.Fatalf("reviewDebugOutputs() error = %v", err)
	}
	if len(findings) != 2 || len(items) != 2 {
		t.Fatalf("reviewDebugOutputs() returned %d findings and %d evidence items, want 2 each", len(findings), len(items))
	}

	wantRanges := [][2]int{{4, 4}, {5, 7}}
	wantContent := []string{"\tfmt.Println(\"debug\")", "\tfmt.Println(\n\t\t\"debug\",\n\t)"}
	for i, finding := range findings {
		sourceRange := finding.SourceRange()
		if got := [2]int{sourceRange.StartLine(), sourceRange.EndLine()}; got != wantRanges[i] {
			t.Fatalf("finding %d range = %v, want %v", i, got, wantRanges[i])
		}
		item := items[i]
		if item.SourceRange() != sourceRange {
			t.Fatalf("evidence %d range = %#v, want %#v", i, item.SourceRange(), sourceRange)
		}
		if item.Digest() != digestHex([]byte(wantContent[i])) {
			t.Fatalf("evidence %d digest = %q, want exact span digest", i, item.Digest())
		}
		if ids := finding.EvidenceIDs(); len(ids) != 1 || ids[0] != item.ID() {
			t.Fatalf("finding %d evidence IDs = %#v, want %q", i, ids, item.ID())
		}
	}
	if findings[0].ID() == findings[1].ID() || items[0].ID() == items[1].ID() {
		t.Fatal("distinct call spans must have distinct identities")
	}
}

func TestReviewDebugOutputsHonorsSelectionAndDeduplicatesLines(t *testing.T) {
	source := []byte("package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\"); fmt.Println(\"debug\")\n\tfmt.Println(\n\t\t\"debug\",\n\t)\n}\n")

	testCases := []struct {
		name      string
		startLine int
		endLine   int
		want      int
	}{
		{name: "same line deduplicates", startLine: 4, endLine: 4, want: 1},
		{name: "outside selection", startLine: 3, endLine: 3},
		{name: "crosses selection", startLine: 5, endLine: 6},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			selection, err := evidence.NewSourceRange("main.go", testCase.startLine, testCase.endLine)
			if err != nil {
				t.Fatalf("evidence.NewSourceRange() error = %v", err)
			}
			findings, items, err := reviewDebugOutputs(source, selection)
			if err != nil {
				t.Fatalf("reviewDebugOutputs() error = %v", err)
			}
			if len(findings) != testCase.want || len(items) != testCase.want {
				t.Fatalf("reviewDebugOutputs() returned %d findings and %d evidence items, want %d", len(findings), len(items), testCase.want)
			}
		})
	}
}

func TestReviewDebugOutputsChangesOnlyEditedSpanIdentity(t *testing.T) {
	original := []byte("package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n\tfmt.Println(\"debug\")\n}\n")
	changed := []byte("package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n\tfmt.Println( \"debug\")\n}\n")
	selection, err := evidence.NewSourceRange("main.go", 1, 6)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	originalFindings, originalItems, err := reviewDebugOutputs(original, selection)
	if err != nil {
		t.Fatalf("reviewDebugOutputs(original) error = %v", err)
	}
	changedFindings, changedItems, err := reviewDebugOutputs(changed, selection)
	if err != nil {
		t.Fatalf("reviewDebugOutputs(changed) error = %v", err)
	}
	if len(originalFindings) != 2 || len(changedFindings) != 2 {
		t.Fatalf("finding counts = %d and %d, want 2", len(originalFindings), len(changedFindings))
	}
	if originalFindings[0].ID() != changedFindings[0].ID() || originalItems[0].ID() != changedItems[0].ID() {
		t.Fatal("editing the second span must not change the first pair")
	}
	if originalFindings[1].ID() == changedFindings[1].ID() || originalItems[1].ID() == changedItems[1].ID() {
		t.Fatal("editing a matched span must change its finding and evidence identities")
	}
}

func TestReviewDebugOutputsUsesPhysicalLinesWithDirectives(t *testing.T) {
	for _, directive := range []string{"//line main.go:1", "//line fake.go:100"} {
		source := []byte("package sample\nimport \"fmt\"\n" + directive + "\nfunc main() { fmt.Println(\"debug\") }\n")
		selection, err := evidence.NewSourceRange("main.go", 1, 4)
		if err != nil {
			t.Fatalf("evidence.NewSourceRange() error = %v", err)
		}

		findings, items, err := reviewDebugOutputs(source, selection)
		if err != nil {
			t.Fatalf("reviewDebugOutputs() error = %v", err)
		}
		if len(findings) != 1 || len(items) != 1 {
			t.Fatalf("reviewDebugOutputs() returned %d findings and %d evidence items, want 1 each", len(findings), len(items))
		}
		sourceRange := findings[0].SourceRange()
		if sourceRange.StartLine() != 4 || sourceRange.EndLine() != 4 {
			t.Fatalf("finding range = %d-%d, want physical line 4", sourceRange.StartLine(), sourceRange.EndLine())
		}
		if items[0].Digest() != digestHex([]byte(`func main() { fmt.Println("debug") }`)) {
			t.Fatalf("evidence digest = %q, want physical call line digest", items[0].Digest())
		}
	}
}

func TestReviewDebugOutputsDoesNotMergeDirectiveAdjustedLines(t *testing.T) {
	source := []byte("package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n//line main.go:4\n\tfmt.Println(\"debug\")\n}\n")
	selection, err := evidence.NewSourceRange("main.go", 1, 7)
	if err != nil {
		t.Fatalf("evidence.NewSourceRange() error = %v", err)
	}

	findings, _, err := reviewDebugOutputs(source, selection)
	if err != nil {
		t.Fatalf("reviewDebugOutputs() error = %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("reviewDebugOutputs() returned %d findings, want 2", len(findings))
	}
	if findings[0].SourceRange().StartLine() != 4 || findings[1].SourceRange().StartLine() != 6 {
		t.Fatalf("finding lines = %d and %d, want physical lines 4 and 6", findings[0].SourceRange().StartLine(), findings[1].SourceRange().StartLine())
	}
}
