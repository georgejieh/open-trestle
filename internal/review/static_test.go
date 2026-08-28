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
			if got := containsDebugOutput([]byte(testCase.content), sourceRange); got != testCase.want {
				t.Fatalf("containsDebugOutput() = %t, want %t", got, testCase.want)
			}
		})
	}
}
