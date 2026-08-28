package evidence

import "testing"

func TestNewSourceRangeAcceptsWorkspaceRelativePath(t *testing.T) {
	for _, sourcePath := range []string{"internal/review/review.go", "docs/naïve file.go"} {
		sourceRange, err := NewSourceRange(sourcePath, 4, 9)
		if err != nil {
			t.Fatalf("NewSourceRange() error = %v", err)
		}

		if sourceRange.Path() != sourcePath {
			t.Fatalf("Path() = %q, want %q", sourceRange.Path(), sourcePath)
		}
		if sourceRange.StartLine() != 4 {
			t.Fatalf("StartLine() = %d, want 4", sourceRange.StartLine())
		}
		if sourceRange.EndLine() != 9 {
			t.Fatalf("EndLine() = %d, want 9", sourceRange.EndLine())
		}
	}
}

func TestNewSourceRangeRejectsInvalidPathAndLines(t *testing.T) {
	testCases := []struct {
		name      string
		path      string
		startLine int
		endLine   int
	}{
		{name: "empty path", path: "", startLine: 1, endLine: 1},
		{name: "workspace root", path: ".", startLine: 1, endLine: 1},
		{name: "absolute path", path: "/workspace/main.go", startLine: 1, endLine: 1},
		{name: "parent traversal", path: "../main.go", startLine: 1, endLine: 1},
		{name: "embedded traversal", path: "internal/../main.go", startLine: 1, endLine: 1},
		{name: "backslash", path: `internal\main.go`, startLine: 1, endLine: 1},
		{name: "nul byte", path: "internal/\x00main.go", startLine: 1, endLine: 1},
		{name: "newline", path: "internal/forged\nstatus.go", startLine: 1, endLine: 1},
		{name: "carriage return", path: "internal/forged\rstatus.go", startLine: 1, endLine: 1},
		{name: "tab", path: "internal/forged\tstatus.go", startLine: 1, endLine: 1},
		{name: "escape", path: "internal/forged\x1bstatus.go", startLine: 1, endLine: 1},
		{name: "delete", path: "internal/forged\x7fstatus.go", startLine: 1, endLine: 1},
		{name: "c1 control", path: "internal/forged\u0085status.go", startLine: 1, endLine: 1},
		{name: "line separator", path: "internal/forged\u2028status.go", startLine: 1, endLine: 1},
		{name: "paragraph separator", path: "internal/forged\u2029status.go", startLine: 1, endLine: 1},
		{name: "bidi override", path: "internal/safe\u202etxt.go", startLine: 1, endLine: 1},
		{name: "bidi isolate", path: "internal/safe\u2066txt.go", startLine: 1, endLine: 1},
		{name: "unclean path", path: "internal//main.go", startLine: 1, endLine: 1},
		{name: "zero start", path: "main.go", startLine: 0, endLine: 1},
		{name: "reversed range", path: "main.go", startLine: 3, endLine: 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewSourceRange(testCase.path, testCase.startLine, testCase.endLine); err == nil {
				t.Fatal("NewSourceRange() error = nil, want validation error")
			}
		})
	}
}
