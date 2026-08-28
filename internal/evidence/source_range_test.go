package evidence

import "testing"

func TestNewSourceRangeAcceptsWorkspaceRelativePath(t *testing.T) {
	sourceRange, err := NewSourceRange("internal/review/review.go", 4, 9)
	if err != nil {
		t.Fatalf("NewSourceRange() error = %v", err)
	}

	if sourceRange.Path() != "internal/review/review.go" {
		t.Fatalf("Path() = %q, want %q", sourceRange.Path(), "internal/review/review.go")
	}
	if sourceRange.StartLine() != 4 {
		t.Fatalf("StartLine() = %d, want 4", sourceRange.StartLine())
	}
	if sourceRange.EndLine() != 9 {
		t.Fatalf("EndLine() = %d, want 9", sourceRange.EndLine())
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
