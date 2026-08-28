package review

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestSelectSourceRangeUsesPhysicalLines(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		startLine int
		endLine   int
		want      string
		wantError bool
	}{
		{name: "empty file", startLine: 1, endLine: 1, wantError: true},
		{name: "single line", content: "alpha", startLine: 1, endLine: 1, want: "alpha"},
		{name: "terminal newline", content: "alpha\n", startLine: 1, endLine: 1, want: "alpha"},
		{name: "line after terminal newline", content: "alpha\n", startLine: 2, endLine: 2, wantError: true},
		{name: "last physical line", content: "alpha\nbeta\n", startLine: 2, endLine: 2, want: "beta"},
		{name: "range crosses end", content: "alpha\nbeta\n", startLine: 1, endLine: 3, wantError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sourceRange, err := evidence.NewSourceRange("main.go", testCase.startLine, testCase.endLine)
			if err != nil {
				t.Fatalf("evidence.NewSourceRange() error = %v", err)
			}

			selected, err := selectSourceRange([]byte(testCase.content), sourceRange)
			if testCase.wantError {
				if err == nil {
					t.Fatalf("selectSourceRange() error = nil, want range error; selected = %q", selected)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectSourceRange() error = %v", err)
			}
			if string(selected) != testCase.want {
				t.Fatalf("selectSourceRange() = %q, want %q", selected, testCase.want)
			}
		})
	}
}
