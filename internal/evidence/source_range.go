package evidence

import (
	"fmt"
	"path"
	"strings"
	"unicode"
)

// SourceRange identifies an inclusive range in a workspace-relative source file.
type SourceRange struct {
	path      string
	startLine int
	endLine   int
}

// NewSourceRange creates a source range.
func NewSourceRange(sourcePath string, startLine, endLine int) (SourceRange, error) {
	if err := validateSourcePath(sourcePath); err != nil {
		return SourceRange{}, err
	}
	if startLine < 1 {
		return SourceRange{}, fmt.Errorf("start line must be positive: %d", startLine)
	}
	if endLine < startLine {
		return SourceRange{}, fmt.Errorf("end line %d precedes start line %d", endLine, startLine)
	}
	return SourceRange{path: sourcePath, startLine: startLine, endLine: endLine}, nil
}

func validateSourcePath(sourcePath string) error {
	if sourcePath == "" {
		return fmt.Errorf("source path is required")
	}
	if path.IsAbs(sourcePath) || path.Clean(sourcePath) != sourcePath || sourcePath == "." || sourcePath == ".." || strings.HasPrefix(sourcePath, "../") {
		return fmt.Errorf("source path must be clean and workspace-relative: %q", sourcePath)
	}
	if strings.ContainsRune(sourcePath, '\\') || strings.IndexFunc(sourcePath, unicode.IsControl) >= 0 {
		return fmt.Errorf("source path contains an invalid character: %q", sourcePath)
	}
	return nil
}

// Path returns the workspace-relative source path.
func (r SourceRange) Path() string {
	return r.path
}

// StartLine returns the inclusive first line.
func (r SourceRange) StartLine() int {
	return r.startLine
}

// EndLine returns the inclusive last line.
func (r SourceRange) EndLine() int {
	return r.endLine
}
