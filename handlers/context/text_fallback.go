package context

import (
	"bytes"
	"path"
	"strings"
	"unicode/utf8"
)

// Non-Go changed hunks are admitted as changed_hunk sources when they are valid
// UTF-8 text. No structural or semantic evidence exists for them: the semantic
// profile still records semantic_unsupported_language for every such path, and
// that omission is kept in the packet.
//
// The exclusion list below is deliberately small. Matching files are recorded
// as omissions with reason excluded_path rather than silently dropped.
var (
	fallbackExcludedSegments = []string{"vendor", "node_modules"}
	fallbackExcludedNames    = []string{"go.sum", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"}
	fallbackExcludedSuffixes = []string{".lock", ".min.js", ".min.css", ".map"}
)

// excludedFallbackPath reports whether a non-Go path is a vendored, lock,
// minified, or source-map file that the text fallback does not review.
func excludedFallbackPath(filePath string) bool {
	for _, segment := range strings.Split(filePath, "/") {
		for _, excluded := range fallbackExcludedSegments {
			if segment == excluded {
				return true
			}
		}
	}
	base := path.Base(filePath)
	for _, name := range fallbackExcludedNames {
		if base == name {
			return true
		}
	}
	for _, suffix := range fallbackExcludedSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// isFallbackText reports whether a hunk is valid UTF-8 without NUL bytes, the
// same content rule review.ContextSource enforces.
func isFallbackText(content []byte) bool {
	return utf8.Valid(content) && bytes.IndexByte(content, 0) < 0
}
