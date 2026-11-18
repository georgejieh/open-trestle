package syntaxwasm

import (
	"bytes"
	"strings"
)

// identByte reports whether c can be part of an identifier in the C-like
// languages; bytes of multi-byte UTF-8 characters count.
func identByte(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
}

// lexCode walks C-like text and reports words ('w'), scope operators ('S'),
// and each other punctuation byte as itself, so a single colon is ':'.
// Comments, string and character literals, raw strings and preprocessor
// lines are skipped. The visitor returns false to stop.
func lexCode(b []byte, visit func(token byte, pos int, word string) bool) {
	lineStart := true
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n':
			lineStart = true
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i += 2
		case c == '#' && lineStart:
			for i < len(b) && b[i] != '\n' {
				if b[i] == '\\' && i+1 < len(b) {
					i++
				}
				i++
			}
		case c == '"' || c == '\'':
			i = skipLiteral(b, i)
			lineStart = false
		case identByte(c):
			start := i
			for i < len(b) && identByte(b[i]) {
				i++
			}
			word := string(b[start:i])
			lineStart = false
			if i < len(b) && b[i] == '"' && strings.HasSuffix(word, "R") && len(word) <= 3 {
				i = skipRawString(b, i)
				continue
			}
			if c >= '0' && c <= '9' {
				// A number, possibly with digit separators.
				for i < len(b) && (identByte(b[i]) || b[i] == '\'' || b[i] == '.') {
					i++
				}
				continue
			}
			if !visit('w', start, word) {
				return
			}
		case c == ':':
			lineStart = false
			if i+1 < len(b) && b[i+1] == ':' {
				i += 2
				if !visit('S', i-2, "") {
					return
				}
				continue
			}
			i++
			if !visit(':', i-1, "") {
				return
			}
		default:
			lineStart = false
			i++
			if !visit(c, i-1, "") {
				return
			}
		}
	}
}

// codeWords returns the words of C-like text outside comments and literals.
func codeWords(b []byte) map[string]bool {
	words := map[string]bool{}
	lexCode(b, func(token byte, _ int, word string) bool {
		if token == 'w' {
			words[word] = true
		}
		return true
	})
	return words
}

// skipLiteral returns the index after the string or character literal that
// starts at b[i].
func skipLiteral(b []byte, i int) int {
	quote := b[i]
	i++
	for i < len(b) && b[i] != quote && b[i] != '\n' {
		if b[i] == '\\' {
			i++
		}
		i++
	}
	if i < len(b) {
		i++
	}
	return i
}

// skipRawString returns the index after the raw string literal whose
// opening quote is b[i].
func skipRawString(b []byte, i int) int {
	i++
	start := i
	for i < len(b) && b[i] != '(' && b[i] != '\n' {
		i++
	}
	if i >= len(b) || b[i] != '(' {
		return i
	}
	closing := ")" + string(b[start:i]) + "\""
	if at := bytes.Index(b[i:], []byte(closing)); at >= 0 {
		return i + at + len(closing)
	}
	return len(b)
}
