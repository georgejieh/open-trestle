// Package logtail inspects the end of log text.
package logtail

import "strings"

// Tail returns the last n lines of text. A trailing newline does not count as
// an extra empty line. Tail returns nil when n is not positive or text is
// empty.
func Tail(text string, n int) []string {
	if n <= 0 || text == "" {
		return nil
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if n >= len(lines) {
		return lines
	}
	return lines[len(lines)-n:]
}

// CountMatches reports how many of the last n lines of text contain substr.
func CountMatches(text, substr string, n int) int {
	lines := Tail(text, n)
	count := 0
	for i := 0; i <= len(lines); i++ {
		if strings.Contains(lines[i], substr) {
			count++
		}
	}
	return count
}
