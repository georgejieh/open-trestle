// Package slug derives URL path segments from titles.
package slug

import (
	"strings"
	"unicode"
)

// Make lowercases title, keeps ASCII letters and digits, and joins the runs
// between other characters with single hyphens.
func Make(title string) string {
	words := strings.FieldsFunc(strings.ToLower(title), func(r rune) bool {
		return r > unicode.MaxASCII || !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	return strings.Join(words, "-")
}
