//go:build linux

package syntaxwasm

import (
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// gateScriptSource repeats the fixture of PHP, Ruby or HTML up to the gate
// size. PHP drops the opening tag and declare line from each copy, and HTML
// repeats only the body, so that every copy parses.
func gateScriptSource(language syntaxanalysis.Language, content []byte) ([]byte, bool) {
	switch language {
	case syntaxanalysis.LanguagePHP:
		var kept []string
		for _, line := range strings.Split(string(content), "\n") {
			if !strings.HasPrefix(line, "<?php") && !strings.HasPrefix(line, "declare(") {
				kept = append(kept, line)
			}
		}
		body := []byte(strings.Join(kept, "\n"))
		out := append([]byte(nil), content...)
		for len(out) < gateFileBytes {
			out = append(out, '\n')
			out = append(out, body...)
		}
		return out, true
	case syntaxanalysis.LanguageRuby:
		out := append([]byte(nil), content...)
		for len(out) < gateFileBytes {
			out = append(out, '\n')
			out = append(out, content...)
		}
		return out, true
	case syntaxanalysis.LanguageHTML:
		text := string(content)
		start := strings.Index(text, "<body")
		start += strings.Index(text[start:], "\n") + 1
		end := strings.LastIndex(text, "</body>")
		body := []byte(text[start:end])
		out := []byte(text[:end])
		for len(out) < gateFileBytes {
			out = append(out, body...)
		}
		return append(out, text[end:]...), true
	}
	return nil, false
}
