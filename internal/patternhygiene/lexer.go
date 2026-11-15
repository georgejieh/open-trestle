package patternhygiene

import "strings"

// Language is a source language the detectors understand.
type Language string

const (
	LanguageGo         Language = "go"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguagePython     Language = "python"
)

// LanguageOf returns the language of a repository path by its extension.
func LanguageOf(path string) (Language, bool) {
	switch {
	case strings.HasSuffix(path, ".go"):
		return LanguageGo, true
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".jsx"), strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".cjs"):
		return LanguageJavaScript, true
	case strings.HasSuffix(path, ".ts"), strings.HasSuffix(path, ".tsx"), strings.HasSuffix(path, ".mts"), strings.HasSuffix(path, ".cts"):
		return LanguageTypeScript, true
	case strings.HasSuffix(path, ".py"):
		return LanguagePython, true
	}
	return "", false
}

// lexedLine is one physical source line split into code and comment text.
// String and character literal contents are blanked from code, so a pattern
// inside a string never matches as code; comment text is kept verbatim.
type lexedLine struct {
	code    string
	comment string
}

type lexState uint8

const (
	stateCode lexState = iota
	stateBlockComment
	stateRawString    // Go raw string or JavaScript template literal
	stateTripleSingle // Python '''
	stateTripleDouble // Python """
)

// lexLines splits content into lines and classifies each line's characters as
// code, comment or literal for one language. It is a small line lexer, not a
// parser: it tracks block comments and multi-line strings across lines, and
// treats a JavaScript template literal's ${...} parts as literal text.
func lexLines(language Language, content string) []lexedLine {
	lines := strings.Split(content, "\n")
	out := make([]lexedLine, len(lines))
	state := stateCode
	var rawQuote byte
	for index, line := range lines {
		var code, comment strings.Builder
		position := 0
		for position < len(line) {
			character := line[position]
			switch state {
			case stateBlockComment:
				if strings.HasPrefix(line[position:], "*/") {
					state = stateCode
					position += 2
					continue
				}
				comment.WriteByte(character)
				position++
				continue
			case stateRawString:
				if character == '\\' && rawQuote == '`' && language != LanguageGo && position+1 < len(line) {
					position += 2
					continue
				}
				if character == rawQuote {
					state = stateCode
					code.WriteByte(character)
				}
				position++
				continue
			case stateTripleSingle, stateTripleDouble:
				quote := `'''`
				if state == stateTripleDouble {
					quote = `"""`
				}
				if character == '\\' && position+1 < len(line) {
					position += 2
					continue
				}
				if strings.HasPrefix(line[position:], quote) {
					state = stateCode
					code.WriteString(quote)
					position += 3
					continue
				}
				position++
				continue
			}
			// Code state.
			if language == LanguagePython {
				if character == '#' {
					comment.WriteString(line[position+1:])
					position = len(line)
					continue
				}
				if strings.HasPrefix(line[position:], `"""`) || strings.HasPrefix(line[position:], `'''`) {
					if line[position] == '"' {
						state = stateTripleDouble
					} else {
						state = stateTripleSingle
					}
					code.WriteString(line[position : position+3])
					position += 3
					continue
				}
			} else {
				if strings.HasPrefix(line[position:], "//") {
					comment.WriteString(line[position+2:])
					position = len(line)
					continue
				}
				if strings.HasPrefix(line[position:], "/*") {
					state = stateBlockComment
					position += 2
					continue
				}
				if character == '`' {
					state, rawQuote = stateRawString, '`'
					code.WriteByte(character)
					position++
					continue
				}
			}
			if character == '"' || character == '\'' {
				code.WriteByte(character)
				position++
				for position < len(line) && line[position] != character {
					if line[position] == '\\' {
						position++
					}
					position++
				}
				if position < len(line) {
					code.WriteByte(character)
					position++
				}
				continue
			}
			code.WriteByte(character)
			position++
		}
		out[index] = lexedLine{code: code.String(), comment: comment.String()}
	}
	return out
}
