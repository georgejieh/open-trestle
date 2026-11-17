package syntaxwasm

import (
	"bytes"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishPHP marks constructors and applies PHP's visibility: anything at
// file or namespace level is reachable from other files, a class member is
// public unless it carries a private or protected modifier, and interface
// members are always public. Members of a type that is not exported, and
// declarations inside a function, are not exported. It also drops the
// relative class names self, static and parent, which name no declaration.
func finishPHP(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	phpFoldNamespaces(content, a)
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind == syntaxanalysis.KindMethod && strings.EqualFold(d.Name.Untrusted(), "__construct") {
			d.Kind = syntaxanalysis.KindConstructor
		}
		if d.Parent < 0 {
			d.Exported = true
			continue
		}
		parent := a.Definitions[d.Parent]
		switch {
		case parent.Kind == syntaxanalysis.KindModule:
			d.Exported = true
		case parent.Kind.Container():
			d.Exported = parent.Exported && (parent.Kind == syntaxanalysis.KindInterface || !phpRestricted(content, d.Range.StartByte, d.NameRange.StartByte))
		default:
			d.Exported = false
		}
	}
	kept := a.References[:0]
	for _, r := range a.References {
		if r.Kind == syntaxanalysis.ReferenceConstruct || r.Kind == syntaxanalysis.ReferenceType {
			switch strings.ToLower(r.Name.Untrusted()) {
			case "self", "static", "parent":
				continue
			}
		}
		kept = append(kept, r)
	}
	a.References = kept
}

// phpRestricted reports whether the modifiers in content[start:end], the
// text of a member before its name, include private or protected. It skips
// attribute lists and comments, which can contain those words.
func phpRestricted(content []byte, start, end int) bool {
	for i := start; i < end; {
		c := content[i]
		switch {
		case c == '#' && i+1 < end && content[i+1] == '[':
			i = skipBracketed(content, i+1, end)
		case c == '#' || (c == '/' && i+1 < end && content[i+1] == '/'):
			for i < end && content[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < end && content[i+1] == '*':
			if at := bytes.Index(content[i+2:end], []byte("*/")); at >= 0 {
				i += at + 4
			} else {
				i = end
			}
		case isWordByte(c):
			j := i
			for j < end && isWordByte(content[j]) {
				j++
			}
			word := string(content[i:j])
			if strings.EqualFold(word, "private") || strings.EqualFold(word, "protected") {
				return true
			}
			i = j
		default:
			i++
		}
	}
	return false
}

// skipBracketed returns the index after the bracket that closes the one at
// content[open], ignoring brackets inside quoted strings.
func skipBracketed(content []byte, open, end int) int {
	depth := 0
	for i := open; i < end; i++ {
		switch c := content[i]; c {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		case '\'', '"':
			for i++; i < end && content[i] != c; i++ {
				if content[i] == '\\' {
					i++
				}
			}
		}
	}
	return end
}

func isWordByte(c byte) bool {
	return c == '_' || c == '\\' || c >= 0x80 || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// phpFoldNamespaces extends a namespace declared without braces to the next
// namespace declaration or the end of the file, as PHP scopes it, and makes
// the definitions, references and imports in that stretch belong to it.
func phpFoldNamespaces(content []byte, a *syntaxanalysis.FileAnalysis) {
	var spaces []int
	for i, d := range a.Definitions {
		if d.Kind == syntaxanalysis.KindModule && d.Parent < 0 && d.Range.EndByte > 0 && content[d.Range.EndByte-1] == ';' {
			spaces = append(spaces, i)
		}
	}
	for n, i := range spaces {
		d := &a.Definitions[i]
		end := len(content)
		if n+1 < len(spaces) {
			end = a.Definitions[spaces[n+1]].Range.StartByte
		}
		d.Range.EndByte = end
		d.Range.End = phpPosition(content, end)
		for j := i + 1; j < len(a.Definitions) && a.Definitions[j].Range.StartByte < end; j++ {
			if a.Definitions[j].Parent < 0 {
				a.Definitions[j].Parent = i
			}
		}
		for j := range a.References {
			if r := &a.References[j]; r.Enclosing < 0 && r.Range.StartByte >= d.Range.StartByte && r.Range.StartByte < end {
				r.Enclosing = i
			}
		}
		for j := range a.Imports {
			if m := &a.Imports[j]; m.Enclosing < 0 && m.Range.StartByte >= d.Range.StartByte && m.Range.StartByte < end {
				m.Enclosing = i
			}
		}
	}
}

// phpPosition returns the 1-based line and byte column of an offset.
func phpPosition(content []byte, offset int) syntaxanalysis.Position {
	line := 1 + bytes.Count(content[:offset], []byte{'\n'})
	return syntaxanalysis.Position{Line: line, Column: offset - bytes.LastIndexByte(content[:offset], '\n')}
}
