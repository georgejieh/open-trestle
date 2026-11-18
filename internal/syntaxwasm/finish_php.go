package syntaxwasm

import (
	"bytes"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishPHP marks constructors and applies PHP's visibility: anything at
// file or namespace level is reachable from other files, a class member is
// public unless it carries a private or protected modifier, and
// declarations inside a function are not exported. It also drops the
// relative class names self, static and parent, which name no declaration.
func finishPHP(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	extendToFileScopes(content, a, phpUnbracedNamespaces(content, a))
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind == syntaxanalysis.KindMethod && strings.EqualFold(d.Name.Untrusted(), "__construct") {
			d.Kind = syntaxanalysis.KindConstructor
		}
	}
	phpPromoteProperties(content, a)
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Parent < 0 {
			d.Exported = true
			continue
		}
		parent := a.Definitions[d.Parent]
		switch {
		case parent.Kind == syntaxanalysis.KindModule:
			d.Exported = true
		case parent.Kind.Container():
			d.Exported = !phpRestricted(content, d.Range.StartByte, d.NameRange.StartByte)
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

// phpPromoteProperties makes a property declared in a constructor's
// parameter list a field of the class: its parent becomes the class, which
// it also names as its container, since it is written inside the
// constructor. A property declared in the constructor of an anonymous
// class, which has no record, is dropped. A promoted parameter is a field
// child of a constructor whose text does not end in a semicolon, unlike a
// property declaration.
func phpPromoteProperties(content []byte, a *syntaxanalysis.FileAnalysis) {
	var drop []bool
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind != syntaxanalysis.KindField || d.Parent < 0 || d.Range.EndByte <= d.Range.StartByte || d.Range.EndByte > len(content) || content[d.Range.EndByte-1] == ';' {
			continue
		}
		constructor := a.Definitions[d.Parent]
		if constructor.Kind != syntaxanalysis.KindConstructor {
			continue
		}
		if owner := constructor.Parent; owner >= 0 && a.Definitions[owner].Kind.Container() {
			d.Parent = owner
			d.Container = a.Definitions[owner].Name
			continue
		}
		if drop == nil {
			drop = make([]bool, len(a.Definitions))
		}
		drop[i] = true
	}
	if drop != nil {
		removeDefinitions(a, drop)
	}
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
		case identByte(c) || c == '\\':
			j := i
			for j < end && (identByte(content[j]) || content[j] == '\\') {
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

// phpUnbracedNamespaces returns the namespaces declared without braces,
// each covering the file up to the next one, as PHP scopes them.
func phpUnbracedNamespaces(content []byte, a *syntaxanalysis.FileAnalysis) []fileScope {
	var scopes []fileScope
	for i, d := range a.Definitions {
		if d.Kind == syntaxanalysis.KindModule && d.Parent < 0 && d.Range.EndByte > 0 && content[d.Range.EndByte-1] == ';' {
			if n := len(scopes); n > 0 {
				scopes[n-1].end = d.Range.StartByte
			}
			scopes = append(scopes, fileScope{index: i, end: len(content)})
		}
	}
	return scopes
}
