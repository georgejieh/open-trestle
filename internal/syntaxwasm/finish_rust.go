package syntaxwasm

import (
	"slices"
	"strings"
	"unicode"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishRust applies the visibility that members take from their owner and
// removes what the syntax only seems to define. The members of a trait take
// the trait's visibility, enum variants take the enum's, and the members of
// an impl of a trait are exported because the query marks such an impl
// exported; a member of an inherent impl is exported only by its own `pub`.
// An impl named after one of its own type parameters, as in a blanket
// impl, is not a definition of any type. The name Self is a keyword for the
// enclosing type, so it is not kept as a reference.
func finishRust(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Parent < 0 {
			continue
		}
		if parent := a.Definitions[d.Parent]; parent.Exported {
			switch parent.Kind {
			case syntaxanalysis.KindInterface, syntaxanalysis.KindClass:
				d.Exported = true
			case syntaxanalysis.KindEnum:
				d.Exported = d.Exported || d.Kind == syntaxanalysis.KindConstant
			}
		}
	}
	for i := len(a.Definitions) - 1; i >= 0; i-- {
		d := a.Definitions[i]
		if d.Kind == syntaxanalysis.KindClass && rustImplParameters(content, d)[d.Name.Untrusted()] {
			removeDefinition(a, i)
		}
	}
	a.References = slices.DeleteFunc(a.References, func(r syntaxanalysis.Reference) bool {
		return r.Name.Untrusted() == "Self"
	})
}

// rustImplParameters returns the names of the type and const parameters
// declared in the generics of an impl header, such as T in `impl<T> X for T`.
func rustImplParameters(content []byte, d syntaxanalysis.Definition) map[string]bool {
	header := string(content[d.Range.StartByte:d.NameRange.StartByte])
	header = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(header), "unsafe"))
	header = strings.TrimSpace(strings.TrimPrefix(header, "impl"))
	params := map[string]bool{}
	if !strings.HasPrefix(header, "<") {
		return params
	}
	depth, start := 0, 1
	segment := func(end int) {
		text := strings.TrimSpace(header[start:end])
		text = strings.TrimSpace(strings.TrimPrefix(text, "const "))
		if text == "" || text[0] == '\'' {
			return
		}
		end = strings.IndexFunc(text, func(r rune) bool { return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) })
		if end < 0 {
			end = len(text)
		}
		params[text[:end]] = true
	}
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '<', '(', '[':
			depth++
		case ')', ']':
			depth--
		case '>':
			if i > 0 && header[i-1] == '-' {
				continue
			}
			depth--
			if depth == 0 {
				segment(i)
				return params
			}
		case ',':
			if depth == 1 {
				segment(i)
				start = i + 1
			}
		}
	}
	return map[string]bool{}
}

// removeDefinition drops one definition and keeps every index that referred
// to it or to a later definition valid: its members move up to its parent.
func removeDefinition(a *syntaxanalysis.FileAnalysis, at int) {
	up := a.Definitions[at].Parent
	remap := func(i int) int {
		switch {
		case i == at:
			return up
		case i > at:
			return i - 1
		}
		return i
	}
	a.Definitions = slices.Delete(a.Definitions, at, at+1)
	for i := range a.Definitions {
		a.Definitions[i].Parent = remap(a.Definitions[i].Parent)
	}
	for i := range a.References {
		a.References[i].Enclosing = remap(a.References[i].Enclosing)
	}
	for i := range a.Imports {
		a.Imports[i].Enclosing = remap(a.Imports[i].Enclosing)
	}
}
