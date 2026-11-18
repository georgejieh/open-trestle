package syntaxwasm

import (
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishRust sets the visibility the syntax implies and removes what it
// only seems to define. The members of a trait and the variants of an enum
// are as visible as their owner, and so are the members of an impl of a
// trait, because the trait decides who can call them; a member of an
// inherent impl is exported by its own `pub`. An impl block has no
// visibility of its own. An impl named after one of its own type
// parameters, as in a blanket impl, is not a definition of any type. The
// name Self is a keyword for the enclosing type, so it is not kept as a
// reference.
func finishRust(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	drop := make([]bool, len(a.Definitions))
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind == syntaxanalysis.KindClass {
			// The query marks the impl of a trait exported.
			traitImpl := d.Exported
			d.Exported = true
			drop[i] = rustImplParameters(content, *d)[d.Name.Untrusted()]
			for j := i + 1; j < len(a.Definitions) && a.Definitions[j].Range.StartByte < d.Range.EndByte; j++ {
				if a.Definitions[j].Parent == i && traitImpl {
					a.Definitions[j].Exported = true
				}
			}
			continue
		}
		if d.Parent < 0 {
			continue
		}
		switch a.Definitions[d.Parent].Kind {
		case syntaxanalysis.KindInterface:
			d.Exported = true
		case syntaxanalysis.KindEnum:
			d.Exported = d.Exported || d.Kind == syntaxanalysis.KindConstant
		}
	}
	removeDefinitions(a, drop)
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
		end = 0
		for end < len(text) && identByte(text[end]) {
			end++
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
