package syntaxwasm

import (
	"bytes"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishRuby marks constructors, applies visibility, folds singleton
// classes into their enclosing definition and drops constructor calls that
// a construction record already describes.
//
// A class << self block is recorded by the query only so that its methods
// and its visibility keywords have a scope; it is removed here, and its
// methods then belong to the class around it. Visibility follows the
// keywords private, protected, public and module_function, alone on a line
// or applied to a def or a list of symbols, and private_constant and
// private_class_method. A def self. method is not affected by a bare
// keyword. Class variables are not exported. Names defined by attr_*
// calls or define_method are not recorded at all.
func finishRuby(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	defs := a.Definitions
	singleton := make([]bool, len(defs))
	for i, d := range defs {
		singleton[i] = d.Kind == syntaxanalysis.KindClass && rubySingletonClass(content, d.Range.StartByte)
		if d.Kind == syntaxanalysis.KindMethod && d.Name.Untrusted() == "initialize" && d.Parent >= 0 && defs[d.Parent].Kind == syntaxanalysis.KindClass {
			defs[i].Kind = syntaxanalysis.KindConstructor
		}
	}
	rubyVisibility(content, a, singleton)
	rubyFoldSingletons(a, singleton)
	kept := a.References[:0]
	for _, r := range a.References {
		qualifier := r.Qualifier.Untrusted()
		if r.Kind == syntaxanalysis.ReferenceCall && r.Name.Untrusted() == "new" && qualifier != "" && qualifier[0] >= 'A' && qualifier[0] <= 'Z' {
			continue
		}
		kept = append(kept, r)
	}
	a.References = kept
}

func rubySingletonClass(content []byte, start int) bool {
	rest := content[start:]
	if !bytes.HasPrefix(rest, []byte("class")) {
		return false
	}
	rest = bytes.TrimLeft(rest[len("class"):], " \t")
	return bytes.HasPrefix(rest, []byte("<<"))
}

// rubySelfMethod reports whether the definition starting at start is
// written def self.name.
func rubySelfMethod(content []byte, start int) bool {
	rest := content[start:]
	if !bytes.HasPrefix(rest, []byte("def")) {
		return false
	}
	rest = bytes.TrimLeft(rest[len("def"):], " \t")
	return bytes.HasPrefix(rest, []byte("self."))
}

func rubyVisibility(content []byte, a *syntaxanalysis.FileAnalysis, singleton []bool) {
	defs := a.Definitions
	calls := map[int][]int{}
	for i, r := range a.References {
		if r.Enclosing < 0 || !r.Qualifier.Empty() {
			continue
		}
		switch r.Name.Untrusted() {
		case "private", "protected", "public", "module_function", "private_constant", "private_class_method", "public_class_method":
			calls[r.Enclosing] = append(calls[r.Enclosing], i)
		}
	}
	for i := range defs {
		d := &defs[i]
		if d.Parent < 0 {
			d.Exported = d.Kind != syntaxanalysis.KindField
			continue
		}
		parent := defs[d.Parent]
		if parent.Kind != syntaxanalysis.KindClass && parent.Kind != syntaxanalysis.KindModule {
			d.Exported = false
			continue
		}
		switch d.Kind {
		case syntaxanalysis.KindField:
			d.Exported = false
		case syntaxanalysis.KindFunction, syntaxanalysis.KindMethod, syntaxanalysis.KindConstructor:
			d.Exported = parent.Exported && rubyMethodVisibility(content, a, calls[d.Parent], d, singleton[d.Parent]) == "public"
		default:
			d.Exported = parent.Exported && !rubyListed(content, a, calls[d.Parent], "private_constant", d)
		}
	}
}

// rubyMethodVisibility returns the visibility of a method: public,
// protected or private.
func rubyMethodVisibility(content []byte, a *syntaxanalysis.FileAnalysis, calls []int, d *syntaxanalysis.Definition, inSingleton bool) string {
	visibility := "public"
	selfMethod := !inSingleton && rubySelfMethod(content, d.Range.StartByte)
	if !selfMethod {
		for _, at := range calls {
			r := a.References[at]
			if r.Range.StartByte >= d.Range.StartByte {
				break
			}
			if !rubyBare(content, r.Range.EndByte) {
				continue
			}
			switch name := r.Name.Untrusted(); name {
			case "private", "protected":
				visibility = name
			case "public", "module_function":
				visibility = "public"
			}
		}
	}
	for _, at := range calls {
		r := a.References[at]
		switch name := r.Name.Untrusted(); name {
		case "private", "protected", "public":
			if !selfMethod && rubyTargets(content, r.Range.EndByte, d) {
				visibility = name
			}
		case "private_class_method", "public_class_method":
			if selfMethod && rubyTargets(content, r.Range.EndByte, d) {
				visibility = "private"
				if name == "public_class_method" {
					visibility = "public"
				}
			}
		}
	}
	return visibility
}

func rubyListed(content []byte, a *syntaxanalysis.FileAnalysis, calls []int, keyword string, d *syntaxanalysis.Definition) bool {
	for _, at := range calls {
		r := a.References[at]
		if r.Name.Untrusted() == keyword && rubyTargets(content, r.Range.EndByte, d) {
			return true
		}
	}
	return false
}

// rubyBare reports whether the rest of the line after pos is empty or a
// comment, so that a visibility keyword there applies to what follows.
func rubyBare(content []byte, pos int) bool {
	pos = skipBlanks(content, pos)
	return pos >= len(content) || content[pos] == '\n' || content[pos] == '\r' || content[pos] == ';' || content[pos] == '#'
}

func skipBlanks(content []byte, pos int) int {
	for pos < len(content) && (content[pos] == ' ' || content[pos] == '\t') {
		pos++
	}
	return pos
}

// rubyTargets reports whether the arguments written after pos name the
// definition: either the def itself follows, or a list of symbols includes
// its name.
func rubyTargets(content []byte, pos int, d *syntaxanalysis.Definition) bool {
	i := skipBlanks(content, pos)
	if i < len(content) && content[i] == '(' {
		i = skipBlanks(content, i+1)
	}
	if i == d.Range.StartByte {
		return true
	}
	for i < len(content) && content[i] == ':' {
		j := i + 1
		for j < len(content) && ((isWordByte(content[j]) && content[j] != '\\') || content[j] == '?' || content[j] == '!') {
			j++
		}
		if j < len(content) && content[j] == '=' && (j+1 >= len(content) || content[j+1] != '>') {
			j++
		}
		if string(content[i+1:j]) == d.Name.Untrusted() {
			return true
		}
		i = skipBlanks(content, j)
		if i >= len(content) || content[i] != ',' {
			break
		}
		i = skipBlanks(content, i+1)
		for i < len(content) && (content[i] == '\n' || content[i] == '\r') {
			i = skipBlanks(content, i+1)
		}
	}
	return false
}

// rubyFoldSingletons removes the singleton-class definitions and points
// everything that referred to one at the definition around it.
func rubyFoldSingletons(a *syntaxanalysis.FileAnalysis, singleton []bool) {
	folded := false
	for _, s := range singleton {
		folded = folded || s
	}
	if !folded {
		return
	}
	mapped := make([]int, len(a.Definitions))
	remap := func(i int) int {
		if i < 0 {
			return -1
		}
		return mapped[i]
	}
	kept := make([]syntaxanalysis.Definition, 0, len(a.Definitions))
	for i, d := range a.Definitions {
		if singleton[i] {
			mapped[i] = remap(d.Parent)
			continue
		}
		mapped[i] = len(kept)
		d.Parent = remap(d.Parent)
		kept = append(kept, d)
	}
	for i := range kept {
		d := &kept[i]
		if d.Kind == syntaxanalysis.KindMethod && (d.Parent < 0 || !kept[d.Parent].Kind.Container()) {
			d.Kind = syntaxanalysis.KindFunction
		}
	}
	a.Definitions = kept
	for i := range a.References {
		a.References[i].Enclosing = remap(a.References[i].Enclosing)
	}
	for i := range a.Imports {
		a.Imports[i].Enclosing = remap(a.Imports[i].Enclosing)
	}
}
