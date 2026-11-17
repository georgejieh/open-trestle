package syntaxwasm

import (
	"bytes"
	"sort"

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
	rubyVisibility(content, a)
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

// rubyScope holds what the visibility calls inside one class or module say.
type rubyScope struct {
	// sections are the bare keywords in source order.
	sections []rubySection
	// byStart and byName hold the visibility given to a def that follows a
	// keyword on the same line, by its start offset, and to the symbols
	// listed after a keyword, by name.
	byStart map[int]string
	byName  map[string]string
	// classByStart and classByName are the same for private_class_method
	// and public_class_method.
	classByStart map[int]string
	classByName  map[string]string
	// hidden holds the names listed after private_constant.
	hidden map[string]bool
}

type rubySection struct {
	at         int
	visibility string
}

func newRubyScope() *rubyScope {
	return &rubyScope{
		byStart: map[int]string{}, byName: map[string]string{},
		classByStart: map[int]string{}, classByName: map[string]string{},
		hidden: map[string]bool{},
	}
}

// rubyScopes reads the visibility calls of a file, grouped by the class or
// module that contains them.
func rubyScopes(content []byte, a *syntaxanalysis.FileAnalysis) map[int]*rubyScope {
	scopes := map[int]*rubyScope{}
	for _, r := range a.References {
		if r.Enclosing < 0 || !r.Qualifier.Empty() {
			continue
		}
		name := r.Name.Untrusted()
		switch name {
		case "private", "protected", "public", "module_function", "private_constant", "private_class_method", "public_class_method":
		default:
			continue
		}
		scope := scopes[r.Enclosing]
		if scope == nil {
			scope = newRubyScope()
			scopes[r.Enclosing] = scope
		}
		start, symbols := rubyArguments(content, r.Range.EndByte)
		switch name {
		case "private", "protected", "public", "module_function":
			visibility := name
			if name == "module_function" {
				visibility = "public"
			}
			switch {
			case rubyBare(content, r.Range.EndByte):
				scope.sections = append(scope.sections, rubySection{at: r.Range.StartByte, visibility: visibility})
			default:
				scope.byStart[start] = visibility
				for _, symbol := range symbols {
					scope.byName[symbol] = visibility
				}
			}
		case "private_constant":
			for _, symbol := range symbols {
				scope.hidden[symbol] = true
			}
		default:
			visibility := "private"
			if name == "public_class_method" {
				visibility = "public"
			}
			scope.classByStart[start] = visibility
			for _, symbol := range symbols {
				scope.classByName[symbol] = visibility
			}
		}
	}
	return scopes
}

func rubyVisibility(content []byte, a *syntaxanalysis.FileAnalysis) {
	defs := a.Definitions
	scopes := rubyScopes(content, a)
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
		scope := scopes[d.Parent]
		switch d.Kind {
		case syntaxanalysis.KindField:
			d.Exported = false
		case syntaxanalysis.KindFunction, syntaxanalysis.KindMethod, syntaxanalysis.KindConstructor:
			d.Exported = parent.Exported && scope.methodVisibility(content, d) == "public"
		default:
			d.Exported = parent.Exported && (scope == nil || !scope.hidden[d.Name.Untrusted()])
		}
	}
}

// methodVisibility returns the visibility of a method: public, protected or
// private. A def self. method ignores the bare keywords, as Ruby does, and
// follows private_class_method instead. A scope may be nil.
func (s *rubyScope) methodVisibility(content []byte, d *syntaxanalysis.Definition) string {
	if s == nil {
		return "public"
	}
	start, name := d.Range.StartByte, d.Name.Untrusted()
	if rubySelfMethod(content, start) {
		if visibility, ok := s.classByStart[start]; ok {
			return visibility
		}
		if visibility, ok := s.classByName[name]; ok {
			return visibility
		}
		return "public"
	}
	if visibility, ok := s.byStart[start]; ok {
		return visibility
	}
	if visibility, ok := s.byName[name]; ok {
		return visibility
	}
	at := sort.Search(len(s.sections), func(i int) bool { return s.sections[i].at >= start })
	if at > 0 {
		return s.sections[at-1].visibility
	}
	return "public"
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

// rubyArguments reads what follows a keyword: the offset where its first
// argument starts, which is the start of the def in private def name, and
// the symbols of a list such as private :a, :b.
func rubyArguments(content []byte, pos int) (int, []string) {
	i := skipBlanks(content, pos)
	if i < len(content) && content[i] == '(' {
		i = skipBlanks(content, i+1)
	}
	start := i
	var symbols []string
	for i < len(content) && content[i] == ':' {
		j := i + 1
		for j < len(content) && ((isWordByte(content[j]) && content[j] != '\\') || content[j] == '?' || content[j] == '!') {
			j++
		}
		if j < len(content) && content[j] == '=' && (j+1 >= len(content) || content[j+1] != '>') {
			j++
		}
		symbols = append(symbols, string(content[i+1:j]))
		i = skipBlanks(content, j)
		if i >= len(content) || content[i] != ',' {
			break
		}
		i = skipBlanks(content, i+1)
		for i < len(content) && (content[i] == '\n' || content[i] == '\r') {
			i = skipBlanks(content, i+1)
		}
	}
	return start, symbols
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
