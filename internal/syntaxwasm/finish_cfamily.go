package syntaxwasm

import (
	"path"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishC applies the rules of C that the syntax tree does not carry.
func finishC(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	finishCFamily(content, a)
}

// finishCPP applies the rules of C++ that the syntax tree does not carry.
func finishCPP(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	finishCFamily(content, a)
}

// finishCFamily drops declarations that belong to function bodies, names
// constructors and out-of-line methods, removes cast operators from the
// call references, sets the exported flag and gives each declarator of a
// declaration its own range.
//
// A declaration inside a preprocessor conditional matches the same query
// shape whether it sits at file scope or in a block, so the block ones are
// removed here by their enclosing definition.
func finishCFamily(content []byte, a *syntaxanalysis.FileAnalysis) {
	dropBlockDeclarations(content, a)
	dropMacroMembers(content, a)
	dropCastCalls(a)
	markConstants(content, a)
	nameConstructors(a)
	setExported(content, a)
	splitDeclarators(content, a)
}

func isFunctionLike(k syntaxanalysis.DefinitionKind) bool {
	return k == syntaxanalysis.KindFunction || k == syntaxanalysis.KindMethod || k == syntaxanalysis.KindConstructor
}

func isClassLike(k syntaxanalysis.DefinitionKind) bool {
	return k == syntaxanalysis.KindClass || k == syntaxanalysis.KindStruct
}

// dropBlockDeclarations removes variable, constant and function
// declarations (definitions whose text ends with a semicolon) that have a
// function, a variable or a constant among their ancestors.
func dropBlockDeclarations(content []byte, a *syntaxanalysis.FileAnalysis) {
	drop := make([]bool, len(a.Definitions))
	// inBlock marks the definitions with a function, variable or constant
	// among their ancestors. Parents come before their children.
	inBlock := make([]bool, len(a.Definitions))
	found := false
	for i, d := range a.Definitions {
		if d.Parent >= 0 {
			k := a.Definitions[d.Parent].Kind
			inBlock[i] = inBlock[d.Parent] || isFunctionLike(k) || k == syntaxanalysis.KindVariable || k == syntaxanalysis.KindConstant
		}
		switch d.Kind {
		case syntaxanalysis.KindVariable, syntaxanalysis.KindConstant, syntaxanalysis.KindFunction:
		default:
			continue
		}
		if inBlock[i] && d.Range.EndByte > d.Range.StartByte && content[d.Range.EndByte-1] == ';' {
			drop[i] = true
			found = true
		}
	}
	if found {
		removeDefinitions(a, drop)
	}
}

// dropCastCalls removes the C++ cast keywords, which parse as calls.
func dropCastCalls(a *syntaxanalysis.FileAnalysis) {
	kept := a.References[:0]
	for _, r := range a.References {
		if r.Kind == syntaxanalysis.ReferenceCall {
			switch r.Name.Untrusted() {
			case "static_cast", "dynamic_cast", "reinterpret_cast", "const_cast":
				continue
			}
		}
		kept = append(kept, r)
	}
	a.References = kept
}

// declarationPrefix returns the text of a definition before its name, at
// most maxLeadingBytes from its start; the specifiers come first.
func declarationPrefix(content []byte, d *syntaxanalysis.Definition) []byte {
	return content[d.Range.StartByte:min(d.NameRange.StartByte, d.Range.StartByte+maxLeadingBytes)]
}

const maxLeadingBytes = 512

// markConstants turns the variables of a file or namespace, and the static
// data members of a class, into constants when nothing can reassign them: a
// const that qualifies the declared type (not a pointed-to type), a const
// pointer, or constexpr. Only the specifiers and the definition's own
// declarator count; the initializers of earlier declarators are skipped.
func markConstants(content []byte, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind != syntaxanalysis.KindVariable && d.Kind != syntaxanalysis.KindField {
			continue
		}
		static, constexpr, specConst, afterStarConst, star, initializer := false, false, false, false, false, false
		angle, depth := 0, 0
		lexCode(declarationPrefix(content, d), func(token byte, _ int, word string) bool {
			switch token {
			case '(', '[', '{':
				depth++
			case ')', ']', '}':
				depth = max(0, depth-1)
			}
			if initializer {
				if token == ',' && depth == 0 {
					initializer, star, afterStarConst = false, false, false
				}
				return true
			}
			switch token {
			case 'w':
				switch word {
				case "static":
					static = true
				case "constexpr":
					constexpr = true
				case "const":
					if star {
						afterStarConst = true
					} else if angle == 0 {
						specConst = true
					}
				}
			case '*', '&':
				star, afterStarConst = true, false
			case ',':
				star, afterStarConst = false, false
			case '=':
				initializer = depth == 0
			case '<':
				angle++
			case '>':
				angle = max(0, angle-1)
			}
			return true
		})
		if d.Kind == syntaxanalysis.KindField && !static {
			continue
		}
		if constexpr || (star && afterStarConst) || (!star && specConst) {
			d.Kind = syntaxanalysis.KindConstant
		}
	}
}

// dropMacroMembers removes the members of a class that look like a
// constructor of another name: a plain name, no return type and no
// destructor tilde, as in a macro invocation that declares members. The
// type references inside such a member are macro arguments and go with it.
func dropMacroMembers(content []byte, a *syntaxanalysis.FileAnalysis) {
	drop := make([]bool, len(a.Definitions))
	var spans []syntaxanalysis.Span
	for i, d := range a.Definitions {
		if d.Kind != syntaxanalysis.KindFunction && d.Kind != syntaxanalysis.KindMethod || d.Parent < 0 || !isClassLike(a.Definitions[d.Parent].Kind) {
			continue
		}
		name := d.Name.Untrusted()
		if name == a.Definitions[d.Parent].Name.Untrusted() || strings.HasPrefix(name, "~") || !d.Container.Empty() {
			continue
		}
		typed := false
		for word := range codeWords(declarationPrefix(content, &a.Definitions[i])) {
			switch word {
			case "explicit", "constexpr", "consteval", "inline":
			default:
				typed = true
			}
		}
		if !typed && isPlainName(name) {
			drop[i] = true
			spans = append(spans, syntaxanalysis.Span{Start: d.Range.StartByte, End: d.Range.EndByte})
		}
	}
	if len(spans) == 0 {
		return
	}
	removeDefinitions(a, drop)
	merged := mergeSpans(spans)
	kept := a.References[:0]
	for _, r := range a.References {
		if r.Kind != syntaxanalysis.ReferenceType || !insideSpans(merged, r.Range.StartByte) {
			kept = append(kept, r)
		}
	}
	a.References = kept
}

func isPlainName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !identByte(name[i]) {
			return false
		}
	}
	return name != ""
}

// nameConstructors turns a function named like its class into a
// constructor, and a function defined out of line as Owner::name into a
// method unless Owner is a namespace of this file.
func nameConstructors(a *syntaxanalysis.FileAnalysis) {
	namespaces := map[string]bool{}
	for _, d := range a.Definitions {
		if d.Kind == syntaxanalysis.KindModule {
			name := d.Name.Untrusted()
			if at := strings.LastIndex(name, "::"); at >= 0 {
				name = name[at+2:]
			}
			namespaces[name] = true
		}
	}
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind != syntaxanalysis.KindFunction && d.Kind != syntaxanalysis.KindMethod {
			continue
		}
		name := d.Name.Untrusted()
		switch {
		case d.Parent >= 0 && isClassLike(a.Definitions[d.Parent].Kind) && name == a.Definitions[d.Parent].Name.Untrusted():
			d.Kind = syntaxanalysis.KindConstructor
		case !d.Container.Empty() && name == d.Container.Untrusted():
			d.Kind = syntaxanalysis.KindConstructor
		case !d.Container.Empty() && d.Kind == syntaxanalysis.KindFunction && !namespaces[d.Container.Untrusted()]:
			d.Kind = syntaxanalysis.KindMethod
		}
	}
}

// setExported decides what other files can reach, apart from the owners,
// which exportThroughOwners applies:
//
//   - a member of a class or struct when its access is public; a struct
//     member is public by default and a class member private;
//   - an enumerator;
//   - a function, variable or constant at file or namespace scope unless it
//     is static, and a const C++ variable only when it is extern or
//     declared in a header;
//   - a type, macro or alias declared in a header;
//   - a namespace unless it is anonymous; nothing inside a function.
func setExported(content []byte, a *syntaxanalysis.FileAnalysis) {
	header := isHeaderPath(a.Path)
	cpp := a.Language == syntaxanalysis.LanguageCPP
	access := memberAccess(content, a)
	for i := range a.Definitions {
		d := &a.Definitions[i]
		d.Exported = false
		var parent *syntaxanalysis.Definition
		if d.Parent >= 0 {
			parent = &a.Definitions[d.Parent]
		}
		switch {
		case parent != nil && parent.Kind == syntaxanalysis.KindEnum:
			d.Exported = true
		case parent != nil && isClassLike(parent.Kind):
			d.Exported = access[i] == "public"
		case parent != nil && parent.Kind != syntaxanalysis.KindModule:
			// Inside a function, a variable or another definition.
		default:
			switch d.Kind {
			case syntaxanalysis.KindModule:
				d.Exported = d.Name.Untrusted() != "namespace"
			case syntaxanalysis.KindFunction, syntaxanalysis.KindMethod, syntaxanalysis.KindConstructor, syntaxanalysis.KindVariable, syntaxanalysis.KindConstant:
				words := codeWords(declarationPrefix(content, d))
				d.Exported = !words["static"]
				if d.Kind == syntaxanalysis.KindConstant && cpp && !header {
					d.Exported = words["extern"]
				}
			default:
				d.Exported = header
			}
		}
	}
}

func isHeaderPath(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".h", ".hh", ".hpp", ".hxx":
		return true
	}
	return false
}

// memberAccess returns the access of every member of a class or struct,
// indexed like the definitions: the last access label before the member in
// its class body, or the default of the kind. It reads the file once, in
// source order, keeping the classes whose bodies are open.
func memberAccess(content []byte, a *syntaxanalysis.FileAnalysis) []string {
	type open struct {
		class, end, bodyDepth int
		current               string
	}
	access := make([]string, len(a.Definitions))
	var stack []open
	next, depth, pending := 0, 0, ""
	enter := func(pos int) {
		for next < len(a.Definitions) && a.Definitions[next].Range.StartByte <= pos {
			d := a.Definitions[next]
			for len(stack) > 0 && stack[len(stack)-1].end <= d.Range.StartByte {
				stack = stack[:len(stack)-1]
			}
			if d.Parent >= 0 && isClassLike(a.Definitions[d.Parent].Kind) {
				for k := len(stack) - 1; k >= 0; k-- {
					if stack[k].class == d.Parent {
						access[next] = stack[k].current
						break
					}
				}
			}
			if isClassLike(d.Kind) {
				current := "public"
				if d.Kind == syntaxanalysis.KindClass {
					current = "private"
				}
				stack = append(stack, open{class: next, end: d.Range.EndByte, bodyDepth: depth + 1, current: current})
			}
			next++
		}
	}
	lexCode(content, func(token byte, pos int, word string) bool {
		enter(pos)
		for len(stack) > 0 && stack[len(stack)-1].end <= pos {
			stack = stack[:len(stack)-1]
		}
		switch token {
		case '{':
			depth++
		case '}':
			depth--
		case 'w':
			pending = ""
			if n := len(stack); n > 0 && depth == stack[n-1].bodyDepth && (word == "public" || word == "private" || word == "protected") {
				pending = word
			}
			return true
		case ':':
			if n := len(stack); n > 0 && pending != "" {
				stack[n-1].current = pending
			}
		}
		pending = ""
		return true
	})
	enter(len(content))
	return access
}

// splitDeclarators gives each variable, constant or field declared in one
// declaration with others, as in `int a = f(), b = g();`, the range of its
// own declarator, from the comma before it, so that each initializer is
// enclosed by its own definition. The first keeps the specifiers. A
// declaration that also holds other definitions keeps its shared range.
func splitDeclarators(content []byte, a *syntaxanalysis.FileAnalysis) {
	var lines syntaxanalysis.LineIndex
	indexed := false
	defs := a.Definitions
	for i := 0; i < len(defs); {
		j := i + 1
		for j < len(defs) && defs[j].Range.StartByte == defs[i].Range.StartByte && defs[j].Range.EndByte == defs[i].Range.EndByte && defs[j].Parent == defs[i].Parent {
			j++
		}
		group := defs[i:j]
		if len(group) < 2 || !declaratorKinds(group) || (j < len(defs) && defs[j].Range.StartByte < defs[i].Range.EndByte) {
			i = j
			continue
		}
		if !indexed {
			lines, indexed = syntaxanalysis.NewLineIndex(content), true
		}
		start, end := group[0].Range.StartByte, group[0].Range.EndByte
		cuts := topLevelCommas(content[start:end])
		for k := range group {
			name := group[k].NameRange.StartByte - start
			from, to := 0, end-start
			for _, c := range cuts {
				if c < name {
					from = c
				} else {
					to = c
					break
				}
			}
			group[k].Range = lines.Range(syntaxanalysis.Span{Start: start + from, End: start + to})
		}
		for r := range a.References {
			if at := a.References[r].Range.StartByte; at >= start && at < end {
				a.References[r].Enclosing = a.EnclosingDefinition(at)
			}
		}
		i = j
	}
}

func declaratorKinds(group []syntaxanalysis.Definition) bool {
	for _, d := range group {
		switch d.Kind {
		case syntaxanalysis.KindVariable, syntaxanalysis.KindConstant, syntaxanalysis.KindField:
		default:
			return false
		}
	}
	return true
}

// topLevelCommas returns the offsets of the commas that separate the
// declarators of a declaration: outside brackets, template arguments and
// initializers' nested expressions.
func topLevelCommas(b []byte) []int {
	var cuts []int
	depth, angle, initializer := 0, 0, false
	lexCode(b, func(token byte, pos int, _ string) bool {
		switch token {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth = max(0, depth-1)
		case '<':
			if !initializer {
				angle++
			}
		case '>':
			if !initializer {
				angle = max(0, angle-1)
			}
		case '=':
			initializer = initializer || depth == 0 && angle == 0
		case ',':
			if depth == 0 && angle == 0 {
				cuts = append(cuts, pos)
				initializer = false
			}
		}
		return true
	})
	return cuts
}
