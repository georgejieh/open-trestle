package syntaxwasm

import (
	"bytes"
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
// call references, and sets the exported flag.
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
		if inBlock[i] && d.Range.EndByte > d.Range.StartByte && d.Range.EndByte <= len(content) && content[d.Range.EndByte-1] == ';' {
			drop[i] = true
			found = true
		}
	}
	if found {
		removeDefinitions(a, drop)
	}
}

// removeDefinitions deletes the marked definitions. Records inside a
// deleted definition move to its nearest remaining ancestor.
func removeDefinitions(a *syntaxanalysis.FileAnalysis, drop []bool) {
	index := make([]int, len(a.Definitions))
	kept := 0
	for i := range a.Definitions {
		if drop[i] {
			index[i] = -1
			continue
		}
		index[i] = kept
		kept++
	}
	resolve := func(i int) int {
		for i >= 0 && drop[i] {
			i = a.Definitions[i].Parent
		}
		if i < 0 {
			return -1
		}
		return index[i]
	}
	out := a.Definitions[:0:0]
	for i, d := range a.Definitions {
		if drop[i] {
			continue
		}
		d.Parent = resolve(d.Parent)
		out = append(out, d)
	}
	for i := range a.References {
		a.References[i].Enclosing = resolve(a.References[i].Enclosing)
	}
	for i := range a.Imports {
		a.Imports[i].Enclosing = resolve(a.Imports[i].Enclosing)
	}
	a.Definitions = out
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

// markConstants turns the variables of a file or namespace, and the static
// data members of a class, into constants when nothing can reassign them: a
// const that qualifies the declared type (not a pointed-to type), a const
// pointer, or constexpr.
func markConstants(content []byte, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind != syntaxanalysis.KindVariable && d.Kind != syntaxanalysis.KindField {
			continue
		}
		start, end := d.Range.StartByte, min(d.NameRange.StartByte, d.Range.StartByte+maxLeadingBytes)
		if start < 0 || end > len(content) || end <= start {
			continue
		}
		static, constexpr, specConst, afterStarConst, star := false, false, false, false, false
		angle := 0
		lexCode(content[start:end], func(token byte, _ int, word string) bool {
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
	var spans []syntaxanalysis.Range
	for i, d := range a.Definitions {
		if d.Kind != syntaxanalysis.KindFunction && d.Kind != syntaxanalysis.KindMethod || d.Parent < 0 || !isClassLike(a.Definitions[d.Parent].Kind) {
			continue
		}
		name := d.Name.Untrusted()
		if name == a.Definitions[d.Parent].Name.Untrusted() || strings.HasPrefix(name, "~") || !d.Container.Empty() {
			continue
		}
		typed := false
		for word := range leadingWords(content, &a.Definitions[i]) {
			switch word {
			case "explicit", "constexpr", "consteval", "inline":
			default:
				typed = true
			}
		}
		if !typed && isPlainName(name) {
			drop[i] = true
			spans = append(spans, d.Range)
		}
	}
	if len(spans) == 0 {
		return
	}
	removeDefinitions(a, drop)
	kept := a.References[:0]
	for _, r := range a.References {
		inside := false
		if r.Kind == syntaxanalysis.ReferenceType {
			for _, s := range spans {
				if r.Range.StartByte >= s.StartByte && r.Range.EndByte <= s.EndByte {
					inside = true
					break
				}
			}
		}
		if !inside {
			kept = append(kept, r)
		}
	}
	a.References = kept
}

func isPlainName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c < 0x80 {
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
			namespaces[name[strings.LastIndex(name, "::")+1:]] = true
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

// setExported decides what other files can reach:
//
//   - a member of a class or struct is exported when its class is and its
//     access is public; a struct member is public by default and a class
//     member private;
//   - an enumerator follows its enumeration;
//   - a function, variable or constant at file or namespace scope is
//     exported unless it is static or in an anonymous namespace, and a
//     const C++ variable only when it is extern (or declared in a header);
//   - a type, macro, namespace or alias is exported when it is declared in
//     a header and not in an anonymous namespace;
//   - nothing inside a function is exported.
func setExported(content []byte, a *syntaxanalysis.FileAnalysis) {
	header := isHeaderPath(a.Path)
	cpp := a.Language == syntaxanalysis.LanguageCPP
	access := memberAccess(content, a)
	anonymous := anonymousNamespaces(a)
	for i := range a.Definitions {
		d := &a.Definitions[i]
		d.Exported = false
		var parent *syntaxanalysis.Definition
		if d.Parent >= 0 {
			parent = &a.Definitions[d.Parent]
		}
		switch {
		case parent != nil && parent.Kind == syntaxanalysis.KindEnum:
			d.Exported = parent.Exported
		case parent != nil && isClassLike(parent.Kind):
			d.Exported = parent.Exported && access[i] == "public"
		case parent != nil && parent.Kind != syntaxanalysis.KindModule:
			// Inside a function, a variable or another definition.
		case anonymous[i]:
		default:
			switch d.Kind {
			case syntaxanalysis.KindModule:
				d.Exported = header && d.Name.Untrusted() != "namespace"
			case syntaxanalysis.KindFunction, syntaxanalysis.KindMethod, syntaxanalysis.KindConstructor, syntaxanalysis.KindVariable, syntaxanalysis.KindConstant:
				words := leadingWords(content, d)
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

// anonymousNamespaces marks the definitions that have an anonymous
// namespace among their ancestors. Parents come before their children.
func anonymousNamespaces(a *syntaxanalysis.FileAnalysis) []bool {
	inside := make([]bool, len(a.Definitions))
	for i, d := range a.Definitions {
		if d.Parent >= 0 {
			parent := a.Definitions[d.Parent]
			inside[i] = inside[d.Parent] || (parent.Kind == syntaxanalysis.KindModule && parent.Name.Untrusted() == "namespace")
		}
	}
	return inside
}

const maxLeadingBytes = 512

// leadingWords returns the words that come before the name of a
// definition, such as static and extern. Only the first bytes count, since
// the specifiers come first.
func leadingWords(content []byte, d *syntaxanalysis.Definition) map[string]bool {
	words := map[string]bool{}
	start, end := d.Range.StartByte, min(d.NameRange.StartByte, d.Range.StartByte+maxLeadingBytes)
	if start < 0 || end > len(content) || end <= start {
		return words
	}
	lexCode(content[start:end], func(token byte, _ int, word string) bool {
		if token == 'w' {
			words[word] = true
		}
		return true
	})
	return words
}

// memberAccess returns the access of every member of a class or struct,
// indexed like the definitions: the last access label before the member in
// the class body, or the default of the kind. Each class body is read once,
// up to its last member, and the total reading is bounded; a member that is
// not reached gets no access, so it is not exported.
func memberAccess(content []byte, a *syntaxanalysis.FileAnalysis) []string {
	access := make([]string, len(a.Definitions))
	children := map[int][]int{}
	for i, d := range a.Definitions {
		if d.Parent >= 0 && isClassLike(a.Definitions[d.Parent].Kind) {
			children[d.Parent] = append(children[d.Parent], i)
		}
	}
	budget := 8*len(content) + 1<<20
	for parent, members := range children {
		p := a.Definitions[parent]
		start, end := p.Range.StartByte, a.Definitions[members[len(members)-1]].Range.StartByte
		if start < 0 || end > len(content) || end < start || end-start > budget {
			continue
		}
		budget -= end - start
		current := "public"
		if p.Kind == syntaxanalysis.KindClass {
			current = "private"
		}
		next, depth, pending := 0, 0, ""
		assign := func(pos int) {
			for next < len(members) && a.Definitions[members[next]].Range.StartByte <= start+pos {
				access[members[next]] = current
				next++
			}
		}
		lexCode(content[start:end], func(token byte, pos int, word string) bool {
			assign(pos)
			switch token {
			case '{':
				depth++
			case '}':
				depth--
			case 'w':
				pending = ""
				if depth == 1 && (word == "public" || word == "private" || word == "protected") {
					pending = word
				}
				return true
			case ':':
				if pending != "" {
					current = pending
				}
			}
			pending = ""
			return true
		})
		assign(end - start)
	}
	return access
}

// lexCode walks C and C++ text and reports words ('w'), scope operators
// ('S'), and each other punctuation byte as itself, so a single colon is ':'.
// Comments, string and character literals, raw strings and preprocessor
// lines are skipped. The visitor returns false to stop.
func lexCode(b []byte, visit func(token byte, pos int, word string) bool) {
	isWord := func(c byte) bool {
		return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
	}
	lineStart := true
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n':
			lineStart = true
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i += 2
		case c == '#' && lineStart:
			for i < len(b) && b[i] != '\n' {
				if b[i] == '\\' && i+1 < len(b) {
					i++
				}
				i++
			}
		case c == '"' || c == '\'':
			i = skipLiteral(b, i)
			lineStart = false
		case isWord(c):
			start := i
			for i < len(b) && isWord(b[i]) {
				i++
			}
			word := string(b[start:i])
			if i < len(b) && b[i] == '"' && strings.HasSuffix(word, "R") && len(word) <= 3 {
				i = skipRawString(b, i)
				lineStart = false
				continue
			}
			if c >= '0' && c <= '9' {
				// A number, possibly with digit separators.
				for i < len(b) && (isWord(b[i]) || b[i] == '\'' || b[i] == '.') {
					i++
				}
				lineStart = false
				continue
			}
			lineStart = false
			if !visit('w', start, word) {
				return
			}
		case c == ':':
			lineStart = false
			if i+1 < len(b) && b[i+1] == ':' {
				i += 2
				if !visit('S', i-2, "") {
					return
				}
				continue
			}
			i++
			if !visit(':', i-1, "") {
				return
			}
		default:
			lineStart = false
			i++
			if !visit(c, i-1, "") {
				return
			}
		}
	}
}

// skipLiteral returns the index after the string or character literal that
// starts at b[i].
func skipLiteral(b []byte, i int) int {
	quote := b[i]
	i++
	for i < len(b) && b[i] != quote && b[i] != '\n' {
		if b[i] == '\\' {
			i++
		}
		i++
	}
	if i < len(b) {
		i++
	}
	return i
}

// skipRawString returns the index after the raw string literal whose
// opening quote is b[i].
func skipRawString(b []byte, i int) int {
	i++
	start := i
	for i < len(b) && b[i] != '(' && b[i] != '\n' {
		i++
	}
	if i >= len(b) || b[i] != '(' {
		return i
	}
	closing := ")" + string(b[start:i]) + "\""
	if at := bytes.Index(b[i:], []byte(closing)); at >= 0 {
		return i + at + len(closing)
	}
	return len(b)
}

// cppSniffBytes bounds the text read to decide the language of a .h file.
const cppSniffBytes = 256 << 10

// headerLanguage returns the language to analyse a C source as: C++ for a
// .h file whose first bytes use syntax that C does not have, C otherwise.
// The signals are namespace and using declarations, templates, class
// declarations, access labels, operator overloads and the scope operator
// outside C23 attribute brackets, and the noexcept and virtual keywords.
// Comments, literals and preprocessor lines are skipped, so an extern "C"
// guard leaves a C header as C.
func headerLanguage(p string, content []byte) syntaxanalysis.Language {
	if strings.ToLower(path.Ext(p)) != ".h" || !looksLikeCPP(content[:min(len(content), cppSniffBytes)]) {
		return syntaxanalysis.LanguageC
	}
	return syntaxanalysis.LanguageCPP
}

func looksLikeCPP(b []byte) bool {
	found := false
	// previous holds the last two tokens: a word as itself, punctuation as
	// its byte.
	var previous [2]string
	attribute := 0
	lexCode(b, func(token byte, pos int, word string) bool {
		current := word
		if token != 'w' {
			current = string(token)
		}
		last, beforeLast := previous[0], previous[1]
		switch {
		case token == '[' && last == "[":
			attribute++
		case token == ']' && last == "]" && attribute > 0:
			attribute--
		case token == 'S' && attribute == 0:
			found = true
		case last == "namespace" && (token == 'w' || token == '{'):
			found = true
		case last == "template" && token == '<':
			found = true
		case last == "using" && (word == "namespace" || token == 'w'):
			found = true
		case beforeLast == "class" && isIdentifier(last) && (token == '{' || token == ':' || token == ';' || word == "final"):
			found = true
		case token == ':' && (last == "public" || last == "private" || last == "protected") && (beforeLast == "{" || beforeLast == ";" || beforeLast == "}" || beforeLast == ":"):
			found = true
		case last == "operator" && token != 'w' && token != ';' && token != ',' && token != ')':
			found = true
		case token == 'w' && (word == "noexcept" || word == "virtual"):
			found = true
		}
		previous[1], previous[0] = last, current
		return !found
	})
	return found
}

func isIdentifier(s string) bool {
	return s != "" && (s[0] == '_' || s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z' || s[0] >= 0x80)
}
