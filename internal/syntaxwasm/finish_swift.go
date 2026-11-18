package syntaxwasm

import (
	"regexp"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishSwift applies the visibility the syntax implies. The members of a
// protocol and the cases of an enum are as visible as their owner. An
// extension has no visibility of its own: its modifier is the default for
// the members that state none. Some keywords parse as names: `class` in a
// protocol's inheritance list, `async` in the function type after an
// attribute such as @Sendable, and the call-shaped `defer` block are not
// references, Self stands for the enclosing type, and an attribute is not
// also a type reference.
func finishSwift(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	extension := make([]bool, len(a.Definitions))
	for i := range a.Definitions {
		d := &a.Definitions[i]
		extension[i] = d.Kind == syntaxanalysis.KindClass && swiftExtension(content, *d)
		if d.Parent < 0 {
			continue
		}
		parent := a.Definitions[d.Parent]
		switch {
		case parent.Kind == syntaxanalysis.KindInterface:
			d.Exported = true
		case parent.Kind == syntaxanalysis.KindEnum && d.Kind == syntaxanalysis.KindConstant:
			d.Exported = true
		case extension[d.Parent]:
			words := codeWords(content[d.Range.StartByte:d.NameRange.StartByte])
			switch {
			case words["private"] || words["fileprivate"] || words["internal"]:
				d.Exported = false
			case words["public"] || words["open"]:
				d.Exported = true
			default:
				d.Exported = parent.Exported
			}
		}
	}
	for i := len(a.Definitions) - 1; i >= 0; i-- {
		if extension[i] {
			a.Definitions[i].Exported = true
		}
	}
	decorators := map[int]bool{}
	for _, r := range a.References {
		if r.Kind == syntaxanalysis.ReferenceDecorator {
			decorators[r.Range.StartByte] = true
		}
	}
	a.References = slices.DeleteFunc(a.References, func(r syntaxanalysis.Reference) bool {
		name := r.Name.Untrusted()
		switch r.Kind {
		case syntaxanalysis.ReferenceType:
			return name == "Self" || name == "class" || name == "async" || decorators[r.Range.StartByte]
		case syntaxanalysis.ReferenceInherit:
			return name == "class"
		case syntaxanalysis.ReferenceCall:
			return name == "defer"
		}
		return false
	})
	a.Imports = slices.DeleteFunc(a.Imports, func(m syntaxanalysis.Import) bool {
		return m.Name.Empty() && swiftKindImport.Match(content[m.Range.StartByte:m.Range.EndByte])
	})
}

// swiftKindImport matches an import of one declaration, such as
// `import struct Module.Name`.
var swiftKindImport = regexp.MustCompile(`(^|\s)import\s+(typealias|struct|class|enum|protocol|let|var|func)\s`)

// swiftExtension reports whether a class definition is an extension: the
// keyword before the extended type's name is `extension`.
func swiftExtension(content []byte, d syntaxanalysis.Definition) bool {
	header := strings.TrimRight(string(content[d.Range.StartByte:d.NameRange.StartByte]), ".")
	header = strings.TrimRightFunc(header, func(r rune) bool { return r == '.' || r < 0x80 && identByte(byte(r)) || r >= 0x80 })
	fields := strings.Fields(header)
	return len(fields) > 0 && fields[len(fields)-1] == "extension"
}
