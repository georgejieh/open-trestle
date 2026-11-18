package syntaxwasm

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishSwift applies the visibility that members take from their owner.
// The members of a protocol and the cases of an enum take the owner's
// visibility, and the members of an extension take the extension's: the
// modifier of an extension is the default for what it declares. Some
// keywords parse as names: `class` in a protocol's inheritance list, `async`
// in the function type after an attribute such as @Sendable, and the
// call-shaped `defer` block are not references, Self stands for the
// enclosing type, and an attribute is not also a type reference.
func finishSwift(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Parent < 0 {
			continue
		}
		parent := a.Definitions[d.Parent]
		if !parent.Exported {
			continue
		}
		switch {
		case parent.Kind == syntaxanalysis.KindInterface:
			d.Exported = true
		case parent.Kind == syntaxanalysis.KindEnum && d.Kind == syntaxanalysis.KindConstant:
			d.Exported = true
		case parent.Kind == syntaxanalysis.KindClass && swiftExtension(content, parent):
			d.Exported = !swiftNarrowed(content, *d)
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

// swiftNarrowed reports whether a declaration states a visibility below the
// default of the extension it is in.
func swiftNarrowed(content []byte, d syntaxanalysis.Definition) bool {
	for _, word := range strings.Fields(string(content[d.Range.StartByte:d.NameRange.StartByte])) {
		switch word {
		case "private", "fileprivate", "internal":
			return true
		}
	}
	return false
}

// swiftExtension reports whether a class definition is an extension: the
// keyword before the extended type's name is `extension`.
func swiftExtension(content []byte, d syntaxanalysis.Definition) bool {
	header := strings.TrimRight(string(content[d.Range.StartByte:d.NameRange.StartByte]), ".")
	header = strings.TrimRightFunc(header, func(r rune) bool { return r == '.' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) })
	fields := strings.Fields(header)
	return len(fields) > 0 && fields[len(fields)-1] == "extension"
}
