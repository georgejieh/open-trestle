package syntaxwasm

import (
	"strings"
	"unicode"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishJava applies the implicit visibility of interface and annotation
// members, public unless declared private, and of enum constants, which
// the syntax does not spell out.
func finishJava(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Parent < 0 {
			continue
		}
		parent := a.Definitions[d.Parent]
		switch {
		case parent.Kind == syntaxanalysis.KindInterface:
			d.Exported = !codeWords(content[d.Range.StartByte:d.NameRange.StartByte])["private"]
		case parent.Kind == syntaxanalysis.KindEnum && d.Kind == syntaxanalysis.KindConstant:
			d.Exported = true
		}
	}
}

// finishECMAScript marks class constructors.
func finishECMAScript(_ []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind == syntaxanalysis.KindMethod && d.Name.Untrusted() == "constructor" && d.Parent >= 0 && a.Definitions[d.Parent].Kind == syntaxanalysis.KindClass {
			d.Kind = syntaxanalysis.KindConstructor
		}
	}
}

// finishPython applies Python's naming conventions: __init__ is the
// constructor, an upper-case module-level binding is a constant, and a
// name is exported when it is listed in __all__ or, without __all__, when
// it is reachable from the module through classes only and does not start
// with an underscore (dunder names count as public).
func finishPython(_ []byte, raw syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	hasAll := len(raw.Exports) > 0
	for i := range a.Definitions {
		d := &a.Definitions[i]
		name := d.Name.Untrusted()
		if d.Kind == syntaxanalysis.KindMethod && name == "__init__" {
			d.Kind = syntaxanalysis.KindConstructor
		}
		if d.Kind == syntaxanalysis.KindVariable && d.Parent < 0 && upperCaseName(name) {
			d.Kind = syntaxanalysis.KindConstant
		}
		if d.Parent < 0 && hasAll {
			// Assemble already marked the names listed in __all__.
			continue
		}
		public := !strings.HasPrefix(name, "_") || (strings.HasPrefix(name, "__") && strings.HasSuffix(name, "__") && len(name) > 4)
		for p := d.Parent; public && p >= 0; p = a.Definitions[p].Parent {
			parent := a.Definitions[p]
			public = parent.Kind == syntaxanalysis.KindClass && (parent.Parent >= 0 || !hasAll || parent.Exported)
		}
		d.Exported = public
	}
}

func upperCaseName(name string) bool {
	letter := false
	for _, r := range name {
		switch {
		case unicode.IsLower(r):
			return false
		case unicode.IsUpper(r):
			letter = true
		case r != '_' && !unicode.IsDigit(r):
			return false
		}
	}
	return letter
}
