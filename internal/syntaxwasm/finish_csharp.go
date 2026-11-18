package syntaxwasm

import (
	"bytes"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishCSharp applies the rules the syntax spells out only in part.
// Members of an interface and of an enum are public unless an access
// modifier says otherwise, and a namespace has no visibility of its own. A
// record whose keywords are `record struct` is a struct. A file-scoped
// namespace covers the rest of the file, so it becomes the parent of the
// top-level definitions after it and of the references and imports there.
// The operator nameof is not a call.
func finishCSharp(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	fileScoped := -1
	for i := range a.Definitions {
		d := &a.Definitions[i]
		prefix := content[d.Range.StartByte:d.NameRange.StartByte]
		if d.Kind == syntaxanalysis.KindClass && strings.HasSuffix(strings.Join(strings.Fields(string(prefix)), " "), "record struct") {
			d.Kind = syntaxanalysis.KindStruct
		}
		if d.Kind == syntaxanalysis.KindModule {
			d.Exported = true
			if fileScoped < 0 && bytes.IndexByte(content[d.Range.StartByte:d.Range.EndByte], '{') < 0 {
				fileScoped = i
			}
		}
		if d.Parent >= 0 {
			switch a.Definitions[d.Parent].Kind {
			case syntaxanalysis.KindInterface, syntaxanalysis.KindEnum:
				words := codeWords(prefix)
				d.Exported = !words["private"] && !words["protected"] && !words["internal"]
			}
		}
	}
	if fileScoped >= 0 {
		extendToFileScopes(content, a, []fileScope{{index: fileScoped, end: len(content)}})
	}
	a.References = slices.DeleteFunc(a.References, func(r syntaxanalysis.Reference) bool {
		return r.Kind == syntaxanalysis.ReferenceCall && r.Qualifier.Empty() && r.Name.Untrusted() == "nameof"
	})
}
