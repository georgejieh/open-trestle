package syntaxwasm

import (
	"bytes"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// finishCSharp applies the rules the syntax spells out only in part. Members
// of an interface and of an enum take the owner's visibility. A record whose keywords
// are `record struct` is a struct. A file-scoped namespace covers the rest
// of the file, so it becomes the parent of the top-level definitions after
// it and of the references and imports there. The operator nameof is not a
// call.
func finishCSharp(content []byte, _ syntaxanalysis.RawFile, a *syntaxanalysis.FileAnalysis) {
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind == syntaxanalysis.KindClass && strings.HasSuffix(strings.Join(strings.Fields(string(content[d.Range.StartByte:d.NameRange.StartByte])), " "), "record struct") {
			d.Kind = syntaxanalysis.KindStruct
		}
		if d.Parent >= 0 && a.Definitions[d.Parent].Exported {
			switch a.Definitions[d.Parent].Kind {
			case syntaxanalysis.KindInterface, syntaxanalysis.KindEnum:
				d.Exported = true
			}
		}
	}
	for i := range a.Definitions {
		d := &a.Definitions[i]
		if d.Kind != syntaxanalysis.KindModule || strings.ContainsRune(string(content[d.Range.StartByte:d.Range.EndByte]), '{') {
			continue
		}
		d.Range.EndByte = len(content)
		d.Range.End = endPosition(content)
		for j := i + 1; j < len(a.Definitions); j++ {
			if a.Definitions[j].Parent < 0 {
				a.Definitions[j].Parent = i
			}
		}
		for j := range a.References {
			if r := &a.References[j]; r.Enclosing < 0 && r.Range.StartByte >= d.Range.StartByte {
				r.Enclosing = i
			}
		}
		for j := range a.Imports {
			if m := &a.Imports[j]; m.Enclosing < 0 && m.Range.StartByte >= d.Range.StartByte {
				m.Enclosing = i
			}
		}
		break
	}
	a.References = slices.DeleteFunc(a.References, func(r syntaxanalysis.Reference) bool {
		return r.Kind == syntaxanalysis.ReferenceCall && r.Qualifier.Empty() && r.Name.Untrusted() == "nameof"
	})
}

// endPosition is the position just after the last byte of the content.
func endPosition(content []byte) syntaxanalysis.Position {
	line := 1 + bytes.Count(content, []byte{'\n'})
	return syntaxanalysis.Position{Line: line, Column: len(content) - bytes.LastIndexByte(content, '\n')}
}
