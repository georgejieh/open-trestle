package syntaxwasm

import (
	"sort"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// removeDefinitions deletes the marked definitions in one pass. Records
// inside a deleted definition move to its nearest remaining ancestor.
func removeDefinitions(a *syntaxanalysis.FileAnalysis, drop []bool) {
	index := make([]int, len(a.Definitions))
	kept := 0
	for i, d := range a.Definitions {
		switch {
		case !drop[i]:
			index[i] = kept
			kept++
		case d.Parent >= 0:
			// Parents come first, so the parent is already resolved.
			index[i] = index[d.Parent]
		default:
			index[i] = -1
		}
	}
	resolve := func(i int) int {
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

// fileScope is a top-level module that covers the file from its start to
// end, such as a PHP namespace without braces or a C# file-scoped
// namespace.
type fileScope struct {
	index, end int
}

// extendToFileScopes stretches each scope's range to its end and makes it
// the parent of the top-level definitions and the enclosing definition of
// the top-level references and imports in that stretch. The scopes are in
// source order and do not overlap; one ordered sweep assigns them.
func extendToFileScopes(content []byte, a *syntaxanalysis.FileAnalysis, scopes []fileScope) {
	if len(scopes) == 0 {
		return
	}
	lines := syntaxanalysis.NewLineIndex(content)
	for _, s := range scopes {
		d := &a.Definitions[s.index]
		d.Range = lines.Range(syntaxanalysis.Span{Start: d.Range.StartByte, End: s.end})
		for j := s.index + 1; j < len(a.Definitions) && a.Definitions[j].Range.StartByte < s.end; j++ {
			if a.Definitions[j].Parent < 0 {
				a.Definitions[j].Parent = s.index
			}
		}
	}
	scopeAt := func(offset int) int {
		at := sort.Search(len(scopes), func(i int) bool { return a.Definitions[scopes[i].index].Range.StartByte > offset }) - 1
		if at >= 0 && offset < scopes[at].end {
			return scopes[at].index
		}
		return -1
	}
	for j := range a.References {
		if r := &a.References[j]; r.Enclosing < 0 {
			r.Enclosing = scopeAt(r.Range.StartByte)
		}
	}
	for j := range a.Imports {
		if m := &a.Imports[j]; m.Enclosing < 0 {
			m.Enclosing = scopeAt(m.Range.StartByte)
		}
	}
}
