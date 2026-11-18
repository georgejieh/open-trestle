package repoindex

import (
	"path"
	"slices"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// LineRange is an inclusive range of 1-based lines.
type LineRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Change is one changed file of a review: the head lines that were added
// or replaced and the base lines that were removed or replaced.
type Change struct {
	// Path is the head path, empty when the file was deleted.
	Path string
	// BasePath is the base path, empty when the file was added.
	BasePath  string
	HeadLines []LineRange
	BaseLines []LineRange
}

// DependentsLimits bound the reverse closure.
type DependentsLimits struct {
	// MaxDepth is how many reference steps the closure follows from the
	// changed definitions.
	MaxDepth int
	// MaxDependents bounds the dependents reported.
	MaxDependents int
	// MaxCandidates bounds the reference candidates followed for one
	// definition, so that a common name does not flood the result.
	MaxCandidates int
}

// DefaultDependentsLimits returns the limits used unless configured.
func DefaultDependentsLimits() DependentsLimits {
	return DependentsLimits{MaxDepth: 3, MaxDependents: 1000, MaxCandidates: 2000}
}

// ChangedDefinition is a definition enclosing changed lines. Side is head
// for a definition of the head snapshot and base for one that the change
// removed or replaced; a base definition's ID is meaningless in the head.
type ChangedDefinition struct {
	Symbol
	Side string `json:"side"`
}

// Dependent is a definition, or the top level of a file, that holds a
// reference candidate of a changed definition or of another dependent.
type Dependent struct {
	// Symbol is nil for a reference at the top level of a file.
	Symbol *Symbol `json:"symbol,omitempty"`
	Path   string  `json:"path"`
	Role   Role    `json:"role"`
	// Depth is 1 for a reference to a changed definition, 2 for a
	// reference to a dependent of depth 1, and so on.
	Depth int `json:"depth"`
	// Via is the referenced name and Line the line of the reference.
	Via   syntaxanalysis.Text `json:"via"`
	Line  int                 `json:"line"`
	Scope Scope               `json:"scope"`
}

// DependentFile is a file holding a changed definition (depth 0) or a
// dependent, at the smallest depth found.
type DependentFile struct {
	Path  string `json:"path"`
	Role  Role   `json:"role"`
	Depth int    `json:"depth"`
}

// DependentsCut records what the limits left out.
type DependentsCut struct {
	// NotExpanded counts dependents at the depth limit whose own
	// references were not followed.
	NotExpanded int `json:"not_expanded"`
	// DependentsDropped counts candidates past MaxDependents.
	DependentsDropped int `json:"dependents_dropped"`
	// CandidatesCut counts definitions whose candidates passed
	// MaxCandidates; their remaining candidates were not followed.
	CandidatesCut int `json:"candidates_cut"`
}

// ChangeGap says why a changed file is not fully covered.
type ChangeGap struct {
	Path   string `json:"path"`
	Side   string `json:"side"`
	Reason string `json:"reason"`
}

// DependentsResult is the reverse closure of a change.
type DependentsResult struct {
	// Coverage is the head graph's: a dependent in a file it does not
	// cover is not found.
	Coverage   GraphCoverage       `json:"coverage"`
	Changed    []ChangedDefinition `json:"changed"`
	Dependents []Dependent         `json:"dependents"`
	Files      []DependentFile     `json:"files"`
	TestFiles  []string            `json:"test_files"`
	Cut        DependentsCut       `json:"cut"`
	Gaps       []ChangeGap         `json:"gaps"`
}

// changedDefinitions returns the definitions of a file that enclose
// changed lines: each definition with a changed line that none of its
// child definitions contains.
func (g *Graph) changedDefinitions(file int32, ranges []LineRange) []int32 {
	f := g.files[file]
	children := map[int32][]int32{}
	for i := f.defs.start; i < f.defs.end; i++ {
		if p := g.defs[i].parent; p >= 0 {
			children[p] = append(children[p], i)
		}
	}
	lines := func(i int32) (int, int) {
		start, end := g.defs[i].rng.lines()
		return int(start), int(end)
	}
	out := []int32{}
	for i := f.defs.start; i < f.defs.end; i++ {
		start, end := lines(i)
		for _, r := range ranges {
			lo, hi := max(start, r.Start), min(end, r.End)
			if lo > hi || coveredByChildren(lo, hi, children[i], lines) {
				continue
			}
			out = append(out, i)
			break
		}
	}
	return out
}

// coveredByChildren reports whether the child definitions together contain
// every line from lo to hi.
func coveredByChildren(lo, hi int, children []int32, lines func(int32) (int, int)) bool {
	spans := make([][2]int, 0, len(children))
	for _, c := range children {
		s, e := lines(c)
		spans = append(spans, [2]int{s, e})
	}
	slices.SortFunc(spans, func(a, b [2]int) int { return a[0] - b[0] })
	next := lo
	for _, s := range spans {
		if s[0] > next {
			break
		}
		next = max(next, s[1]+1)
	}
	return next > hi
}

type seed struct {
	target target
	name   syntaxanalysis.Text
	depth  int
}

// Dependents computes the definitions enclosing a change's lines and the
// reverse closure of the definitions and files that hold reference
// candidates of them, breadth first, within the limits. base, which may be
// nil, supplies the definitions the change removed or replaced.
func Dependents(head, base *Graph, changes []Change, limits DependentsLimits) DependentsResult {
	defaults := DefaultDependentsLimits()
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxDependents <= 0 {
		limits.MaxDependents = defaults.MaxDependents
	}
	if limits.MaxCandidates <= 0 {
		limits.MaxCandidates = defaults.MaxCandidates
	}
	result := DependentsResult{Coverage: head.Coverage(), Changed: []ChangedDefinition{}, Dependents: []Dependent{}, Files: []DependentFile{}, TestFiles: []string{}, Gaps: []ChangeGap{}}
	visited := map[int32]bool{}
	fileDepth := map[string]int{}
	roles := map[string]Role{}
	frontier := []seed{}
	headNames := map[string]bool{}
	note := func(p string, role Role, depth int) {
		if d, ok := fileDepth[p]; !ok || depth < d {
			fileDepth[p] = depth
		}
		roles[p] = role
	}
	for _, c := range changes {
		if c.Path != "" && len(c.HeadLines) > 0 {
			id, ok := head.coveredFile(c.Path, "head", &result)
			if !ok {
				continue
			}
			note(c.Path, head.files[id].entry.Role, 0)
			for _, i := range head.changedDefinitions(id, c.HeadLines) {
				visited[i] = true
				s := head.symbol(i)
				headNames[c.Path+"\x00"+s.QualifiedName.Untrusted()] = true
				result.Changed = append(result.Changed, ChangedDefinition{Symbol: s, Side: "head"})
				frontier = append(frontier, seed{target: head.targetOf(i), name: s.Name})
			}
		}
		if c.BasePath == "" || len(c.BaseLines) == 0 {
			continue
		}
		if base == nil {
			result.Gaps = append(result.Gaps, ChangeGap{Path: c.BasePath, Side: "base", Reason: "base_not_loaded"})
			continue
		}
		id, ok := base.coveredFile(c.BasePath, "base", &result)
		if !ok {
			continue
		}
		for _, i := range base.changedDefinitions(id, c.BaseLines) {
			s := base.symbol(i)
			if headNames[c.BasePath+"\x00"+s.QualifiedName.Untrusted()] {
				continue
			}
			result.Changed = append(result.Changed, ChangedDefinition{Symbol: s, Side: "base"})
			t := base.targetOf(i)
			t.file, t.name = -1, -1
			if hid, ok := head.byPath[c.BasePath]; ok {
				t.file = hid
			} else {
				t.importers = map[int32]bool{}
				for _, p := range base.importersOf(id) {
					if hid, ok := head.byPath[p]; ok {
						t.importers[hid] = true
					}
				}
			}
			t.dir = path.Dir(c.BasePath)
			if n, ok := head.nameIDs[s.Name.Untrusted()]; ok {
				t.name = n
			}
			frontier = append(frontier, seed{target: t, name: s.Name})
		}
	}
	topLevel := map[string]bool{}
	for len(frontier) > 0 {
		next := []seed{}
		for _, s := range frontier {
			if s.depth >= limits.MaxDepth {
				result.Cut.NotExpanded++
				continue
			}
			if s.target.name < 0 {
				continue
			}
			followed := 0
			head.candidates(s.target, func(i int32, scope Scope) bool {
				if followed++; followed > limits.MaxCandidates {
					result.Cut.CandidatesCut++
					return false
				}
				r := head.refs[i]
				f := head.files[r.file]
				if r.enclosing >= 0 && visited[r.enclosing] {
					return true
				}
				key := f.entry.Path + "\x00" + s.name.Untrusted()
				if r.enclosing < 0 && topLevel[key] {
					return true
				}
				if len(result.Dependents) >= limits.MaxDependents {
					result.Cut.DependentsDropped++
					return true
				}
				d := Dependent{Path: f.entry.Path, Role: f.entry.Role, Depth: s.depth + 1, Via: s.name, Line: int(r.rng.startLine), Scope: scope}
				if r.enclosing >= 0 {
					visited[r.enclosing] = true
					symbol := head.symbol(r.enclosing)
					d.Symbol = &symbol
					next = append(next, seed{target: head.targetOf(r.enclosing), name: symbol.Name, depth: s.depth + 1})
				} else {
					topLevel[key] = true
				}
				result.Dependents = append(result.Dependents, d)
				note(f.entry.Path, f.entry.Role, s.depth+1)
				return true
			})
		}
		frontier = next
	}
	paths := make([]string, 0, len(fileDepth))
	for p := range fileDepth {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		result.Files = append(result.Files, DependentFile{Path: p, Role: roles[p], Depth: fileDepth[p]})
		if roles[p] == RoleTest {
			result.TestFiles = append(result.TestFiles, p)
		}
	}
	return result
}

// coveredFile finds a changed file and records a gap when it has no
// analysis or its analysis is incomplete.
func (g *Graph) coveredFile(p, side string, result *DependentsResult) (int32, bool) {
	id, ok := g.byPath[p]
	if !ok {
		result.Gaps = append(result.Gaps, ChangeGap{Path: p, Side: side, Reason: "not_in_snapshot"})
		return 0, false
	}
	f := g.files[id]
	if f.entry.Status != StatusIndexed {
		result.Gaps = append(result.Gaps, ChangeGap{Path: p, Side: side, Reason: string(f.entry.Status)})
		return 0, false
	}
	if len(f.gaps) > 0 {
		result.Gaps = append(result.Gaps, ChangeGap{Path: p, Side: side, Reason: "analysis_gaps"})
	}
	return id, true
}
