package repoindex

import (
	"slices"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

type seed struct {
	target target
	name   syntaxanalysis.Text
	depth  int
}

// closure is the state of one Dependents computation.
type closure struct {
	head, base *Graph
	limits     DependentsLimits
	work       int
	result     DependentsResult
	frontier   []seed
	// visited holds the head definitions already changed or dependent, and
	// topLevel the file and name pairs already reported at a top level.
	visited   map[int32]bool
	topLevel  map[string]bool
	fileDepth map[string]int
	roles     map[string]Role
	// headExported records, per path and qualified name, the visibility of
	// each changed head definition.
	headExported map[string]bool
}

func newClosure(head, base *Graph, limits DependentsLimits) *closure {
	return &closure{head: head, base: base, limits: limits, work: limits.MaxWork,
		result:  DependentsResult{Coverage: head.Coverage(), Changed: []ChangedDefinition{}, Dependents: []Dependent{}, Files: []DependentFile{}, TestFiles: []string{}, Gaps: []ChangeGap{}},
		visited: map[int32]bool{}, topLevel: map[string]bool{}, fileDepth: map[string]int{}, roles: map[string]Role{}, headExported: map[string]bool{}}
}

func (c *closure) note(p string, role Role, depth int) {
	if d, ok := c.fileDepth[p]; !ok || depth < d {
		c.fileDepth[p] = depth
	}
	c.roles[p] = role
}

func (c *closure) gap(p, side, reason string) {
	c.result.Gaps = append(c.result.Gaps, ChangeGap{Path: p, Side: side, Reason: reason})
}

// seed adds the changed definitions of one change.
func (c *closure) seed(change Change) {
	if change.Approximation != "" {
		c.gap(change.Path+change.BasePath, "change", change.Approximation)
		c.result.Coverage.Complete = false
	}
	if change.Path != "" && len(change.HeadLines) > 0 {
		c.seedHead(change)
	}
	if change.BasePath == "" || len(change.BaseLines) == 0 {
		return
	}
	if c.base == nil {
		c.gap(change.BasePath, "base", "base_not_loaded")
		return
	}
	c.seedBase(change)
}

func (c *closure) seedHead(change Change) {
	id, ok := c.covered(c.head, change.Path, "head")
	if !ok {
		return
	}
	c.note(change.Path, c.head.files[id].entry.Role, 0)
	for _, i := range c.head.changedDefinitions(id, change.HeadLines) {
		c.visited[i] = true
		s := c.head.symbol(i)
		c.headExported[change.Path+"\x00"+s.QualifiedName.Untrusted()] = s.Exported
		c.result.Changed = append(c.result.Changed, ChangedDefinition{Symbol: s, Side: "head"})
		c.frontier = append(c.frontier, seed{target: c.head.targetOf(i), name: s.Name})
	}
}

// seedBase adds the changed definitions of the base file. A base definition
// that the head still has at the same path, name and visibility is already
// a head seed; one whose visibility changed stays a seed, because the files
// that used it while it was exported are affected.
func (c *closure) seedBase(change Change) {
	id, ok := c.covered(c.base, change.BasePath, "base")
	if !ok {
		return
	}
	for _, i := range c.base.changedDefinitions(id, change.BaseLines) {
		s := c.base.symbol(i)
		if exported, ok := c.headExported[change.Path+"\x00"+s.QualifiedName.Untrusted()]; ok && exported == s.Exported {
			continue
		}
		c.result.Changed = append(c.result.Changed, ChangedDefinition{Symbol: s, Side: "base"})
		c.frontier = append(c.frontier, seed{target: c.baseTarget(id, i, change), name: s.Name})
	}
}

// baseTarget maps a base definition into the head: the head file at its
// head path, the head unit of its package, and, for a file the head no
// longer has, the head files that imported it in the base.
func (c *closure) baseTarget(file, i int32, change Change) target {
	t := c.base.targetOf(i)
	t.file, t.unit, t.name = -1, -1, -1
	if n, ok := c.head.nameIDs[c.base.names[c.base.defs[i].name].Untrusted()]; ok {
		t.name = n
	}
	if hid, ok := c.head.byPath[change.Path]; ok && change.Path != "" {
		t.file, t.unit = hid, c.head.files[hid].unit
	}
	if t.family.packages {
		if unit, ok := c.head.units[unitKey(t.family.name, c.base.packageScope(file))]; ok {
			t.unit = unit
		}
	}
	if t.file < 0 {
		t.importers = map[int32]bool{}
		for _, f := range c.base.importersOf(file) {
			if hid, ok := c.head.byPath[c.base.files[f].entry.Path]; ok {
				t.importers[hid] = true
			}
		}
	}
	return t
}

// expand follows the candidates of the frontier breadth first.
func (c *closure) expand() {
	for len(c.frontier) > 0 {
		next := []seed{}
		for _, s := range c.frontier {
			if s.depth >= c.limits.MaxDepth {
				c.result.Cut.NotExpanded++
				continue
			}
			if s.target.name < 0 {
				continue
			}
			next = c.follow(s, next)
		}
		c.frontier = next
	}
}

// follow records the dependents of one seed and returns the frontier with
// the new dependents added.
func (c *closure) follow(s seed, next []seed) []seed {
	followed := 0
	complete := c.head.candidates(s.target, &c.work, func(i int32, scope Scope) bool {
		if followed++; followed > c.limits.MaxCandidates {
			c.result.Cut.CandidatesCut++
			return false
		}
		r := c.head.refs[i]
		f := c.head.files[r.file]
		key := f.entry.Path + "\x00" + s.name.Untrusted()
		if r.enclosing >= 0 && c.visited[r.enclosing] || r.enclosing < 0 && c.topLevel[key] {
			return true
		}
		if len(c.result.Dependents) >= c.limits.MaxDependents {
			c.result.Cut.DependentsDropped++
			return true
		}
		d := Dependent{Path: f.entry.Path, Role: f.entry.Role, Depth: s.depth + 1, Via: s.name, Line: int(r.rng.startLine), Scope: scope}
		if r.enclosing >= 0 {
			c.visited[r.enclosing] = true
			symbol := c.head.symbol(r.enclosing)
			d.Symbol = &symbol
			next = append(next, seed{target: c.head.targetOf(r.enclosing), name: symbol.Name, depth: s.depth + 1})
		} else {
			c.topLevel[key] = true
		}
		c.result.Dependents = append(c.result.Dependents, d)
		c.note(f.entry.Path, f.entry.Role, s.depth+1)
		return true
	})
	if !complete {
		c.result.Cut.WorkCut++
	}
	return next
}

// finish lists the files and marks the result incomplete when a limit cut
// the closure.
func (c *closure) finish() DependentsResult {
	paths := make([]string, 0, len(c.fileDepth))
	for p := range c.fileDepth {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		c.result.Files = append(c.result.Files, DependentFile{Path: p, Role: c.roles[p], Depth: c.fileDepth[p]})
		if c.roles[p] == RoleTest {
			c.result.TestFiles = append(c.result.TestFiles, p)
		}
	}
	if c.result.Cut != (DependentsCut{}) {
		c.result.Coverage.Complete = false
	}
	return c.result
}

// covered finds a changed file and records a gap when it has no analysis
// or its analysis is incomplete.
func (c *closure) covered(g *Graph, p, side string) (int32, bool) {
	id, ok := g.byPath[p]
	if !ok {
		c.gap(p, side, "not_in_snapshot")
		return 0, false
	}
	f := g.files[id]
	if f.entry.Status != StatusIndexed {
		c.gap(p, side, string(f.entry.Status))
		return 0, false
	}
	if len(f.gaps) > 0 {
		c.gap(p, side, "analysis_gaps")
	}
	return id, true
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
