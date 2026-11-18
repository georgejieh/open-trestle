// Package reviewcontext turns the repository index of a change into the
// ranked context a review shows next to the changed code: the definitions
// that enclose changed hunks, the uses of changed definitions, the tests
// that reference them and a ranked repository map. It proposes line ranges
// only; the review binds the text from its own verified snapshot.
package reviewcontext

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Limits bound a plan. Enclosing, Callers, Tests and Map bound the items of
// each stage; a caller whose signature is far from its use counts once for
// its two ranges.
type Limits struct {
	Enclosing, Callers, Tests, Map int
	// EnclosingLines and TestLines bound one enclosing definition and one
	// test; CallerSpan is the most lines a use may lie below its signature
	// and still share one range with it.
	EnclosingLines, TestLines, CallerSpan int
}

// DefaultLimits returns the limits a review uses.
func DefaultLimits() Limits {
	return Limits{Enclosing: 16, Callers: 24, Tests: 8, Map: 24, EnclosingLines: 200, TestLines: 120, CallerSpan: 40}
}

// Plan proposes context for a change from the head and base graphs. It is
// deterministic: equal graphs and changes give an equal plan.
func Plan(head, base *repoindex.Graph, changes []repoindex.Change, limits Limits) review.ContextPlan {
	deps := repoindex.Dependents(head, base, changes, repoindex.DefaultDependentsLimits())
	seeds := []string{}
	for _, c := range changes {
		if c.Path != "" {
			seeds = append(seeds, c.Path)
		}
	}
	ranking := head.Rank(seeds, repoindex.DefaultRankLimits())
	p := planner{head: head, limits: limits, ranking: ranking, changed: changedLines(changes), headPaths: headPaths(changes), plan: review.ContextPlan{
		State: review.ContextIndexUsed, Complete: deps.Coverage.Complete && ranking.Complete,
		Coverage: coverage(deps), StageOmitted: map[review.ContextStage]int{},
	}}
	p.enclosing(deps.Changed)
	p.uses(deps.Dependents)
	p.repositoryMap(deps.Changed)
	p.changedDefinitions(deps)
	return p.plan
}

type planner struct {
	head   *repoindex.Graph
	limits Limits
	// headPaths maps the base path of each changed file the head still has
	// to its head path.
	headPaths map[string]string
	ranking   repoindex.Ranking
	changed   map[string][]repoindex.LineRange
	plan      review.ContextPlan
}

func (p *planner) add(stage review.ContextStage, path string, start, end, rank, depth int) {
	p.plan.Items = append(p.plan.Items, review.ContextPlanItem{Stage: stage, Path: path, StartLine: max(start, 1), EndLine: max(end, start, 1), Rank: rank, Depth: depth})
}

// lines returns a range's first and last line; a range that ends at column
// 1 ends on the line before.
func lines(r syntaxanalysis.Range) (int, int) {
	end := r.End.Line
	if r.End.Column == 1 && end > r.Start.Line {
		end--
	}
	return r.Start.Line, end
}

func headPaths(changes []repoindex.Change) map[string]string {
	out := map[string]string{}
	for _, c := range changes {
		if c.Path != "" && c.BasePath != "" {
			out[c.BasePath] = c.Path
		}
	}
	return out
}

func changedLines(changes []repoindex.Change) map[string][]repoindex.LineRange {
	out := map[string][]repoindex.LineRange{}
	for _, c := range changes {
		if c.Path != "" {
			out[c.Path] = append(out[c.Path], c.HeadLines...)
		}
	}
	return out
}

// covered reports whether changed lines hold every line from start to end.
func covered(ranges []repoindex.LineRange, start, end int) bool {
	sorted := slices.Clone(ranges)
	slices.SortFunc(sorted, func(a, b repoindex.LineRange) int { return a.Start - b.Start })
	next := start
	for _, r := range sorted {
		if r.Start > next {
			break
		}
		next = max(next, r.End+1)
	}
	return next > end
}

// enclosing adds the whole head definition around each changed hunk, or a
// window of it around the first changed line when it is longer than the
// bound. A definition that only lost lines is shown as the head still has
// it. A definition the changed lines cover already is left out.
func (p *planner) enclosing(changed []repoindex.ChangedDefinition) {
	rank := 0
	seen := map[string]bool{}
	for _, d := range changed {
		if d.Kind == syntaxanalysis.KindModule {
			continue
		}
		if d.Side != "head" {
			head, ok := p.headDefinition(d)
			if !ok {
				continue
			}
			d = repoindex.ChangedDefinition{Symbol: head, Side: "head"}
		}
		start, end := lines(d.Range)
		if key := fmt.Sprintf("%s:%d", d.Path, start); seen[key] {
			continue
		} else {
			seen[key] = true
		}
		ranges := p.changed[d.Path]
		if covered(ranges, start, end) {
			continue
		}
		if rank == p.limits.Enclosing {
			p.plan.StageOmitted[review.ContextStageEnclosingSymbol]++
			continue
		}
		if end-start+1 > p.limits.EnclosingLines {
			first := end
			for _, r := range ranges {
				if r.End >= start && r.Start <= end {
					first = min(first, max(r.Start, start))
				}
			}
			start = max(start, first-p.limits.EnclosingLines/4)
			end = min(end, start+p.limits.EnclosingLines-1)
		}
		rank++
		p.add(review.ContextStageEnclosingSymbol, d.Path, start, end, rank, 0)
	}
}

// headDefinition finds the head definition of a changed base definition:
// the one with its qualified name in the file's head path.
func (p *planner) headDefinition(d repoindex.ChangedDefinition) (repoindex.Symbol, bool) {
	path, ok := p.headPaths[d.Path]
	if !ok {
		return repoindex.Symbol{}, false
	}
	for _, s := range p.head.Definitions(d.Name.Untrusted()) {
		if s.Path == path && s.QualifiedName.Untrusted() == d.QualifiedName.Untrusted() {
			return s, true
		}
	}
	return repoindex.Symbol{}, false
}

// uses adds the callers and other uses of changed definitions, with the
// signature of the definition that holds each, and the tests among them.
// Both are ranked by depth, then by the rank of their file, then by place.
func (p *planner) uses(dependents []repoindex.Dependent) {
	sorted := slices.Clone(dependents)
	slices.SortStableFunc(sorted, func(a, b repoindex.Dependent) int {
		if c := cmp.Compare(a.Depth, b.Depth); c != 0 {
			return c
		}
		if c := cmp.Compare(p.ranking.Files[b.Path], p.ranking.Files[a.Path]); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return cmp.Compare(a.Line, b.Line)
	})
	callers, tests := 0, 0
	for _, d := range sorted {
		if d.Role == repoindex.RoleTest {
			if tests == p.limits.Tests {
				p.plan.StageOmitted[review.ContextStageRelatedTest]++
				continue
			}
			tests++
			start, end := d.Line-3, d.Line+3
			if d.Symbol != nil {
				start, end = lines(d.Symbol.Range)
				end = min(end, start+p.limits.TestLines-1)
			}
			p.add(review.ContextStageRelatedTest, d.Path, start, end, tests, d.Depth)
			continue
		}
		if callers == p.limits.Callers {
			p.plan.StageOmitted[review.ContextStageDirectReference]++
			continue
		}
		callers++
		if d.Symbol == nil {
			p.add(review.ContextStageDirectReference, d.Path, d.Line-2, d.Line+2, callers, d.Depth)
			continue
		}
		start, end := lines(d.Symbol.Range)
		signatureEnd := max(start, d.Symbol.NameRange.End.Line)
		if d.Line-start <= p.limits.CallerSpan {
			p.add(review.ContextStageDirectReference, d.Path, start, min(end, d.Line+1), callers, d.Depth)
			continue
		}
		p.add(review.ContextStageDirectReference, d.Path, start, signatureEnd, callers, d.Depth)
		p.add(review.ContextStageDirectReference, d.Path, max(signatureEnd+1, d.Line-2), min(end, d.Line+2), callers, d.Depth)
	}
}

// mapKinds are the definitions whose signatures the repository map lists.
var mapKinds = map[syntaxanalysis.DefinitionKind]bool{
	syntaxanalysis.KindFunction: true, syntaxanalysis.KindMethod: true, syntaxanalysis.KindConstructor: true,
	syntaxanalysis.KindClass: true, syntaxanalysis.KindStruct: true, syntaxanalysis.KindInterface: true,
	syntaxanalysis.KindEnum: true, syntaxanalysis.KindType: true, syntaxanalysis.KindConstant: true, syntaxanalysis.KindMacro: true,
}

// repositoryMap adds the signatures of the source definitions the ranking
// places highest that no other item already shows.
func (p *planner) repositoryMap(changed []repoindex.ChangedDefinition) {
	shown := map[string][][2]int{}
	for _, item := range p.plan.Items {
		shown[item.Path] = append(shown[item.Path], [2]int{item.StartLine, item.EndLine})
	}
	for _, d := range changed {
		if d.Side == "head" {
			start, end := lines(d.Range)
			shown[d.Path] = append(shown[d.Path], [2]int{start, end})
		}
	}
	rank := 0
	for _, s := range p.ranking.Symbols {
		if s.Score <= 0 || s.Role != repoindex.RoleSource || !mapKinds[s.Kind] {
			continue
		}
		start, _ := lines(s.Range)
		if slices.ContainsFunc(shown[s.Path], func(r [2]int) bool { return r[0] <= start && start <= r[1] }) {
			continue
		}
		if rank == p.limits.Map {
			p.plan.StageOmitted[review.ContextStageRepositoryMap]++
			continue
		}
		rank++
		end := min(max(start, s.NameRange.End.Line), start+2)
		p.add(review.ContextStageRepositoryMap, s.Path, start, end, rank, 0)
		shown[s.Path] = append(shown[s.Path], [2]int{start, end})
	}
}

// changedDefinitions counts the direct dependents and tests of each changed
// head definition. A dependent names the definition it uses only by name, so
// two changed definitions with one name share their counts.
func (p *planner) changedDefinitions(deps repoindex.DependentsResult) {
	dependents, tests := map[string]int{}, map[string]int{}
	for _, d := range deps.Dependents {
		if d.Depth != 1 {
			continue
		}
		p.plan.Dependents++
		dependents[d.Via.Untrusted()]++
		if d.Role == repoindex.RoleTest {
			tests[d.Via.Untrusted()]++
		}
	}
	for _, d := range deps.Changed {
		if d.Side != "head" || d.Kind == syntaxanalysis.KindModule {
			continue
		}
		start, end := lines(d.Range)
		name := d.Name.Untrusted()
		p.plan.Changed = append(p.plan.Changed, review.ContextPlanDefinition{Path: d.Path, StartLine: start, EndLine: end, Dependents: dependents[name], Tests: tests[name]})
	}
}

func coverage(deps repoindex.DependentsResult) review.ContextIndexCoverage {
	c := review.ContextIndexCoverage{ChangeGaps: len(deps.Gaps)}
	for status, n := range deps.Coverage.Statuses {
		c.Files += n
		switch status {
		case repoindex.StatusIndexed:
			c.Indexed += n
		case repoindex.StatusUnavailable, repoindex.StatusFileLimit, repoindex.StatusByteLimit, repoindex.StatusTimeLimit, repoindex.StatusStoreLimit, repoindex.StatusFailed:
			c.LeftOut += n
		}
	}
	for _, n := range deps.Coverage.AnalysisGaps {
		c.AnalysisGaps += n
	}
	cut := deps.Cut
	c.ClosureCut = cut.NotExpanded + cut.DependentsDropped + cut.CandidatesCut + cut.WorkCut
	return c
}
