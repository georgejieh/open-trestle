package repoindex

import (
	"math"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// RankLimits bound a ranking.
type RankLimits struct {
	// MaxCandidates bounds the reference candidates counted for one
	// definition, so that a common name does not dominate the graph.
	MaxCandidates int
	// MaxWork bounds the references checked for the whole graph.
	MaxWork int
}

// DefaultRankLimits returns the limits used unless configured.
func DefaultRankLimits() RankLimits { return RankLimits{MaxCandidates: 500, MaxWork: 4_000_000} }

// RankedSymbol is a definition with its share of the ranking.
type RankedSymbol struct {
	Symbol
	Score float64 `json:"score"`
}

// Ranking orders the files and definitions of a graph by their relevance to
// a set of seed files.
type Ranking struct {
	// Files maps each file with a nonzero rank to its rank; the ranks sum
	// to one.
	Files map[string]float64
	// Symbols lists the definitions that some other file references, by
	// descending score, then path and line.
	Symbols []RankedSymbol
	// Complete is false when MaxWork cut the reference count.
	Complete bool
}

const (
	rankDamping    = 0.85
	rankIterations = 50
	rankTolerance  = 1e-9
)

// Rank computes a PageRank over the file graph, personalised to the seed
// files: a file links to every file whose definitions it holds reference
// candidates of, and to every file its imports resolve to, with the square
// root of the count as the weight. A definition's score is the rank that
// flows to it from the files that reference it. Seeds the graph does not
// have are ignored; with none left, the personalisation is uniform.
func (g *Graph) Rank(seeds []string, limits RankLimits) Ranking {
	if limits.MaxCandidates <= 0 || limits.MaxWork <= 0 {
		limits = DefaultRankLimits()
	}
	n := len(g.files)
	ranking := Ranking{Files: map[string]float64{}, Symbols: []RankedSymbol{}, Complete: true}
	if n == 0 {
		return ranking
	}
	uses, complete := g.crossFileUses(limits)
	ranking.Complete = complete
	links := make([]map[int32]float64, n)
	for _, u := range uses {
		if links[u.from] == nil {
			links[u.from] = map[int32]float64{}
		}
		links[u.from][g.defs[u.def].file] += float64(u.count)
	}
	for i := range g.files {
		for _, t := range append(g.importFiles.get(int32(i)), g.importUnitFiles(int32(i))...) {
			if t == int32(i) {
				continue
			}
			if links[i] == nil {
				links[i] = map[int32]float64{}
			}
			links[i][t]++
		}
	}
	edges := make([][]rankEdge, n)
	for i, targets := range links {
		total := 0.0
		for t, count := range targets {
			edges[i] = append(edges[i], rankEdge{to: t, weight: math.Sqrt(count)})
		}
		slices.SortFunc(edges[i], func(a, b rankEdge) int { return int(a.to - b.to) })
		for _, e := range edges[i] {
			total += e.weight
		}
		for k := range edges[i] {
			edges[i][k].weight /= total
		}
	}
	personal := g.personalisation(seeds)
	rank := pageRank(personal, edges)
	for i, r := range rank {
		if r > 0 {
			ranking.Files[g.files[i].entry.Path] = r
		}
	}
	ranking.Symbols = g.symbolScores(uses, rank)
	return ranking
}

type rankEdge struct {
	to     int32
	weight float64
}

// rankUse counts the candidates of one definition in one other file.
type rankUse struct {
	from, def int32
	count     int32
}

// crossFileUses counts, per definition and referencing file, the reference
// candidates outside the definition's own file.
func (g *Graph) crossFileUses(limits RankLimits) ([]rankUse, bool) {
	work := limits.MaxWork
	complete := true
	uses := []rankUse{}
	for i := range g.defs {
		if g.defs[i].kind == syntaxanalysis.KindModule {
			continue
		}
		counts := map[int32]int32{}
		seen := 0
		finished := g.candidates(g.targetOf(int32(i)), &work, func(r int32, _ Scope) bool {
			if seen++; seen > limits.MaxCandidates {
				return false
			}
			if from := g.refs[r].file; from != g.defs[i].file {
				counts[from]++
			}
			return true
		})
		if !finished {
			complete = false
		}
		files := make([]int32, 0, len(counts))
		for f := range counts {
			files = append(files, f)
		}
		slices.Sort(files)
		for _, f := range files {
			uses = append(uses, rankUse{from: f, def: int32(i), count: counts[f]})
		}
		if work <= 0 {
			complete = false
			break
		}
	}
	return uses, complete
}

// importUnitFiles lists the files of the units a file's imports resolve to.
func (g *Graph) importUnitFiles(file int32) []int32 {
	out := []int32{}
	for _, unit := range g.importUnits.get(file) {
		out = append(out, g.unitFiles.get(unit)...)
	}
	return out
}

func (g *Graph) personalisation(seeds []string) []float64 {
	personal := make([]float64, len(g.files))
	found := 0
	for _, p := range seeds {
		if id, ok := g.byPath[p]; ok && personal[id] == 0 {
			personal[id] = 1
			found++
		}
	}
	for i := range personal {
		if found == 0 {
			personal[i] = 1 / float64(len(personal))
		} else {
			personal[i] /= float64(found)
		}
	}
	return personal
}

// pageRank iterates until the ranks change by less than the tolerance. The
// rank of a file without links returns to the personalisation.
func pageRank(personal []float64, edges [][]rankEdge) []float64 {
	rank := slices.Clone(personal)
	next := make([]float64, len(rank))
	for iteration := 0; iteration < rankIterations; iteration++ {
		dangling := 0.0
		clear(next)
		for i, r := range rank {
			if len(edges[i]) == 0 {
				dangling += r
				continue
			}
			for _, e := range edges[i] {
				next[e.to] += rankDamping * r * e.weight
			}
		}
		delta := 0.0
		for i := range next {
			next[i] += ((1 - rankDamping) + rankDamping*dangling) * personal[i]
			delta += math.Abs(next[i] - rank[i])
		}
		rank, next = next, rank
		if delta < rankTolerance {
			break
		}
	}
	return rank
}

// symbolScores shares each referencing file's rank among the definitions
// it references, in proportion to its candidates of each.
func (g *Graph) symbolScores(uses []rankUse, rank []float64) []RankedSymbol {
	totals := make([]float64, len(g.files))
	for _, u := range uses {
		totals[u.from] += float64(u.count)
	}
	scores := map[int32]float64{}
	for _, u := range uses {
		scores[u.def] += rank[u.from] * float64(u.count) / totals[u.from]
	}
	out := make([]RankedSymbol, 0, len(scores))
	for def, score := range scores {
		out = append(out, RankedSymbol{Symbol: g.symbol(def), Score: score})
	}
	slices.SortFunc(out, func(a, b RankedSymbol) int {
		switch {
		case a.Score != b.Score:
			if a.Score > b.Score {
				return -1
			}
			return 1
		case a.Path != b.Path:
			return strings.Compare(a.Path, b.Path)
		}
		return a.Range.StartByte - b.Range.StartByte
	})
	return out
}
