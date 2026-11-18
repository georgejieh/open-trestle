package repoindex

import (
	"context"
	"maps"
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
	// MaxWork bounds the definitions checked against references.
	MaxWork int
	// MaxFiles bounds the files of the neighbourhood that is ranked.
	MaxFiles int
	// MaxEdges bounds the links between files.
	MaxEdges int
}

// DefaultRankLimits returns the limits used unless configured.
func DefaultRankLimits() RankLimits {
	return RankLimits{MaxCandidates: 500, MaxWork: 4_000_000, MaxFiles: 2_000, MaxEdges: 100_000}
}

func (l RankLimits) withDefaults() RankLimits {
	d := DefaultRankLimits()
	for _, pair := range []struct{ value, fallback *int }{{&l.MaxCandidates, &d.MaxCandidates}, {&l.MaxWork, &d.MaxWork}, {&l.MaxFiles, &d.MaxFiles}, {&l.MaxEdges, &d.MaxEdges}} {
		if *pair.value <= 0 {
			*pair.value = *pair.fallback
		}
	}
	return l
}

// RankedSymbol is a definition with its share of the ranking.
type RankedSymbol struct {
	Symbol
	Score float64 `json:"score"`
}

// Ranking orders the files and definitions near a set of seed files by
// their relevance to them.
type Ranking struct {
	// Files maps each file with a nonzero rank to its rank; the ranks sum
	// to one.
	Files map[string]float64
	// Symbols lists the definitions that the walked files reference, by
	// descending score, then path and place.
	Symbols []RankedSymbol
	// Complete is false when a limit cut a candidate count, the work, the
	// links or the neighbourhood.
	Complete bool
}

const (
	rankDamping    = 0.85
	rankIterations = 50
	rankTolerance  = 1e-9
	// rankSteps is how many links from the seeds the neighbourhood reaches.
	rankSteps = 2
)

// Rank computes a PageRank personalised to the seed files over their
// neighbourhood: the files reachable from them within two links. A file
// links to each file whose definitions it holds reference candidates of, and
// to each file its imports resolve to, with the square root of the count as
// the weight. Only the files within one link of a seed are walked, so only
// definitions they reference are scored, each by the rank that flows to it
// from the files that reference it. Seeds the graph does not have are
// ignored; without any, the ranking is empty.
func (g *Graph) Rank(ctx context.Context, seeds []string, limits RankLimits) (Ranking, error) {
	w := &rankWalk{g: g, limits: limits.withDefaults(), index: map[int32]int32{}, counted: map[int32]int{}, complete: true}
	w.work = w.limits.MaxWork
	for _, p := range seeds {
		if id, ok := g.byPath[p]; ok {
			w.node(id)
		}
	}
	ranking := Ranking{Files: map[string]float64{}, Symbols: []RankedSymbol{}, Complete: true}
	found := len(w.nodes)
	if found == 0 {
		return ranking, nil
	}
	if err := w.walk(ctx); err != nil {
		return Ranking{}, err
	}
	personal := make([]float64, len(w.nodes))
	for i := range found {
		personal[i] = 1 / float64(found)
	}
	rank, err := pageRank(ctx, personal, w.edges())
	if err != nil {
		return Ranking{}, err
	}
	for i, r := range rank {
		if r > 0 {
			ranking.Files[g.files[w.nodes[i]].entry.Path] = r
		}
	}
	ranking.Symbols = w.symbolScores(rank)
	ranking.Complete = w.complete
	return ranking, nil
}

// rankWalk collects the neighbourhood of the seeds breadth first.
type rankWalk struct {
	g      *Graph
	limits RankLimits
	work   int
	// nodes are the graph files of the neighbourhood in walk order, the
	// seeds first, and index the node of each.
	nodes []int32
	index map[int32]int32
	// links counts, per node, the candidates and imports to each node.
	links     []map[int32]float64
	linkCount int
	counted   map[int32]int
	uses      []rankUse
	// complete is false once a limit cuts the walk.
	complete bool
}

// rankUse counts the candidates of one definition in one walked file.
type rankUse struct {
	from, def int32
	count     int32
}

type rankEdge struct {
	to     int32
	weight float64
}

// node returns the node of a file, adding it within the file bound.
func (w *rankWalk) node(file int32) (int32, bool) {
	if n, ok := w.index[file]; ok {
		return n, true
	}
	if len(w.nodes) >= w.limits.MaxFiles {
		w.complete = false
		return 0, false
	}
	n := int32(len(w.nodes))
	w.index[file] = n
	w.nodes = append(w.nodes, file)
	w.links = append(w.links, nil)
	return n, true
}

// walk follows the links of the nodes within rankSteps-1 links of a seed.
func (w *rankWalk) walk(ctx context.Context) error {
	frontier := slices.Clone(w.nodes)
	for step := 0; step < rankSteps && len(frontier) > 0 && w.work > 0; step++ {
		next := []int32{}
		for _, file := range frontier {
			if err := ctx.Err(); err != nil {
				return err
			}
			next = w.follow(w.index[file], next)
		}
		frontier = next
	}
	return nil
}

// follow adds the links of one node and returns the frontier with the
// files it reaches first added.
func (w *rankWalk) follow(from int32, next []int32) []int32 {
	file := w.nodes[from]
	targets := w.importTargets(file)
	uses := w.candidateUses(file)
	for _, def := range slices.Sorted(maps.Keys(uses)) {
		targets[w.g.defs[def].file] += float64(uses[def])
	}
	for _, t := range slices.Sorted(maps.Keys(targets)) {
		if w.linkCount >= w.limits.MaxEdges {
			w.complete = false
			break
		}
		fresh := !w.known(t)
		to, ok := w.node(t)
		if !ok {
			continue
		}
		if fresh {
			next = append(next, t)
		}
		if w.links[from] == nil {
			w.links[from] = map[int32]float64{}
		}
		w.links[from][to] = targets[t]
		w.linkCount++
	}
	for _, def := range slices.Sorted(maps.Keys(uses)) {
		if to, ok := w.index[w.g.defs[def].file]; ok && w.links[from][to] > 0 {
			w.uses = append(w.uses, rankUse{from: from, def: def, count: uses[def]})
		}
	}
	return next
}

func (w *rankWalk) known(file int32) bool {
	_, ok := w.index[file]
	return ok
}

// importTargets counts the files a file's imports resolve to, as many as
// the links left allow.
func (w *rankWalk) importTargets(file int32) map[int32]float64 {
	g := w.g
	room := w.limits.MaxEdges - w.linkCount
	out := map[int32]float64{}
	add := func(targets []int32) {
		for _, t := range targets {
			if t == file {
				continue
			}
			if _, ok := out[t]; !ok && len(out) >= room {
				w.complete = false
				return
			}
			out[t]++
		}
	}
	add(g.importFiles.get(file))
	for _, unit := range g.importUnits.get(file) {
		add(g.unitFiles.get(unit))
	}
	return out
}

// candidateUses counts, per definition of another file, the references of
// a file that are its candidates. Each definition checked costs one unit of
// work, and a definition stops counting past MaxCandidates.
func (w *rankWalk) candidateUses(file int32) map[int32]int32 {
	g := w.g
	f := g.files[file]
	out := map[int32]int32{}
	for r := f.refs.start; r < f.refs.end; r++ {
		ref := g.refs[r]
		if ref.name == 0 {
			continue
		}
		for _, def := range g.defsByName.get(ref.name) {
			if w.work <= 0 {
				w.complete = false
				return out
			}
			w.work--
			d := g.defs[def]
			if d.file == file || d.kind == syntaxanalysis.KindModule || g.scope(g.targetOf(def), ref) == "" {
				continue
			}
			if w.counted[def]++; w.counted[def] > w.limits.MaxCandidates {
				w.complete = false
				continue
			}
			out[def]++
		}
	}
	return out
}

// edges normalises each node's links by the square root of their counts.
func (w *rankWalk) edges() [][]rankEdge {
	edges := make([][]rankEdge, len(w.nodes))
	for i, targets := range w.links {
		total := 0.0
		for _, t := range slices.Sorted(maps.Keys(targets)) {
			weight := math.Sqrt(targets[t])
			edges[i] = append(edges[i], rankEdge{to: t, weight: weight})
			total += weight
		}
		for k := range edges[i] {
			edges[i][k].weight /= total
		}
	}
	return edges
}

// pageRank iterates until the ranks change by less than the tolerance. The
// rank of a file without links returns to the personalisation. Each product
// is converted explicitly before it is added, so that no platform fuses the
// two into one operation with a different rounding.
func pageRank(ctx context.Context, personal []float64, edges [][]rankEdge) ([]float64, error) {
	rank := slices.Clone(personal)
	next := make([]float64, len(rank))
	for iteration := 0; iteration < rankIterations; iteration++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dangling := 0.0
		clear(next)
		for i, r := range rank {
			if len(edges[i]) == 0 {
				dangling += r
				continue
			}
			for _, e := range edges[i] {
				next[e.to] += float64(rankDamping * r * e.weight)
			}
		}
		teleport := (1 - rankDamping) + float64(rankDamping*dangling)
		delta := 0.0
		for i := range next {
			next[i] += float64(teleport * personal[i])
			delta += math.Abs(next[i] - rank[i])
		}
		rank, next = next, rank
		if delta < rankTolerance {
			break
		}
	}
	return rank, nil
}

// symbolScores shares each walked file's rank among the definitions it
// references, in proportion to its candidates of each.
func (w *rankWalk) symbolScores(rank []float64) []RankedSymbol {
	totals := make([]float64, len(w.nodes))
	for _, u := range w.uses {
		totals[u.from] += float64(u.count)
	}
	scores := map[int32]float64{}
	for _, u := range w.uses {
		scores[u.def] += float64(rank[u.from]*float64(u.count)) / totals[u.from]
	}
	out := make([]RankedSymbol, 0, len(scores))
	for def, score := range scores {
		out = append(out, RankedSymbol{Symbol: w.g.symbol(def), Score: score})
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
		case a.Range.StartByte != b.Range.StartByte:
			return a.Range.StartByte - b.Range.StartByte
		}
		return int(a.ID - b.ID)
	})
	return out
}
