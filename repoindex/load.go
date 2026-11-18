package repoindex

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// GraphCoverage says how much of a commit a graph covers. Complete is false
// when the tree was cut, a path or a go.mod file was left out, a file that
// should have an analysis has none, or an analysis has a gap: a reference
// in such a place is not seen.
type GraphCoverage struct {
	Commit   string         `json:"commit"`
	Complete bool           `json:"complete"`
	Statuses map[Status]int `json:"files_by_status"`
	// AnalysisGaps counts the files whose analysis has a gap of each
	// reason, with the limit for a limit gap, as in "limit_exceeded:file_size".
	AnalysisGaps map[string]int `json:"analysis_gaps"`
	Coverage     Coverage       `json:"build"`
}

func newCoverage(s Snapshot) GraphCoverage {
	c := GraphCoverage{Commit: s.Commit, Coverage: s.Coverage, Statuses: map[Status]int{}, AnalysisGaps: map[string]int{}}
	for _, f := range s.Files {
		c.Statuses[f.Status]++
	}
	c.Complete = !s.Coverage.TreeTruncated && s.Coverage.InvalidPaths == 0 && s.Coverage.ModulesLeftOut == 0
	for _, status := range []Status{StatusUnavailable, StatusFileLimit, StatusByteLimit, StatusTimeLimit, StatusStoreLimit, StatusFailed} {
		c.Complete = c.Complete && c.Statuses[status] == 0
	}
	return c
}

// addGaps counts the gaps of one file's analysis.
func (c *GraphCoverage) addGaps(gaps []syntaxanalysis.Gap) {
	seen := map[string]bool{}
	for _, g := range gaps {
		key := string(g.Reason)
		if g.Limit != "" {
			key += ":" + string(g.Limit)
		}
		if !seen[key] {
			seen[key] = true
			c.AnalysisGaps[key]++
			c.Complete = false
		}
	}
}

// Coverage returns what the graph covers.
func (g *Graph) Coverage() GraphCoverage { return g.coverage }

// Snapshot returns the snapshot of an indexed commit.
func (s *Store) Snapshot(ctx context.Context, algorithm, commit string) (Snapshot, error) {
	sess, err := s.open(ctx, false)
	if err != nil {
		return Snapshot{}, err
	}
	defer sess.close()
	return sess.snapshot(algorithm, commit)
}

// Load builds the graph of an indexed commit. Damage clears the index and
// is ErrDamaged.
func (s *Store) Load(ctx context.Context, algorithm, commit string) (*Graph, error) {
	sess, err := s.open(ctx, false)
	if err != nil {
		return nil, err
	}
	defer sess.close()
	snapshot, err := sess.snapshot(algorithm, commit)
	if err != nil {
		return nil, err
	}
	g := newGraph(snapshot)
	for i, f := range snapshot.Files {
		if i%1024 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var analysis *syntaxanalysis.FileAnalysis
		if f.Status == StatusIndexed {
			key := snapshot.key(f)
			record, err := sess.record(key)
			if err != nil {
				return nil, err
			}
			decoded, err := record.decode(f.Path)
			if err != nil {
				return nil, sess.clear()
			}
			analysis = &decoded
		}
		g.add(f, analysis)
	}
	g.finish()
	return g, nil
}

// Load returns the graph of a tree's commit. It builds the commit first
// when the index has no snapshot of it, as after damage cleared it.
func (b Builder) Load(ctx context.Context, tree Tree) (*Graph, bool, error) {
	g, err := b.Store.Load(ctx, tree.Algorithm(), tree.Commit())
	if !errors.Is(err, ErrNotIndexed) && !errors.Is(err, ErrDamaged) {
		return g, false, err
	}
	if _, err := b.Build(ctx, tree); err != nil {
		return nil, true, err
	}
	g, err = b.Store.Load(ctx, tree.Algorithm(), tree.Commit())
	return g, true, err
}
