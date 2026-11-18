package main

import (
	"context"
	"io"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/repoindex"
)

// maxDiffBytes bounds the blob bytes a dependents query reads to find
// changed lines; a modified file past it counts as changed throughout.
const maxDiffBytes = 256 << 20

// runIndexDependents computes the dependents of the change from --base to
// --commit: the changed lines come from a diff of each modified file's base
// and head blobs.
func runIndexDependents(ctx context.Context, s *indexSession, f indexFlags, head *repoindex.Graph, stdout, stderr io.Writer) int {
	baseRevision, err := s.commit(ctx, f.base)
	if err != nil {
		return indexFail(stderr, 2, "--base: %v", err)
	}
	base, err := s.ensureIndexed(ctx, baseRevision, stderr)
	if err != nil {
		return indexFail(stderr, 1, "%v", err)
	}
	changes, pairs := repoindex.ChangedFiles(base.Files(), head.Files())
	if err := s.diffAll(ctx, baseRevision, changes, pairs); err != nil {
		return indexFail(stderr, 1, "the change could not be read: %v", err)
	}
	repoindex.SortChanges(changes)
	return writeIndexJSON(stdout, stderr, repoindex.Dependents(head, base, changes, repoindex.DefaultDependentsLimits()))
}

// diffAll reads the base and head blob of each pair in shared acquisitions
// of the object store and narrows its change to the changed lines. A pair
// past the byte budget, or one the diff cannot represent, keeps its whole
// file with the approximation recorded.
func (s *indexSession) diffAll(ctx context.Context, revision evidence.RevisionIdentity, changes []repoindex.Change, pairs []repoindex.DiffPair) error {
	tree, err := repoindex.NewGitTree(s.store, revision)
	if err != nil {
		return err
	}
	for _, p := range pairs {
		changes[p.Index].Approximation = repoindex.ApproximationDiffBudget
	}
	next, read := 0, int64(0)
	var baseContent []byte
	baseRead := false
	return tree.ReadBlobs(ctx, func() (string, bool) {
		if next >= 2*len(pairs) || read >= maxDiffBytes && next%2 == 0 {
			return "", false
		}
		next++
		if pair := pairs[(next-1)/2]; next%2 == 1 {
			return pair.Base, true
		} else {
			return pair.Head, true
		}
	}, func(content []byte, err error) error {
		read += int64(len(content))
		if next%2 == 1 {
			baseContent, baseRead = content, err == nil
			return ctx.Err()
		}
		c := &changes[pairs[next/2-1].Index]
		c.Approximation = repoindex.ApproximationDiffUnavailable
		if baseRead && err == nil {
			if headLines, baseLines, ok := diffLines(c.Path, baseContent, content); ok {
				c.HeadLines, c.BaseLines, c.Approximation = headLines, baseLines, ""
			}
		}
		return ctx.Err()
	})
}

// diffLines returns the changed head and base lines of a modified file.
func diffLines(path string, baseContent, headContent []byte) (head, base []repoindex.LineRange, ok bool) {
	patch, err := evidence.GenerateUnifiedFileDiff(path, baseContent, headContent)
	if err != nil {
		return nil, nil, false
	}
	_, lineMap, err := evidence.ParseUnifiedFileDiff(path, baseContent, headContent, patch)
	if err != nil {
		return nil, nil, false
	}
	for _, hunk := range lineMap.Hunks() {
		if n := hunk.HeadLineCount(); n > 0 {
			head = append(head, repoindex.LineRange{Start: hunk.HeadStartLine(), End: hunk.HeadStartLine() + n - 1})
		}
		if n := hunk.BaseLineCount(); n > 0 {
			base = append(base, repoindex.LineRange{Start: hunk.BaseStartLine(), End: hunk.BaseStartLine() + n - 1})
		}
	}
	return head, base, true
}
