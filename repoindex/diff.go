package repoindex

import (
	"context"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// DiffChanges reads the base and head blob of each pair in shared
// acquisitions of the tree's object store and narrows its change to the
// changed lines. A pair past maxBytes, or one the diff cannot represent,
// keeps its whole file with the approximation recorded.
func DiffChanges(ctx context.Context, tree Tree, changes []Change, pairs []DiffPair, maxBytes int64) error {
	for _, p := range pairs {
		changes[p.Index].Approximation = ApproximationDiffBudget
	}
	next, read := 0, int64(0)
	var baseContent []byte
	baseRead := false
	return tree.ReadBlobs(ctx, func() (string, bool) {
		if next >= 2*len(pairs) || read >= maxBytes && next%2 == 0 {
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
		c.Approximation = ApproximationDiffUnavailable
		if baseRead && err == nil {
			if lines, ok := diffLines(c.Path, baseContent, content); ok {
				c.HeadLines, c.BaseLines, c.DeletionPoints, c.Approximation = lines.HeadLines, lines.BaseLines, lines.DeletionPoints, ""
			}
		}
		return ctx.Err()
	})
}

// diffLines returns the changed lines of a modified file: its head and base
// lines and its deletion points.
func diffLines(path string, baseContent, headContent []byte) (Change, bool) {
	patch, err := evidence.GenerateUnifiedFileDiff(path, baseContent, headContent)
	if err != nil {
		return Change{}, false
	}
	_, lineMap, err := evidence.ParseUnifiedFileDiff(path, baseContent, headContent, patch)
	if err != nil {
		return Change{}, false
	}
	var c Change
	for _, hunk := range lineMap.Hunks() {
		n := hunk.HeadLineCount()
		if n > 0 {
			c.HeadLines = append(c.HeadLines, LineRange{Start: hunk.HeadStartLine(), End: hunk.HeadStartLine() + n - 1})
		}
		if m := hunk.BaseLineCount(); m > 0 {
			c.BaseLines = append(c.BaseLines, LineRange{Start: hunk.BaseStartLine(), End: hunk.BaseStartLine() + m - 1})
			if n == 0 {
				c.DeletionPoints = append(c.DeletionPoints, hunk.HeadStartLine())
			}
		}
	}
	return c, true
}
