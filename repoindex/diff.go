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
			if headLines, baseLines, ok := diffLines(c.Path, baseContent, content); ok {
				c.HeadLines, c.BaseLines, c.Approximation = headLines, baseLines, ""
			}
		}
		return ctx.Err()
	})
}

// diffLines returns the changed head and base lines of a modified file.
func diffLines(path string, baseContent, headContent []byte) (head, base []LineRange, ok bool) {
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
			head = append(head, LineRange{Start: hunk.HeadStartLine(), End: hunk.HeadStartLine() + n - 1})
		}
		if n := hunk.BaseLineCount(); n > 0 {
			base = append(base, LineRange{Start: hunk.BaseStartLine(), End: hunk.BaseStartLine() + n - 1})
		}
	}
	return head, base, true
}
