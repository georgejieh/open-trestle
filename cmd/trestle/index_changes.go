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
	changes, err := s.changes(ctx, baseRevision, base, head)
	if err != nil {
		return indexFail(stderr, 1, "the change could not be read: %v", err)
	}
	return writeIndexJSON(stdout, stderr, repoindex.Dependents(head, base, changes, repoindex.DefaultDependentsLimits()))
}

// changes compares two indexed snapshots and narrows each modified file to
// its changed lines.
func (s *indexSession) changes(ctx context.Context, revision evidence.RevisionIdentity, base, head *repoindex.Graph) ([]repoindex.Change, error) {
	changes, pairs := repoindex.ChangedFiles(base.Files(), head.Files())
	tree, err := repoindex.NewGitTree(s.store, revision)
	if err != nil {
		return nil, err
	}
	if err := repoindex.DiffChanges(ctx, tree, changes, pairs, maxDiffBytes); err != nil {
		return nil, err
	}
	repoindex.SortChanges(changes)
	return changes, nil
}
