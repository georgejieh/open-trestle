package scm

import (
	"context"
	"errors"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// LocalGitTreeEntry is one entry of a commit's tree that is not a
// directory. Object is the hex object ID: a blob for regular, executable
// and symbolic-link entries, a commit for a gitlink.
type LocalGitTreeEntry struct {
	Path   string
	Mode   evidence.GitTreeMode
	Object string
}

// LocalGitTreeWalk says how far a walk got.
type LocalGitTreeWalk struct {
	// Entries is the number of entries passed to the visitor.
	Entries int
	// Truncated reports that the walk stopped at its entry limit, so later
	// entries in tree order were not visited.
	Truncated bool
	// InvalidPaths counts entries skipped because their path is not valid
	// UTF-8 or is longer than the path limit.
	InvalidPaths int
}

// maxCachedWalkTrees bounds the parsed subtrees a walk keeps, so that a
// subtree shared by several paths is read once.
const maxCachedWalkTrees = 65_536

// WalkTree reads a commit and visits every non-directory entry of its tree
// in Git tree order, without reading any blob. Every object read is
// verified against its ID. It stops after maxEntries entries and reports
// that the walk was truncated; a malformed graph or a missing object is an
// error. A visitor error ends the walk and is returned.
func (s *LocalGitObjectStore) WalkTree(ctx context.Context, revision evidence.RevisionIdentity, maxEntries int, visit func(LocalGitTreeEntry) error) (LocalGitTreeWalk, error) {
	canonical, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || !revisionIdentityValuesEqual(revision, canonical) || maxEntries < 0 || visit == nil {
		return LocalGitTreeWalk{}, LocalGitRevisionInvalidGraph
	}
	commitContent, err := s.ReadCommit(ctx, canonical)
	if err != nil {
		return LocalGitTreeWalk{}, classifyLocalGitObjectRead(err)
	}
	verification, err := evidence.VerifyGitCommitObject(canonical, commitContent)
	if err != nil {
		return LocalGitTreeWalk{}, LocalGitRevisionInvalidGraph
	}
	commit, err := evidence.ParseVerifiedGitCommit(canonical, verification, commitContent)
	if err != nil || commit.TreeAlgorithm() != canonical.Algorithm() {
		return LocalGitTreeWalk{}, LocalGitRevisionInvalidGraph
	}
	w := treeWalker{ctx: ctx, store: s, algorithm: canonical.Algorithm(), max: maxEntries, visit: visit, cache: map[string][]localGitTreeEntry{}, active: map[string]bool{}}
	err = w.walk(commit.TreeDigest(), nil, 0)
	if errors.Is(err, errWalkTruncated) {
		w.result.Truncated, err = true, nil
	}
	return w.result, err
}

var errWalkTruncated = errors.New("tree walk truncated")

type treeWalker struct {
	ctx       context.Context
	store     *LocalGitObjectStore
	algorithm evidence.RevisionAlgorithm
	max       int
	visit     func(LocalGitTreeEntry) error
	cache     map[string][]localGitTreeEntry
	active    map[string]bool
	result    LocalGitTreeWalk
}

func (w *treeWalker) entries(digest string) ([]localGitTreeEntry, error) {
	if entries, ok := w.cache[digest]; ok {
		return entries, nil
	}
	content, err := w.store.ReadTree(w.ctx, w.algorithm, digest)
	if err != nil {
		return nil, classifyLocalGitObjectRead(err)
	}
	entries, err := parseLocalGitTreeEntries(w.ctx, content, w.algorithm, maxLocalGitRevisionEntries)
	if err != nil {
		return nil, err
	}
	if len(w.cache) < maxCachedWalkTrees {
		w.cache[digest] = entries
	}
	return entries, nil
}

func (w *treeWalker) walk(digest string, prefix []byte, depth int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if depth > maxLocalGitRevisionDepth || w.active[digest] {
		return LocalGitRevisionInvalidGraph
	}
	entries, err := w.entries(digest)
	if err != nil {
		return err
	}
	w.active[digest] = true
	defer delete(w.active, digest)
	for _, entry := range entries {
		path := append(append([]byte{}, prefix...), entry.name...)
		if entry.mode == evidence.GitTreeModeDirectory {
			if err := w.walk(entry.digest, append(path, '/'), depth+1); err != nil {
				return err
			}
			continue
		}
		if w.result.Entries >= w.max {
			return errWalkTruncated
		}
		if !utf8.Valid(path) || len(path) > maxLocalGitRevisionPathBytes {
			w.result.InvalidPaths++
			continue
		}
		w.result.Entries++
		if err := w.visit(LocalGitTreeEntry{Path: string(path), Mode: entry.mode, Object: entry.digest}); err != nil {
			return err
		}
	}
	return nil
}
