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
	// entries in tree order were not visited. Every entry walked counts
	// toward the limit, directories and invalid paths included, so that a
	// tree of nested shared subtrees cannot make the walk unbounded.
	Truncated bool
	// InvalidPaths counts entries skipped because their path is not valid
	// UTF-8 or is longer than the path limit.
	InvalidPaths int
}

// maxCachedWalkTrees bounds the parsed subtrees a walk keeps, so that a
// subtree shared by several paths is read once.
const maxCachedWalkTrees = 65_536

// LocalGitObjectReader reads verified trees and blobs within one
// acquisition of the object store.
type LocalGitObjectReader interface {
	ReadTree(context.Context, evidence.RevisionAlgorithm, string) ([]byte, error)
	ReadBlob(context.Context, evidence.RevisionAlgorithm, string) ([]byte, error)
}

// WithObjectReader runs fn with a reader whose reads share one acquisition:
// the packs are checked once, when fn returns, instead of after every
// object. An acquisition has a work budget; a read past it fails with
// LocalGitRevisionResourceLimit, and a new acquisition can continue.
func (s *LocalGitObjectStore) WithObjectReader(ctx context.Context, fn func(LocalGitObjectReader) error) error {
	return s.withScopedObjectReader(ctx, func(reader localGitObjectReader) error { return fn(reader) })
}

// WalkTree reads a commit and visits every non-directory entry of its tree
// in Git tree order, without reading any blob, in one acquisition. Every
// object read is verified against its ID. It stops after walking maxEntries
// entries and reports that the walk was truncated; a malformed graph or a missing
// object is an error. A visitor error ends the walk and is returned.
func (s *LocalGitObjectStore) WalkTree(ctx context.Context, revision evidence.RevisionIdentity, maxEntries int, visit func(LocalGitTreeEntry) error) (LocalGitTreeWalk, error) {
	canonical, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || !revisionIdentityValuesEqual(revision, canonical) || maxEntries < 0 || visit == nil {
		return LocalGitTreeWalk{}, LocalGitRevisionInvalidGraph
	}
	var result LocalGitTreeWalk
	err = s.withScopedObjectReader(ctx, func(reader localGitObjectReader) error {
		var walkErr error
		result, walkErr = walkTree(ctx, reader, canonical, maxEntries, visit)
		return walkErr
	})
	return result, err
}

func walkTree(ctx context.Context, reader localGitObjectReader, canonical evidence.RevisionIdentity, maxEntries int, visit func(LocalGitTreeEntry) error) (LocalGitTreeWalk, error) {
	commitContent, err := reader.ReadCommit(ctx, canonical)
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
	w := treeWalker{ctx: ctx, reader: reader, algorithm: canonical.Algorithm(), max: maxEntries, visit: visit, cache: map[string][]localGitTreeEntry{}, active: map[string]bool{}}
	err = w.walk(commit.TreeDigest(), nil, 0)
	if errors.Is(err, errWalkTruncated) {
		w.result.Truncated, err = true, nil
	}
	return w.result, err
}

var errWalkTruncated = errors.New("tree walk truncated")

type treeWalker struct {
	ctx       context.Context
	reader    localGitObjectReader
	algorithm evidence.RevisionAlgorithm
	max       int
	visit     func(LocalGitTreeEntry) error
	cache     map[string][]localGitTreeEntry
	active    map[string]bool
	walked    int
	result    LocalGitTreeWalk
}

func (w *treeWalker) entries(digest string) ([]localGitTreeEntry, error) {
	if entries, ok := w.cache[digest]; ok {
		return entries, nil
	}
	content, err := w.reader.ReadTree(w.ctx, w.algorithm, digest)
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
		if w.walked >= w.max {
			return errWalkTruncated
		}
		w.walked++
		path := append(append([]byte{}, prefix...), entry.name...)
		if entry.mode == evidence.GitTreeModeDirectory {
			if err := w.walk(entry.digest, append(path, '/'), depth+1); err != nil {
				return err
			}
			continue
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
