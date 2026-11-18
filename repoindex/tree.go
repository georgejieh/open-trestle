package repoindex

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

// EntryKind is the kind of a tree entry that is not a directory.
type EntryKind int

const (
	EntryFile EntryKind = iota
	EntrySymlink
	EntrySubmodule
)

// TreeEntry is one tree entry; Object is its hex object ID.
type TreeEntry struct {
	Path   string
	Kind   EntryKind
	Object string
}

// TreeWalk says how far a walk got; see scm.LocalGitTreeWalk.
type TreeWalk struct {
	Entries      int
	Truncated    bool
	InvalidPaths int
}

// Tree is the commit a build indexes.
type Tree interface {
	Algorithm() string
	Commit() string
	// Walk visits at most maxEntries entries in tree order.
	Walk(ctx context.Context, maxEntries int, visit func(TreeEntry) error) (TreeWalk, error)
	// ReadBlob returns a verified blob.
	ReadBlob(ctx context.Context, object string) ([]byte, error)
}

// GitTree reads a commit from the verified object store reviews use.
type GitTree struct {
	store    *scm.LocalGitObjectStore
	revision evidence.RevisionIdentity
}

// NewGitTree returns the tree of a commit in the store.
func NewGitTree(store *scm.LocalGitObjectStore, revision evidence.RevisionIdentity) (*GitTree, error) {
	if store == nil || revision.Kind() != evidence.RevisionKindGitCommit {
		return nil, errors.New("a Git commit in a local object store is required")
	}
	return &GitTree{store: store, revision: revision}, nil
}

func (t *GitTree) Algorithm() string { return string(t.revision.Algorithm()) }
func (t *GitTree) Commit() string    { return t.revision.Digest() }

func (t *GitTree) Walk(ctx context.Context, maxEntries int, visit func(TreeEntry) error) (TreeWalk, error) {
	walk, err := t.store.WalkTree(ctx, t.revision, maxEntries, func(e scm.LocalGitTreeEntry) error {
		kind := EntryFile
		switch e.Mode {
		case evidence.GitTreeModeSymlink:
			kind = EntrySymlink
		case evidence.GitTreeModeGitlink:
			kind = EntrySubmodule
		}
		return visit(TreeEntry{Path: e.Path, Kind: kind, Object: e.Object})
	})
	return TreeWalk{Entries: walk.Entries, Truncated: walk.Truncated, InvalidPaths: walk.InvalidPaths}, err
}

func (t *GitTree) ReadBlob(ctx context.Context, object string) ([]byte, error) {
	return t.store.ReadBlob(ctx, t.revision.Algorithm(), object)
}
