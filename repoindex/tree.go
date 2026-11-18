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
	// ReadBlobs reads blobs one after another: it asks next for each object
	// ID until next reports none, and passes each blob, or the error of
	// reading it, to deliver. An error of deliver ends the reading and is
	// returned.
	ReadBlobs(ctx context.Context, next func() (string, bool), deliver func([]byte, error) error) error
}

// GitTree reads a commit from the verified object store reviews use.
type GitTree struct {
	store    *scm.LocalGitObjectStore
	revision evidence.RevisionIdentity
	// acquisitionBytes is how many blob bytes one acquisition of the
	// object store reads before the next starts.
	acquisitionBytes int64
}

// NewGitTree returns the tree of a commit in the store.
func NewGitTree(store *scm.LocalGitObjectStore, revision evidence.RevisionIdentity) (*GitTree, error) {
	if store == nil || revision.Kind() != evidence.RevisionKindGitCommit {
		return nil, errors.New("a Git commit in a local object store is required")
	}
	return &GitTree{store: store, revision: revision, acquisitionBytes: acquisitionBytes}, nil
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

// acquisitionBytes keeps an acquisition well inside its work budget. Each
// acquisition ends with a check of the packs, so fewer are faster.
const acquisitionBytes = 64 << 20

var errNextAcquisition = errors.New("next acquisition")

// ReadBlobs implements Tree. A blob past an acquisition's work budget is
// read again in a fresh acquisition before it counts as unreadable.
func (t *GitTree) ReadBlobs(ctx context.Context, next func() (string, bool), deliver func([]byte, error) error) error {
	carry, more := "", true
	for more {
		err := t.store.WithObjectReader(ctx, func(reader scm.LocalGitObjectReader) error {
			var read int64
			fresh := true
			for {
				object := carry
				if carry == "" {
					if object, more = next(); !more {
						return nil
					}
				}
				carry = ""
				content, err := reader.ReadBlob(ctx, t.revision.Algorithm(), object)
				if errors.Is(err, scm.LocalGitRevisionResourceLimit) && !fresh {
					carry = object
					return errNextAcquisition
				}
				fresh = false
				if err := deliver(content, err); err != nil {
					return err
				}
				if read += int64(len(content)); read >= t.acquisitionBytes {
					return errNextAcquisition
				}
			}
		})
		if err != nil && !errors.Is(err, errNextAcquisition) {
			return err
		}
	}
	return nil
}
