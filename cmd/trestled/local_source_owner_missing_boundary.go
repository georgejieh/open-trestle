package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// localMissingStateBoundary is a sampled, unwired pre-constructor observation.
// It does not grant ownership, enrollment, or activation authority.
type localMissingStateBoundary struct {
	StatePath   string
	ParentPath  string
	ParentRoot  *os.Root
	ParentInfo  os.FileInfo
	ParentPin   *fileauthority.DirectoryPin
	Suffix      []string
	closeParent func(*os.Root) error
}

var errLocalMissingStateBoundary = errors.New("local missing state boundary refused")

func missingBoundaryContext(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return errLocalMissingStateBoundary
	}
	return nil
}

func missingBoundarySame(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode()
}

func missingBoundaryPrivate(info os.FileInfo) bool {
	return info != nil && info.Mode() == os.ModeDir|0700 && fileauthority.TrustedOwner(info)
}

func missingBoundaryComponent(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 128 && !strings.ContainsAny(name, `/\`)
}

// Keep the original identity of even sticky ancestors, which PinDirectory
// accepts inside a chain but cannot pin as the final (writable) directory.
type missingBoundaryPathPin struct {
	path string
	info os.FileInfo
}

func missingBoundaryPinsUnchanged(pins []missingBoundaryPathPin) bool {
	for _, pin := range pins {
		current, err := os.Lstat(pin.path)
		if err != nil || !missingBoundarySame(pin.info, current) || !fileauthority.TrustedOwner(current) {
			return false
		}
	}
	return true
}

// captureLocalMissingStateBoundary retains the original deepest existing parent.
// Only the first missing child is observed absent; later suffix parts are lexical.
func captureLocalMissingStateBoundary(ctx context.Context, stateDir string) (*localMissingStateBoundary, error) {
	return captureLocalMissingStateBoundaryWithOpenedParent(ctx, stateDir, nil)
}

// openedParent is a per-call observation seam after an existing parent is opened.
func captureLocalMissingStateBoundaryWithOpenedParent(ctx context.Context, stateDir string, openedParent func(string)) (boundary *localMissingStateBoundary, err error) {
	if missingBoundaryContext(ctx) != nil || stateDir == "" {
		return nil, errLocalMissingStateBoundary
	}
	absolute, absErr := filepath.Abs(stateDir)
	if absErr != nil || absolute == string(filepath.Separator) {
		return nil, errLocalMissingStateBoundary
	}
	names := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	parent, openErr := os.OpenRoot(string(filepath.Separator))
	if openErr != nil {
		return nil, errors.Join(errLocalMissingStateBoundary, openErr)
	}
	defer func() {
		if parent != nil {
			err = errors.Join(err, parent.Close())
			if err != nil {
				boundary = nil
			}
		}
	}()
	path := string(filepath.Separator)
	parentPin, pinErr := fileauthority.PinDirectory(path)
	if pinErr != nil {
		return nil, errors.Join(errLocalMissingStateBoundary, pinErr)
	}
	rootedRoot, rootErr := parent.Stat(".")
	namedRoot, namedErr := os.Lstat(path)
	if rootErr != nil || namedErr != nil || !missingBoundarySame(rootedRoot, namedRoot) || parentPin.Recheck() != nil {
		return nil, errLocalMissingStateBoundary
	}
	pins := []missingBoundaryPathPin{{path, namedRoot}}
	for index, name := range names {
		if missingBoundaryContext(ctx) != nil || !missingBoundaryComponent(name) {
			return nil, errLocalMissingStateBoundary
		}
		childPath := filepath.Join(path, name)
		before, statErr := os.Lstat(childPath)
		if errors.Is(statErr, os.ErrNotExist) {
			if _, rootedErr := parent.Lstat(name); !errors.Is(rootedErr, os.ErrNotExist) {
				return nil, errLocalMissingStateBoundary
			}
			suffix := append([]string(nil), names[index:]...)
			if len(suffix) == 0 || len(suffix) > 64 {
				return nil, errLocalMissingStateBoundary
			}
			for _, component := range suffix {
				if !missingBoundaryComponent(component) {
					return nil, errLocalMissingStateBoundary
				}
			}
			original, rootErr := parent.Stat(".")
			if rootErr != nil || !missingBoundaryPrivate(original) {
				return nil, errLocalMissingStateBoundary
			}
			current, currentErr := os.Lstat(path)
			opened, openedErr := parent.Stat(".")
			if currentErr != nil || openedErr != nil || !missingBoundarySame(original, current) || !missingBoundarySame(original, opened) || !missingBoundaryPinsUnchanged(pins) || parentPin.Recheck() != nil || missingBoundaryContext(ctx) != nil {
				return nil, errLocalMissingStateBoundary
			}
			if _, pathnameErr := os.Lstat(childPath); !errors.Is(pathnameErr, os.ErrNotExist) {
				return nil, errLocalMissingStateBoundary
			}
			if _, rootedErr := parent.Lstat(name); !errors.Is(rootedErr, os.ErrNotExist) {
				return nil, errLocalMissingStateBoundary
			}
			if parentPin.Recheck() != nil || !missingBoundaryPinsUnchanged(pins) || missingBoundaryContext(ctx) != nil {
				return nil, errLocalMissingStateBoundary
			}
			result := &localMissingStateBoundary{StatePath: absolute, ParentPath: path, ParentRoot: parent, ParentInfo: original, ParentPin: parentPin, Suffix: suffix}
			parent = nil
			return result, nil
		}
		if statErr != nil || before == nil || !before.IsDir() || before.Mode()&os.ModeType != os.ModeDir {
			return nil, errLocalMissingStateBoundary
		}
		rooted, rootedErr := parent.Lstat(name)
		if rootedErr != nil || !missingBoundarySame(before, rooted) || !fileauthority.TrustedOwner(before) || !missingBoundaryPinsUnchanged(pins) || parentPin.Recheck() != nil {
			return nil, errLocalMissingStateBoundary
		}
		// A sticky writable directory may be a trusted ancestor, but may
		// not itself be the leaf of a fileauthority.DirectoryPin.
		childPin := parentPin
		if before.Mode().Perm()&0022 == 0 {
			var pinErr error
			childPin, pinErr = fileauthority.PinDirectory(childPath)
			if pinErr != nil {
				return nil, errors.Join(errLocalMissingStateBoundary, pinErr)
			}
		} else if before.Mode()&os.ModeSticky == 0 {
			return nil, errLocalMissingStateBoundary
		}
		pins = append(pins, missingBoundaryPathPin{childPath, before})
		if !missingBoundaryPinsUnchanged(pins) || parentPin.Recheck() != nil || childPin.Recheck() != nil {
			return nil, errLocalMissingStateBoundary
		}
		child, childErr := parent.OpenRoot(name)
		if childErr != nil {
			return nil, errors.Join(errLocalMissingStateBoundary, childErr)
		}
		opened, openedErr := child.Stat(".")
		after, afterErr := os.Lstat(childPath)
		rootedAfter, rootedAfterErr := parent.Lstat(name)
		if openedErr != nil || afterErr != nil || rootedAfterErr != nil || !missingBoundarySame(before, opened) || !missingBoundarySame(before, after) || !missingBoundarySame(before, rootedAfter) || !missingBoundaryPinsUnchanged(pins) || parentPin.Recheck() != nil || childPin.Recheck() != nil {
			return nil, errors.Join(errLocalMissingStateBoundary, child.Close())
		}
		if closeErr := parent.Close(); closeErr != nil {
			parent = nil
			return nil, errors.Join(errLocalMissingStateBoundary, closeErr, child.Close())
		}
		parent = child
		parentPin = childPin
		path = childPath
		if openedParent != nil {
			openedParent(path)
		}
	}
	return nil, errLocalMissingStateBoundary
}

func (b *localMissingStateBoundary) recheckParent(ctx context.Context) error {
	if missingBoundaryContext(ctx) != nil || b == nil || b.ParentRoot == nil || b.ParentPin == nil || b.ParentInfo == nil || !missingBoundaryPrivate(b.ParentInfo) || len(b.Suffix) == 0 || len(b.Suffix) > 64 || filepath.Join(append([]string{b.ParentPath}, b.Suffix...)...) != b.StatePath {
		return errLocalMissingStateBoundary
	}
	if b.ParentPin.Recheck() != nil {
		return errLocalMissingStateBoundary
	}
	rooted, rootErr := b.ParentRoot.Stat(".")
	named, nameErr := os.Lstat(b.ParentPath)
	if rootErr != nil || nameErr != nil || !missingBoundarySame(b.ParentInfo, rooted) || !missingBoundarySame(b.ParentInfo, named) || missingBoundaryContext(ctx) != nil {
		return errLocalMissingStateBoundary
	}
	return nil
}

func (b *localMissingStateBoundary) RecheckMissing(ctx context.Context) error {
	if err := b.recheckParent(ctx); err != nil {
		return err
	}
	child := b.Suffix[0]
	if !missingBoundaryComponent(child) {
		return errLocalMissingStateBoundary
	}
	if _, err := b.ParentRoot.Lstat(child); !errors.Is(err, os.ErrNotExist) {
		return errLocalMissingStateBoundary
	}
	if _, err := os.Lstat(filepath.Join(b.ParentPath, child)); !errors.Is(err, os.ErrNotExist) {
		return errLocalMissingStateBoundary
	}
	return b.recheckParent(ctx)
}

// RecheckConstructed borrows stateRoot only inside the caller's nested leases.
// The separate post-constructor shape check handles state locks and artifacts.
func (b *localMissingStateBoundary) RecheckConstructed(ctx context.Context, stateRoot *os.Root) (err error) {
	if stateRoot == nil || b.recheckParent(ctx) != nil {
		return errLocalMissingStateBoundary
	}
	parent := b.ParentRoot
	path := b.ParentPath
	var children []*os.Root
	defer func() {
		for i := len(children) - 1; i >= 0; i-- {
			err = errors.Join(err, children[i].Close())
		}
	}()
	var final os.FileInfo
	for index, name := range b.Suffix {
		if missingBoundaryContext(ctx) != nil || !missingBoundaryComponent(name) {
			return errLocalMissingStateBoundary
		}
		path = filepath.Join(path, name)
		before, namedErr := os.Lstat(path)
		rooted, rootedErr := parent.Lstat(name)
		if namedErr != nil || rootedErr != nil || !missingBoundaryPrivate(before) || !missingBoundarySame(before, rooted) {
			return errLocalMissingStateBoundary
		}
		child, openErr := parent.OpenRoot(name)
		if openErr != nil {
			return errors.Join(errLocalMissingStateBoundary, openErr)
		}
		children = append(children, child)
		opened, openedErr := child.Stat(".")
		after, afterErr := os.Lstat(path)
		rootedAfter, rootedAfterErr := parent.Lstat(name)
		if openedErr != nil || afterErr != nil || rootedAfterErr != nil || !missingBoundarySame(before, opened) || !missingBoundarySame(before, after) || !missingBoundarySame(before, rootedAfter) {
			return errLocalMissingStateBoundary
		}
		if index+1 < len(b.Suffix) {
			entries, entriesErr := boundedOwnerEntries(child, 1)
			if entriesErr != nil || len(entries) != 1 || entries[0].Name() != b.Suffix[index+1] {
				return errLocalMissingStateBoundary
			}
		} else {
			final = before
		}
		parent = child
	}
	borrowedBefore, beforeErr := stateRoot.Stat(".")
	if beforeErr != nil || !missingBoundaryPrivate(borrowedBefore) || !missingBoundarySame(final, borrowedBefore) {
		return errLocalMissingStateBoundary
	}
	if b.recheckParent(ctx) != nil {
		return errLocalMissingStateBoundary
	}
	namedAfter, namedErr := os.Lstat(b.StatePath)
	rootedAfter, rootedErr := parent.Stat(".")
	borrowedAfter, borrowedErr := stateRoot.Stat(".")
	if namedErr != nil || rootedErr != nil || borrowedErr != nil || !missingBoundarySame(final, namedAfter) || !missingBoundarySame(final, rootedAfter) || !missingBoundarySame(final, borrowedAfter) || missingBoundaryContext(ctx) != nil {
		return errLocalMissingStateBoundary
	}
	return nil
}

func (b *localMissingStateBoundary) Close() error {
	if b == nil || b.ParentRoot == nil {
		return nil
	}
	root := b.ParentRoot
	b.ParentRoot = nil
	if b.closeParent != nil {
		return b.closeParent(root)
	}
	return root.Close()
}
