package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// localPathPreflight is a read-only path snapshot, not an owner or race guard.
// Abs normalizes lexical aliases (relative names, dots and repeated separators);
// only symlink aliases in existing components are rejected. Missing suffixes
// cannot be pinned and remain the constructors' responsibility to create.
func localPathPreflight(state string) (func(), error) {
	absolute, err := filepath.Abs(state)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	stateRoot, err := localExistingRoot(absolute)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	artifactRoot, err := localExistingRoot(filepath.Join(absolute, "artifacts"))
	if err != nil {
		if stateRoot != nil {
			_ = stateRoot.Close()
		}
		return nil, ErrInvalidDaemonConfiguration
	}
	if stateRoot != nil && artifactRoot != nil {
		child, childErr := stateRoot.Lstat("artifacts")
		opened, openedErr := artifactRoot.Stat(".")
		if childErr != nil || openedErr != nil || child.Mode() != opened.Mode() || !os.SameFile(child, opened) {
			_ = stateRoot.Close()
			_ = artifactRoot.Close()
			return nil, ErrInvalidDaemonConfiguration
		}
	}
	return func() {
		if artifactRoot != nil {
			_ = artifactRoot.Close()
		}
		if stateRoot != nil {
			_ = stateRoot.Close()
		}
	}, nil
}

// localExistingRoot checks each component from a rooted parent in order. It
// neither creates a missing component nor assumes an ENOENT masks other errors.
func localExistingRoot(absolute string) (*os.Root, error) {
	parent, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, err
	}
	defer func() {
		if parent != nil {
			_ = parent.Close()
		}
	}()
	path := string(filepath.Separator)
	components := strings.Split(strings.TrimPrefix(absolute, path), path)
	for _, component := range components {
		if component == "" {
			continue
		}
		path = filepath.Join(path, component)
		before, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			// The rooted lookup distinguishes a missing child from a changed or
			// inaccessible absolute pathname at this instant.
			if _, rootedErr := parent.Lstat(component); !errors.Is(rootedErr, os.ErrNotExist) {
				return nil, ErrInvalidDaemonConfiguration
			}
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		rooted, err := parent.Lstat(component)
		if err != nil || !os.SameFile(before, rooted) || before.Mode() != rooted.Mode() || !before.IsDir() || before.Mode()&os.ModeType != os.ModeDir {
			return nil, ErrInvalidDaemonConfiguration
		}
		child, err := parent.OpenRoot(component)
		if err != nil {
			return nil, err
		}
		opened, openErr := child.Stat(".")
		after, afterErr := os.Lstat(path)
		rootedAfter, rootedErr := parent.Lstat(component)
		if openErr != nil || afterErr != nil || rootedErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) || !os.SameFile(before, rootedAfter) || before.Mode() != opened.Mode() || before.Mode() != after.Mode() || before.Mode() != rootedAfter.Mode() {
			_ = child.Close()
			return nil, ErrInvalidDaemonConfiguration
		}
		_ = parent.Close()
		parent = child
	}
	info, err := parent.Stat(".")
	if err != nil || info.Mode() != os.ModeDir|0o700 {
		return nil, ErrInvalidDaemonConfiguration
	}
	// The caller holds the observed leaf through the following constructors.
	openedLeaf := parent
	parent = nil
	return openedLeaf, nil
}
