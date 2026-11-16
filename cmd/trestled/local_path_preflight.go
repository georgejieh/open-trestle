package main

import (
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/localownerroot"
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

// localExistingRoot checks every existing component through an opened root.
func localExistingRoot(absolute string) (*os.Root, error) {
	return localownerroot.ExistingRoot(absolute, ErrInvalidDaemonConfiguration)
}
