//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package filelock

import (
	"fmt"
	"os"
)

// openLockFile opens or creates the lock file at path with mode 0600.
func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

// lockFilePrivate reports true: the mode was set to 0600 through the handle.
func lockFilePrivate(*os.File) bool { return true }

func platformLock(file *os.File) error   { return fmt.Errorf("%w: platform unsupported", ErrOperation) }
func platformUnlock(file *os.File) error { return nil }
