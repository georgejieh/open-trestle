//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package filelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openLockFile opens or creates the lock file at path with mode 0600.
func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

// lockFilePrivate reports true: the mode was set to 0600 through the handle.
func lockFilePrivate(*os.File) bool { return true }

func platformLock(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrLocked
		}
		return fmt.Errorf("%w: lock", ErrOperation)
	}
	return nil
}
func platformUnlock(file *os.File) error {
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("%w: unlock", ErrOperation)
	}
	return nil
}
