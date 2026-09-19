//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package filelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

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
