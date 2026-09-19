//go:build windows

package filelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
)

var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	lockFileEx   = kernel32.NewProc("LockFileEx")
	unlockFileEx = kernel32.NewProc("UnlockFileEx")
)

func platformLock(file *os.File) error {
	overlapped := new(syscall.Overlapped)
	result, _, callErr := lockFileEx.Call(file.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(overlapped)))
	if result != 0 {
		return nil
	}
	if errors.Is(callErr, syscall.Errno(33)) {
		return ErrLocked
	}
	return fmt.Errorf("%w: lock", ErrOperation)
}
func platformUnlock(file *os.File) error {
	overlapped := new(syscall.Overlapped)
	result, _, _ := unlockFileEx.Call(file.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(overlapped)))
	if result == 0 {
		return fmt.Errorf("%w: unlock", ErrOperation)
	}
	return nil
}
