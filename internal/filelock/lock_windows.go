//go:build windows

package filelock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
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

// openLockFile opens the lock file at path, creating it owner-only when it
// is missing, so that no other account can open it and hold the lock.
func openLockFile(path string) (*os.File, error) {
	return ownersonly.OpenOrCreateFile(path)
}

// lockFilePrivate reports whether the lock file grants no account other
// than its owner and the system's own accounts access beyond reading its
// attributes and DACL. A lock file another account could open could be
// locked by it.
func lockFilePrivate(file *os.File) bool {
	return ownersonly.CheckHandle(syscall.Handle(file.Fd()), ownersonly.Rule{Owner: ownersonly.OwnerTrusted, Others: ownersonly.OthersNone}) == nil
}
