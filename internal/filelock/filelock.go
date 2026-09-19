// Package filelock provides process-lifetime advisory locks for durable local stores.
package filelock

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

var (
	// ErrInvalidPath identifies an empty, symlinked, or non-regular lock path.
	ErrInvalidPath = errors.New("invalid file lock path")
	// ErrLocked identifies a lock currently held by another process or handle.
	ErrLocked = errors.New("file lock held")
	// ErrOperation identifies a filesystem or platform lock failure.
	ErrOperation = errors.New("file lock operation failed")
)

// Lock owns an advisory lock until Close.
type Lock struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

func Acquire(path string) (*Lock, error) {
	if path == "" {
		return nil, ErrInvalidPath
	}
	if information, err := os.Lstat(path); err == nil && information.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidPath
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrInvalidPath
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open", ErrOperation)
	}
	fail := func(err error) (*Lock, error) { _ = file.Close(); return nil, err }
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return fail(ErrInvalidPath)
	}
	pathInformation, err := os.Lstat(path)
	if err != nil || pathInformation.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInformation) {
		return fail(ErrInvalidPath)
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("%w: protect", ErrOperation))
	}
	if err := platformLock(file); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		_ = platformUnlock(file)
		return fail(fmt.Errorf("%w: sync", ErrOperation))
	}
	return &Lock{file: file}, nil
}
func (l *Lock) Close() error {
	if l == nil {
		return ErrInvalidPath
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if err := platformUnlock(l.file); err != nil {
		_ = l.file.Close()
		return err
	}
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("%w: close", ErrOperation)
	}
	return nil
}
