//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package filelock

import (
	"fmt"
	"os"
)

func platformLock(file *os.File) error   { return fmt.Errorf("%w: platform unsupported", ErrOperation) }
func platformUnlock(file *os.File) error { return nil }
