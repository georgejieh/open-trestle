//go:build darwin || linux

package main

import (
	"os"
	"syscall"
)

func openRegularInputFileNative(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
