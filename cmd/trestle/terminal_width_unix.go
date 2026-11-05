//go:build linux || darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

func queryTerminalColumns(file *os.File) int {
	var size struct{ rows, columns, x, y uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size)))
	if errno != 0 {
		return 0
	}
	return int(size.columns)
}
