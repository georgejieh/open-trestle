//go:build linux

package controlplane

import (
	"os"
	"syscall"
)

func rootedScannerSupported() bool { return true }
func rootedSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
