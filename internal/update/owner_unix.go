//go:build unix

package update

import (
	"os"
	"syscall"
)

// fileOwner is the numeric owner of info's file.
func fileOwner(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
