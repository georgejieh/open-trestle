//go:build linux

package main

import (
	"os"
	"syscall"
)

// TrustedOwner admits both root and this process; each witness must retain
// the exact original UID as well as independently passing the trust check.
func physicalPacketInodeOwnerSame(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return false
	}
	first, okA := a.Sys().(*syscall.Stat_t)
	second, okB := b.Sys().(*syscall.Stat_t)
	return okA && okB && first.Dev == second.Dev && first.Ino == second.Ino && first.Uid == second.Uid
}
