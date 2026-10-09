//go:build unix

package main

import (
	"os"
	"syscall"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

func ownerConstructorLockInfo(info os.FileInfo) bool {
	if info == nil || info.Mode() != 0600 || !fileauthority.TrustedOwner(info) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
