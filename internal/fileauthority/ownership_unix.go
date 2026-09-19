//go:build unix

package fileauthority

import (
	"os"
	"syscall"
)

// TrustedOwner permits the process owner or the operating-system administrator.
func TrustedOwner(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}
