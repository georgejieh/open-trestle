//go:build unix

package setup

import (
	"fmt"
	"os"
	"sort"
	"syscall"
)

func fileOwnedByCurrentProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
func fileOwnedByTrustedProcessOrRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Uid == 0 || stat.Uid == uint32(os.Geteuid()))
}

func fileOwnershipSupported() bool { return true }

func currentProcessIdentity() (string, bool) {
	groups, err := os.Getgroups()
	if err != nil {
		return "", false
	}
	sort.Ints(groups)
	return fmt.Sprintf("euid:%d;egid:%d;groups:%v", os.Geteuid(), os.Getegid(), groups), true
}
