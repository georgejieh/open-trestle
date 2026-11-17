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

// privateToProcess reports whether info, which describes the entry at path,
// is owned by the effective user with permission bits that permission
// accepts.
func privateToProcess(_ string, info os.FileInfo, permission unixPermission) bool {
	return permission(info.Mode().Perm()) && fileOwnedByCurrentProcess(info)
}

// openPrivateToProcess is privateToProcess for an open file and its Stat.
func openPrivateToProcess(_ *os.File, info os.FileInfo, permission unixPermission) bool {
	return privateToProcess("", info, permission)
}

// unwritableByOthers reports whether info, which describes the entry at
// path, has no group or other write bit. It does not check the owner.
func unwritableByOthers(_ string, info os.FileInfo) bool { return info.Mode().Perm()&0o022 == 0 }

// trustedUnwritable reports whether info, which describes the entry at path,
// is owned by the effective user or root and has no group or other write
// bit.
func trustedUnwritable(_ string, info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 == 0 && fileOwnedByTrustedProcessOrRoot(info)
}

// stableAncestorAuthority reports whether parent is owned by the effective
// user or root and either writable by no one else or sticky above a child
// that the effective user owns.
func stableAncestorAuthority(parent, child os.FileInfo) bool {
	if !fileOwnedByTrustedProcessOrRoot(parent) {
		return false
	}
	if parent.Mode().Perm()&0o022 == 0 {
		return true
	}
	return parent.Mode()&os.ModeSticky != 0 && fileOwnedByCurrentProcess(child)
}

// stableConfigurationAncestorAuthority is stableAncestorAuthority with a
// sticky parent's child owned by the effective user or root.
func stableConfigurationAncestorAuthority(parent, child os.FileInfo) bool {
	if !fileOwnedByTrustedProcessOrRoot(parent) {
		return false
	}
	if parent.Mode().Perm()&0o022 == 0 {
		return true
	}
	return parent.Mode()&os.ModeSticky != 0 && fileOwnedByTrustedProcessOrRoot(child)
}

// ancestorAuthority checks a directory above a private entry; see
// stableAncestorAuthority.
func ancestorAuthority(_ string, parent os.FileInfo, _ string, child os.FileInfo) bool {
	return stableAncestorAuthority(parent, child)
}

// configurationAncestorAuthority checks a directory above a configuration
// file; see stableConfigurationAncestorAuthority.
func configurationAncestorAuthority(_ string, parent os.FileInfo, _ string, child os.FileInfo) bool {
	return stableConfigurationAncestorAuthority(parent, child)
}

// createPrivateFile creates a new file for writing with mode 0600. It fails
// if anything exists at path.
func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// makePrivateDirectory creates a new directory with mode 0700.
func makePrivateDirectory(path string) error { return os.Mkdir(path, 0o700) }
