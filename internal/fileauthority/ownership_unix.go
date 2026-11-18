//go:build unix

package fileauthority

import (
	"fmt"
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

func trustedParent(parent, child os.FileInfo) bool {
	return parent.IsDir() && parent.Mode()&os.ModeSymlink == 0 && TrustedOwner(parent) &&
		(parent.Mode().Perm()&0022 == 0 || parent.Mode()&os.ModeSticky != 0 && TrustedOwner(child))
}

func componentTrusted(component pinnedPath, child *pinnedPath) bool {
	info := component.info
	if !TrustedOwner(info) {
		return false
	}
	switch component.role {
	case roleDirectory:
		return info.IsDir() && info.Mode().Perm()&0022 == 0
	case roleFile:
		return info.Mode().IsRegular() && info.Mode().Perm()&0022 == 0
	}
	return child != nil && trustedParent(info, child.info)
}

func openedFileTrusted(_ *os.File, info os.FileInfo) bool { return TrustedOwner(info) }

// PrivateFile reports whether info, which describes the entry at path, is a
// regular file of mode exactly 0600 owned by this account or root. On
// Windows the owner and DACL are checked instead; see the Windows
// implementation.
func PrivateFile(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && TrustedOwner(info)
}

// PrivateOpenFile is PrivateFile for an open file and its Stat.
func PrivateOpenFile(_ *os.File, info os.FileInfo) bool { return PrivateFile("", info) }

// PrivateDirectory reports whether info, which describes the entry at path,
// is a directory, not a symbolic link, of mode exactly 0700. Ownership and
// the directories above it are checked by PinDirectory and CheckDirectory.
func PrivateDirectory(_ string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700
}

// PrivateDirectoryRequirement describes, for an error message, what
// PrivateDirectory requires and what info has instead.
func PrivateDirectoryRequirement(info os.FileInfo) string {
	return fmt.Sprintf("mode 0700, not %04o", info.Mode().Perm())
}

// PrivateFileRequirement describes, for an error message, what PrivateFile
// requires.
func PrivateFileRequirement() string { return "a regular file of mode 0600 owned by this account" }

// UnwritableFile reports whether info, which describes the entry at path, is
// a regular file owned by this account or root without group or other
// write permission.
func UnwritableFile(_ string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o022 == 0 && TrustedOwner(info)
}

// MkdirAllPrivate creates path and any missing parent with mode 0700, as
// os.MkdirAll does.
func MkdirAllPrivate(path string) error { return os.MkdirAll(path, 0o700) }

// MkdirPrivate creates a new directory at path with mode 0700, as os.Mkdir
// does.
func MkdirPrivate(path string) error { return os.Mkdir(path, 0o700) }

// CreatePrivateFile creates a new file at path for writing with mode 0600,
// as os.OpenFile does with O_WRONLY, O_CREATE and O_EXCL. It fails if
// anything exists at path.
func CreatePrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// SyncDirectory commits the entries of the directory at path to stable
// storage.
func SyncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// createProtected creates base in root for WriteNewProtectedFile.
func createProtected(root *os.Root, _, base string) (*os.File, error) {
	return root.OpenFile(base, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// syncRoot commits the entries of root, which is the directory at path.
func syncRoot(root *os.Root, _ string) error {
	directory, err := root.Open(".")
	if err != nil || directory == nil {
		return ErrProtectedWriteIncomplete
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
