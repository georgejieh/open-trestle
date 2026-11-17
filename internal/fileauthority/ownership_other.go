//go:build !unix && !windows

package fileauthority

import "os"

// TrustedOwner fails closed where ownership authority is not implemented.
func TrustedOwner(os.FileInfo) bool { return false }

func componentTrusted(pinnedPath, *pinnedPath) bool { return false }

func openedFileTrusted(*os.File, os.FileInfo) bool { return false }

// PrivateFile fails closed where ownership authority is not implemented.
func PrivateFile(string, os.FileInfo) bool { return false }

// PrivateOpenFile fails closed where ownership authority is not implemented.
func PrivateOpenFile(*os.File, os.FileInfo) bool { return false }

// PrivateDirectory fails closed where ownership authority is not implemented.
func PrivateDirectory(string, os.FileInfo) bool { return false }

// PrivateDirectoryRequirement describes, for an error message, why
// PrivateDirectory refused.
func PrivateDirectoryRequirement(os.FileInfo) string {
	return "ownership is not checked on this system"
}

// PrivateFileRequirement describes, for an error message, why PrivateFile
// refused.
func PrivateFileRequirement() string { return "a private regular file, which this system cannot check" }

// UnwritableFile fails closed where ownership authority is not implemented.
func UnwritableFile(string, os.FileInfo) bool { return false }

// MkdirAllPrivate creates path and any missing parent with mode 0700.
func MkdirAllPrivate(path string) error { return os.MkdirAll(path, 0o700) }

// MkdirPrivate creates a new directory at path with mode 0700.
func MkdirPrivate(path string) error { return os.Mkdir(path, 0o700) }

// CreatePrivateFile creates a new file at path for writing with mode 0600.
func CreatePrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

// SyncDirectory fails where directory durability is not implemented.
func SyncDirectory(string) error { return ErrUntrustedPath }

func createProtected(*os.Root, string, string) (*os.File, error) {
	return nil, ErrProtectedWriteRefused
}

func syncRoot(*os.Root, string) error { return ErrProtectedWriteIncomplete }
