//go:build windows

package fileauthority

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
)

// TrustedOwner always reports false on Windows, where os.FileInfo carries no
// owner. The other checks of this package read the owner and DACL through a
// handle instead.
func TrustedOwner(os.FileInfo) bool { return false }

// trustedEntry checks the entry at path, which must be the one info
// describes: its owner must be this account, LocalSystem, Administrators or
// TrustedInstaller, and its DACL may grant other principals only what others
// permits.
func trustedEntry(path string, info os.FileInfo, others ownersonly.Others) bool {
	return info != nil && ownersonly.CheckPath(path, info, ownersonly.Rule{Owner: ownersonly.OwnerTrusted, Others: others}) == nil
}

func trustedHandle(file *os.File, others ownersonly.Others) bool {
	return file != nil && ownersonly.CheckHandle(syscall.Handle(file.Fd()), ownersonly.Rule{Owner: ownersonly.OwnerTrusted, Others: others}) == nil
}

// componentTrusted requires that no other principal can write the final
// entry and that a directory above it lets others at most add entries, which
// cannot remove, rename or replace the entry below it. Reparse points are
// refused.
func componentTrusted(component pinnedPath, child *pinnedPath) bool {
	info := component.info
	switch component.role {
	case roleDirectory:
		return info.IsDir() && trustedEntry(component.path, info, ownersonly.OthersRead)
	case roleFile:
		return info.Mode().IsRegular() && trustedEntry(component.path, info, ownersonly.OthersRead)
	}
	return child != nil && info.IsDir() && trustedEntry(component.path, info, ownersonly.OthersReadAdd)
}

func openedFileTrusted(file *os.File, info os.FileInfo) bool {
	return info.Mode().IsRegular() && trustedHandle(file, ownersonly.OthersRead)
}

// PrivateFile reports whether info, which describes the entry at path, is a
// regular file, not a reparse point, owned by this account, LocalSystem,
// Administrators or TrustedInstaller, whose DACL grants every other
// principal at most the right to read its attributes and security
// descriptor. It opens path and requires the object to be the one info
// describes.
func PrivateFile(path string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && trustedEntry(path, info, ownersonly.OthersNone)
}

// PrivateOpenFile is PrivateFile for an open file and its Stat, checked
// through the file's own handle.
func PrivateOpenFile(file *os.File, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && trustedHandle(file, ownersonly.OthersNone)
}

// PrivateDirectory reports whether info, which describes the entry at path,
// is a directory that passes the checks of PrivateFile.
func PrivateDirectory(path string, info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && trustedEntry(path, info, ownersonly.OthersNone)
}

// PrivateDirectoryRequirement describes, for an error message, what
// PrivateDirectory requires.
func PrivateDirectoryRequirement(os.FileInfo) string {
	return "only this account, SYSTEM, Administrators and TrustedInstaller may have access"
}

// PrivateFileRequirement describes, for an error message, what PrivateFile
// requires.
func PrivateFileRequirement() string {
	return "a regular file that only this account, SYSTEM, Administrators and TrustedInstaller can access"
}

// UnwritableFile reports whether info, which describes the entry at path, is
// a regular file, not a reparse point, owned by this account, LocalSystem,
// Administrators or TrustedInstaller, whose DACL grants no other principal
// write, DELETE or security-changing rights. Whether the folder above lets
// others remove it is checked by PinDirectory and OpenReadOnly.
func UnwritableFile(path string, info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && trustedEntry(path, info, ownersonly.OthersRead)
}

// MkdirAllPrivate creates path and any missing parent. Each directory it
// creates is owner-only from the start, as ownersonly.Mkdir makes it; an
// existing directory is left as it is.
func MkdirAllPrivate(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if parent := filepath.Dir(path); parent != path {
		if err := MkdirAllPrivate(parent); err != nil {
			return err
		}
	}
	if err := ownersonly.Mkdir(path); err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

// MkdirPrivate creates a new directory at path that is owner-only from the
// start, as ownersonly.Mkdir makes it. It fails if anything exists at path.
func MkdirPrivate(path string) error { return ownersonly.Mkdir(path) }

// CreatePrivateFile creates a new file at path for writing that is
// owner-only from the start, as ownersonly.CreateFile makes it. It fails if
// anything exists at path.
func CreatePrivateFile(path string) (*os.File, error) {
	return ownersonly.CreateFile(path, os.O_WRONLY)
}

// SyncDirectory asks the file system to flush the entries of the directory
// at path, which NTFS commits to stable storage. FlushFileBuffers needs a
// handle with write access, so the directory is opened for adding entries,
// which writes nothing by itself.
func SyncDirectory(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	const addEntries = 0x00000002 | 0x00000004
	const backupSemantics = 0x02000000
	handle, err := syscall.CreateFile(name, addEntries, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, backupSemantics|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	flushErr := syscall.FlushFileBuffers(handle)
	closeErr := syscall.CloseHandle(handle)
	if flushErr != nil {
		return &os.PathError{Op: "sync", Path: path, Err: flushErr}
	}
	return closeErr
}

// createProtected creates base in the directory at parent, which root
// holds open, with an owner-only descriptor. os.Root takes no security
// descriptor, so the file is created by path below the pinned parent; the caller
// then requires that root's entry is the created file.
func createProtected(_ *os.Root, parent, base string) (*os.File, error) {
	return ownersonly.CreateFile(filepath.Join(parent, base), os.O_WRONLY)
}

// syncRoot commits the entries of root, which is the directory at path.
func syncRoot(_ *os.Root, path string) error { return SyncDirectory(path) }
