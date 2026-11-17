//go:build windows

package scanhelper

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/ownersonly"
)

var errCacheDirectory = errors.New("working directory is not a private cache directory")

// IsolateStandardStreams keeps the standard output handle for the protocol
// and makes the process's standard output and error handles the null device.
func IsolateStandardStreams() (*os.File, error) {
	protocol := os.Stdout
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	for _, standard := range []uint32{windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		if err := windows.SetStdHandle(standard, windows.Handle(null.Fd())); err != nil {
			_ = null.Close()
			return nil, err
		}
	}
	os.Stdout = null
	os.Stderr = null
	return protocol, nil
}

// CloseInheritedDescriptors does nothing on Windows, where the parent's
// os/exec lets the helper inherit only the handles it names: standard input,
// output and error.
func CloseInheritedDescriptors() error { return nil }

// LimitResources does nothing: Windows writes no core files by default and
// has no descriptor limit of the Unix kind.
func LimitResources() error { return nil }

// WatchInputHangup does nothing on Windows, where the parent places the
// helper in a job object that ends it with the parent.
func WatchInputHangup(int) (stop func()) { return func() {} }

// ExitWithParent does nothing on Windows, where the parent places the helper
// in a job object that ends it with the parent.
func ExitWithParent() {}

// PrivateCacheDirectory returns the working directory after checking that it
// is a directory, not a reparse point, owned by the current user, whose DACL
// grants principals other than the current user and the system's own
// accounts no access beyond reading attributes; see package ownersonly. wazero loads native code
// from the cache, so a directory anyone else can write would let them run
// code in the helper.
func PrivateCacheDirectory() (string, error) {
	directory, err := os.Getwd()
	if err != nil || !filepath.IsAbs(directory) {
		return "", errCacheDirectory
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		ownersonly.CheckPath(directory, info, ownersonly.Rule{Owner: ownersonly.OwnerCurrentUser, Others: ownersonly.OthersNone}) != nil {
		return "", errCacheDirectory
	}
	return directory, nil
}
