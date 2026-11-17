//go:build windows

package scanhelper

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

var errCacheDirectory = errors.New("private cache directories are not verified on Windows")

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

// LimitResources does nothing: Windows writes no core files by default and
// has no descriptor limit of the Unix kind.
func LimitResources() error { return nil }

// ExitWithParent does nothing on Windows, where the parent places the helper
// in a job object that ends it with the parent.
func ExitWithParent() {}

// PrivateCacheDirectory refuses every directory, so the helper exits with
// ExitCacheDirectory before it serves a request on Windows. Owner-only access
// on Windows is a property of the directory's ACL, which this helper does not
// check, and an unchecked cache directory is a path for code injection.
func PrivateCacheDirectory() (string, error) {
	return "", errCacheDirectory
}
