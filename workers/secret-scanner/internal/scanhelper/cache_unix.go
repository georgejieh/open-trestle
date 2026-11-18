//go:build unix && !darwin

package scanhelper

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var errCacheDirectory = errors.New("working directory is not a private cache directory")

// PrivateCacheDirectory returns the working directory after checking that it
// is a directory, not a symbolic link, owned by the effective user and
// without any group or other permission bit. wazero loads native code from
// the cache, so a directory anyone else can write would let them run code
// in the helper.
func PrivateCacheDirectory() (string, error) {
	directory, err := os.Getwd()
	if err != nil || !filepath.IsAbs(directory) {
		return "", errCacheDirectory
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errCacheDirectory
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return "", errCacheDirectory
	}
	return directory, nil
}
