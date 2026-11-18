//go:build unix && !darwin

package syntaxwasm

import (
	"os"
	"path/filepath"
	"syscall"
)

// privateCacheDirectory checks the compilation cache directory and returns
// the path with symbolic links above it resolved. Every directory on the
// resolved path must be owned by root or the current user and writable by
// no one else unless it is sticky. The directory itself must not be a
// symbolic link and must be owned by the effective user with no group or
// other permission bit.
func privateCacheDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == path {
		return "", ErrCacheUntrusted
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || !filepath.IsAbs(parent) || !trustedAncestors(parent) {
		return "", ErrCacheUntrusted
	}
	directory := filepath.Join(parent, filepath.Base(path))
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", ErrCacheUntrusted
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(status.Uid) != uint64(os.Geteuid()) {
		return "", ErrCacheUntrusted
	}
	return directory, nil
}

func trustedAncestors(directory string) bool {
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() {
			return false
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (status.Uid != 0 && uint64(status.Uid) != uint64(os.Geteuid())) || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return false
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return true
		}
		directory = parent
	}
}
