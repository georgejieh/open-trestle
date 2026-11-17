//go:build linux || darwin

package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// openHelperFile opens path without following a final symbolic link and
// verifies, on the open descriptor, that it is a regular file with no write
// permission for anyone and no set-ID or sticky bit, owned by root or the
// current user, whose content has the expected SHA-256. Only the owner could
// add write permission again, and the owner is already trusted.
func openHelperFile(path string, expectedDigest string) (*os.File, int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !validDigest(expectedDigest) {
		return nil, -1, ErrHelperUntrusted
	}
	// O_NONBLOCK keeps a FIFO at the path from blocking the open; it is
	// cleared once the descriptor is known to be a regular file.
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, -1, ErrHelperUntrusted
	}
	var status syscall.Stat_t
	if err := syscall.Fstat(descriptor, &status); err != nil || status.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		status.Mode&0o222 != 0 || status.Mode&(syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX) != 0 || !trustedHelperOwner(status.Uid) ||
		syscall.SetNonblock(descriptor, false) != nil {
		_ = syscall.Close(descriptor)
		return nil, -1, ErrHelperUntrusted
	}
	file := os.NewFile(uintptr(descriptor), path)
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil || hex.EncodeToString(digest.Sum(nil)) != expectedDigest {
		_ = file.Close()
		return nil, -1, ErrHelperUntrusted
	}
	return file, descriptor, nil
}

func trustedHelperOwner(uid uint32) bool {
	return uid == 0 || uid == uint32(os.Geteuid())
}

// openCacheDirectory checks the helper's cache directory and returns the path
// to start the helper in. Symbolic links above the directory are resolved
// once, and every directory on the resolved path must be owned by root or the
// current user and writable by no one else unless it is sticky, so no other
// user can replace an entry on it between the check and the helper's start.
// The directory itself must not be a symbolic link and must be owned by the
// effective user with no group or other permission bit, which is what the
// helper requires of its working directory. With create, a missing directory
// is first created with mode 0700; nothing above it is ever created.
func openCacheDirectory(path string, create bool) (string, error) {
	if !validAbsolutePath(path) || filepath.Dir(path) == path {
		return "", ErrSessionConfig
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || !filepath.IsAbs(parent) || !trustedAncestors(parent) {
		return "", ErrCacheUntrusted
	}
	directory := filepath.Join(parent, filepath.Base(path))
	if create {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", ErrCacheUntrusted
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", ErrCacheUntrusted
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uint32(os.Geteuid()) {
		return "", ErrCacheUntrusted
	}
	return directory, nil
}

// trustedAncestors reports whether directory and every directory above it
// are owned by root or the current user and, unless sticky, writable by no
// one else.
func trustedAncestors(directory string) bool {
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() {
			return false
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !trustedHelperOwner(status.Uid) || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return false
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return true
		}
		directory = parent
	}
}

// processGroup is the helper's process group; the helper is its leader.
type processGroup struct {
	pid int
}

func (group *processGroup) attach(process *os.Process) error {
	group.pid = process.Pid
	return nil
}

// kill sends SIGKILL to every process in the group, then to the leader by
// its process handle in case it left the group.
func (group *processGroup) kill(process *os.Process) {
	if group.pid > 0 {
		_ = syscall.Kill(-group.pid, syscall.SIGKILL)
	}
	_ = process.Kill()
}

func (group *processGroup) release() {}
