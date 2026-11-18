//go:build linux

package secretscan

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"
)

// openVerifiedHelper verifies the helper and returns a path that executes
// the verified descriptor itself, so renaming or replacing the file at the
// configured path after the check cannot change what runs.
func openVerifiedHelper(path string, expectedDigest string) (verifiedHelper, error) {
	file, descriptor, err := openHelperFile(path, expectedDigest)
	if err != nil {
		return verifiedHelper{}, err
	}
	return verifiedHelper{file: file, execPath: "/proc/self/fd/" + strconv.Itoa(descriptor), displayPath: path}, nil
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

func configureHelperCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

// waitExit blocks until the group leader has exited without reaping it, so
// its process ID and group ID stay reserved until the group is killed.
func (group *processGroup) waitExit() {
	const idTypePID = 1
	var information [128]byte
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, idTypePID, uintptr(group.pid), uintptr(unsafe.Pointer(&information[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
		if errno != syscall.EINTR {
			return
		}
	}
}
