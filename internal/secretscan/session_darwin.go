//go:build darwin

package secretscan

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// openVerifiedHelper resolves symbolic links once, requires every directory
// on the resolved path to be writable only by root or the current user (or
// sticky), and verifies the file. macOS cannot execute a descriptor, so the
// resolved path is executed; because no other user can replace an entry on
// that path, the file cannot be swapped between the check and the exec.
func openVerifiedHelper(path string, expectedDigest string) (verifiedHelper, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return verifiedHelper{}, ErrHelperUntrusted
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) || verifyHelperDirectories(filepath.Dir(resolved)) != nil {
		return verifiedHelper{}, ErrHelperUntrusted
	}
	file, _, err := openHelperFile(resolved, expectedDigest)
	if err != nil {
		return verifiedHelper{}, err
	}
	return verifiedHelper{file: file, execPath: resolved, displayPath: resolved}, nil
}

func verifyHelperDirectories(directory string) error {
	for {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() {
			return ErrHelperUntrusted
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !trustedHelperOwner(status.Uid) || info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return ErrHelperUntrusted
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return nil
		}
		directory = parent
	}
}

// configureHelperCommand puts the helper in its own process group. macOS has
// no parent-death signal; a helper whose parent dies sees EOF on stdin.
func configureHelperCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// waitExit blocks until the group leader has exited without reaping it. Any
// kqueue error is treated as an exit, which leads to a kill and a reap.
func (group *processGroup) waitExit() {
	queue, err := syscall.Kqueue()
	if err != nil {
		return
	}
	defer syscall.Close(queue)
	var change syscall.Kevent_t
	syscall.SetKevent(&change, group.pid, syscall.EVFILT_PROC, syscall.EV_ADD|syscall.EV_ONESHOT)
	change.Fflags = syscall.NOTE_EXIT
	events := make([]syscall.Kevent_t, 1)
	for {
		count, err := syscall.Kevent(queue, []syscall.Kevent_t{change}, events, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || count > 0 {
			return
		}
	}
}
