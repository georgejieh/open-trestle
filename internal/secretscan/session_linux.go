//go:build linux

package secretscan

import (
	"os/exec"
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
