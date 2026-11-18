//go:build linux && (amd64 || arm64)

package checksandbox

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// deniedCalls fail with EPERM: debugging other processes, changing mounts
// or namespaces, loading kernel code and the other calls a check never
// needs and an escape would.
var deniedCalls = append([]uintptr{
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT,
	unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR, unix.SYS_UNSHARE, unix.SYS_SETNS,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_QUOTACTL,
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
}, archDeniedCalls...)

const (
	seccompNumberOffset       = 0
	seccompArchitectureOffset = 4
	seccompFirstArgOffset     = 16
	newNamespaceFlags         = unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWNET |
		unix.CLONE_NEWIPC | unix.CLONE_NEWUTS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWTIME
)

// filterProgram allows every call except the denied ones, clone with a
// new-namespace flag, and clone3, which fails with ENOSYS so that C
// libraries fall back to clone, whose flags the filter can read. A call
// from another architecture's table kills the process.
func filterProgram() []unix.SockFilter {
	errno := func(code unix.Errno) unix.SockFilter {
		return statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(code))
	}
	program := []unix.SockFilter{
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompArchitectureOffset),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, auditArchitecture, 1, 0),
		statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompNumberOffset),
	}
	program = append(program, archPrologue...)
	program = append(program,
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_CLONE3, 0, 1),
		errno(unix.ENOSYS),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_CLONE, 0, 4),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompFirstArgOffset),
		jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, newNamespaceFlags, 0, 1),
		errno(unix.EPERM),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompNumberOffset),
	)
	for _, call := range deniedCalls {
		program = append(program, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(call), 0, 1), errno(unix.EPERM))
	}
	return append(program, statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW))
}

// installFilter installs the filter on every thread of the process.
func installFilter() error {
	program := filterProgram()
	fprog := unix.SockFprog{Len: uint16(len(program)), Filter: &program[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return errno
	}
	return nil
}

func statement(code uint16, value uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: value}
}

func jump(code uint16, value uint32, ifTrue, ifFalse uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: ifTrue, Jf: ifFalse, K: value}
}
