//go:build linux && amd64

package sandbox

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ErrUnavailable = errors.New("secret scanner sandbox unavailable")

const (
	seccompDataNumberOffset       = 0
	seccompDataArchitectureOffset = 4
	seccompDataArgumentsOffset    = 16
	auditArchitectureX86_64       = 0xc000003e
	x32SyscallBit                 = 0x40000000
)

func Install() error {
	if !hasNoNewPrivileges() {
		return ErrUnavailable
	}
	filters := seccompFilters()
	program := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}
	_, _, errno := unix.RawSyscall6(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&program)),
		0,
		0,
		0,
	)
	if errno != 0 {
		return ErrUnavailable
	}
	return nil
}

func SilenceStandardError() error {
	var descriptors [2]int
	if err := unix.Pipe2(descriptors[:], unix.O_CLOEXEC); err != nil {
		return ErrUnavailable
	}
	defer unix.Close(descriptors[0])
	defer unix.Close(descriptors[1])
	if err := unix.Dup3(descriptors[0], unix.Stderr, 0); err != nil {
		return ErrUnavailable
	}
	return nil
}

func hasNoNewPrivileges() bool {
	value, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	return errno == 0 && value == 1
}

func seccompFilters() []unix.SockFilter {
	filters := []unix.SockFilter{
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArchitectureOffset),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, auditArchitectureX86_64, 1, 0),
		statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNumberOffset),
		jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, x32SyscallBit, 0, 1),
		denyStatement(),
	}
	filters = appendArgumentMaskDenial(filters, unix.SYS_CLONE, 0, namespaceCloneFlags)
	filters = appendArgumentMaskDenial(filters, unix.SYS_OPEN, 1, writeOpenFlags)
	filters = appendArgumentMaskDenial(filters, unix.SYS_OPENAT, 2, writeOpenFlags)
	for _, syscallNumber := range deniedSyscalls {
		filters = append(filters,
			jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(syscallNumber), 0, 1),
			denyStatement(),
		)
	}
	return append(filters, statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ALLOW))
}

func appendArgumentMaskDenial(filters []unix.SockFilter, syscallNumber uintptr, argument uint32, mask uint32) []unix.SockFilter {
	return append(filters,
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(syscallNumber), 0, 4),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataArgumentsOffset+argument*8),
		jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, mask, 0, 1),
		denyStatement(),
		statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, seccompDataNumberOffset),
	)
}

func statement(code uint16, value uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: value}
}

func jump(code uint16, value uint32, jumpTrue uint8, jumpFalse uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jumpTrue, Jf: jumpFalse, K: value}
}

func denyStatement() unix.SockFilter {
	return statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM))
}

const namespaceCloneFlags = unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS | unix.CLONE_NEWPID | unix.CLONE_NEWTIME | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS

const writeOpenFlags = unix.O_WRONLY | unix.O_RDWR | unix.O_APPEND | unix.O_CREAT | unix.O_TRUNC | unix.O_TMPFILE

var deniedSyscalls = [...]uintptr{
	unix.SYS_SOCKET,
	unix.SYS_SOCKETPAIR,
	unix.SYS_CONNECT,
	unix.SYS_BIND,
	unix.SYS_LISTEN,
	unix.SYS_ACCEPT,
	unix.SYS_ACCEPT4,
	unix.SYS_SENDTO,
	unix.SYS_SENDMSG,
	unix.SYS_SENDMMSG,
	unix.SYS_RECVFROM,
	unix.SYS_RECVMSG,
	unix.SYS_RECVMMSG,
	unix.SYS_SHUTDOWN,
	unix.SYS_SETSOCKOPT,
	unix.SYS_GETSOCKOPT,
	unix.SYS_GETPEERNAME,
	unix.SYS_GETSOCKNAME,
	unix.SYS_EXECVE,
	unix.SYS_EXECVEAT,
	unix.SYS_UNSHARE,
	unix.SYS_SETNS,
	unix.SYS_CLONE3,
	unix.SYS_MOUNT,
	unix.SYS_UMOUNT2,
	unix.SYS_PIVOT_ROOT,
	unix.SYS_CHROOT,
	unix.SYS_OPEN_TREE,
	unix.SYS_MOVE_MOUNT,
	unix.SYS_FSOPEN,
	unix.SYS_FSCONFIG,
	unix.SYS_FSMOUNT,
	unix.SYS_MOUNT_SETATTR,
	unix.SYS_PTRACE,
	unix.SYS_PROCESS_VM_READV,
	unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_KCMP,
	unix.SYS_PIDFD_GETFD,
	unix.SYS_OPENAT2,
	unix.SYS_CREAT,
	unix.SYS_TRUNCATE,
	unix.SYS_FTRUNCATE,
	unix.SYS_UNLINK,
	unix.SYS_UNLINKAT,
	unix.SYS_RENAME,
	unix.SYS_RENAMEAT,
	unix.SYS_RENAMEAT2,
	unix.SYS_LINK,
	unix.SYS_LINKAT,
	unix.SYS_SYMLINK,
	unix.SYS_SYMLINKAT,
	unix.SYS_MKDIR,
	unix.SYS_MKDIRAT,
	unix.SYS_RMDIR,
	unix.SYS_MKNOD,
	unix.SYS_MKNODAT,
	unix.SYS_CHMOD,
	unix.SYS_FCHMOD,
	unix.SYS_FCHMODAT,
	unix.SYS_CHOWN,
	unix.SYS_FCHOWN,
	unix.SYS_LCHOWN,
	unix.SYS_FCHOWNAT,
	unix.SYS_UTIME,
	unix.SYS_UTIMES,
	unix.SYS_FUTIMESAT,
	unix.SYS_UTIMENSAT,
	unix.SYS_SETXATTR,
	unix.SYS_LSETXATTR,
	unix.SYS_FSETXATTR,
	unix.SYS_REMOVEXATTR,
	unix.SYS_LREMOVEXATTR,
	unix.SYS_FREMOVEXATTR,
	unix.SYS_FALLOCATE,
	unix.SYS_MEMFD_CREATE,
	unix.SYS_SWAPON,
	unix.SYS_SWAPOFF,
	unix.SYS_QUOTACTL,
	unix.SYS_IO_URING_SETUP,
	unix.SYS_IO_URING_ENTER,
	unix.SYS_IO_URING_REGISTER,
	unix.SYS_BPF,
	unix.SYS_USERFAULTFD,
	unix.SYS_PERF_EVENT_OPEN,
}
