//go:build linux

package checksandbox

import "golang.org/x/sys/unix"

const auditArchitecture = unix.AUDIT_ARCH_X86_64

// archPrologue kills a process that uses the x32 system call table.
var archPrologue = []unix.SockFilter{
	jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, 0x40000000, 0, 1),
	statement(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
}

var archDeniedCalls = []uintptr{unix.SYS_IOPL, unix.SYS_IOPERM}
