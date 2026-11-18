//go:build linux

package checksandbox

import "golang.org/x/sys/unix"

const auditArchitecture = unix.AUDIT_ARCH_AARCH64

var archPrologue []unix.SockFilter

var archDeniedCalls []uintptr
