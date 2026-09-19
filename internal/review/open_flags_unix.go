//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package review

import (
	"os"
	"syscall"
)

func regularFileOpenFlags() int {
	return os.O_RDONLY | syscall.O_NONBLOCK
}
