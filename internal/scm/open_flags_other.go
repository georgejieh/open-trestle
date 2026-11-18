//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris || windows)

package scm

import (
	"os"
	"runtime"
)

func regularFileOpenFlags() int {
	return os.O_RDONLY
}

func nonblockingRegularFileOpenSupported() bool {
	return false
}

func confinedRootOpenSupported() bool {
	return runtime.GOOS == "wasip1"
}
