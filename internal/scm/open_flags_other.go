//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris)

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
	return runtime.GOOS == "windows" || runtime.GOOS == "wasip1"
}
