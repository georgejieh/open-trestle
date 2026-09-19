//go:build !(aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris)

package review

import "os"

func regularFileOpenFlags() int {
	return os.O_RDONLY
}
