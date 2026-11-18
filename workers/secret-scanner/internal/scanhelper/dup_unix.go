//go:build unix && !linux

package scanhelper

import "golang.org/x/sys/unix"

func duplicateOnto(source, target int) error {
	return unix.Dup2(source, target)
}
