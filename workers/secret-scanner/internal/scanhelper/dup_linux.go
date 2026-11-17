//go:build linux

package scanhelper

import "golang.org/x/sys/unix"

func duplicateOnto(source, target int) error {
	return unix.Dup3(source, target, 0)
}
