//go:build linux

package localownerroot

import (
	"fmt"
	"os"
	"syscall"
)

func IdentityFromInfo(info os.FileInfo) (DirectoryIdentity, error) {
	if info == nil || info.Mode() != os.ModeDir|0700 {
		return DirectoryIdentity{}, fmt.Errorf("%w: opened directory metadata", ErrUnsupported)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return DirectoryIdentity{}, fmt.Errorf("%w: opened directory device/inode", ErrUnsupported)
	}
	return DirectoryIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}
