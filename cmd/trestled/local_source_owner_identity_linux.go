//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

func localSourceDirectoryIdentityFromInfo(info os.FileInfo) (localSourceDirectoryIdentity, error) {
	if info == nil || info.Mode() != os.ModeDir|0700 {
		return localSourceDirectoryIdentity{}, fmt.Errorf("%w: opened directory metadata", errLocalSourceOwnerUnsupported)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return localSourceDirectoryIdentity{}, fmt.Errorf("%w: opened directory device/inode", errLocalSourceOwnerUnsupported)
	}
	return localSourceDirectoryIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino)}, nil
}
