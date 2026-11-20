package checksandbox

import (
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

// storedSize is the size of a file's content.
func storedSize(path string, entry fs.DirEntry) int64 { return lstatSize(path, entry) }

// volumeFree names the volume holding path and returns its free space.
func volumeFree(path string) (string, uint64, bool) {
	var stat unix.Statfs_t
	if unix.Statfs(path, &stat) != nil {
		return "", 0, false
	}
	return fmt.Sprint(stat.Fsid.Val), stat.Bavail * uint64(stat.Bsize), true
}
