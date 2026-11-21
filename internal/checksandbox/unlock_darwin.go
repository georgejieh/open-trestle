package checksandbox

import (
	"os"

	"golang.org/x/sys/unix"
)

// maxUnlockDepth bounds how deep unlockTree descends, and so how many
// folders it holds open at once.
const maxUnlockDepth = 256

// unlockTree undoes what a test can do to keep its files from being
// deleted: it clears the file flags of every entry below root, such as
// uchg, and gives every folder back its owner's permissions. Each entry is
// opened relative to its open parent and never through a link, so nothing
// outside root changes even if a process still running swaps a folder for
// a link.
func unlockTree(root string) {
	if fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
		unlockOpened(fd, maxUnlockDepth)
	}
}

// unlockOpened unlocks the open entry fd and, when it is a folder, what it
// holds. It closes fd.
func unlockOpened(fd int, depth int) {
	_ = unix.Fchflags(fd, 0)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || depth == 0 {
		_ = unix.Close(fd)
		return
	}
	_ = unix.Fchmod(fd, 0o700)
	folder := os.NewFile(uintptr(fd), "")
	defer folder.Close()
	names, _ := folder.Readdirnames(-1)
	for _, name := range names {
		if child, err := openEntry(fd, name); err == nil {
			unlockOpened(child, depth-1)
		}
	}
}

// openEntry opens name in the folder dir without following a link, first
// giving its owner read access back when it lacks it.
func openEntry(dir int, name string) (int, error) {
	const flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Openat(dir, name, flags, 0)
	if err == unix.EACCES {
		_ = unix.Fchmodat(dir, name, 0o700, unix.AT_SYMLINK_NOFOLLOW)
		fd, err = unix.Openat(dir, name, flags, 0)
	}
	return fd, err
}
