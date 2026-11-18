//go:build linux

package checksandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// systemPaths are shown read-only in every sandbox; a symbolic link among
// them, as on merged-/usr systems, is recreated rather than mounted.
var systemPaths = []string{"/usr", "/etc", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

var devices = []string{"null", "zero", "full", "random", "urandom", "tty"}

// buildRoot mounts a size-bounded tmpfs on config.Root, fills it with
// read-only views of the system and toolchain folders, a copy of the tree,
// a private home and temporary folder, a few devices and a fresh /proc, and
// makes it the root. Nothing else of the host remains reachable.
func buildRoot(config childConfig) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("mount propagation: %w", err)
	}
	root := config.Root
	options := "mode=0755,size=" + strconv.FormatInt(config.Limits.DiskBytes, 10)
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, options); err != nil {
		return fmt.Errorf("scratch: %w", err)
	}
	for _, directory := range []string{sandboxWork, sandboxHome, sandboxTemp, "/dev/shm", "/proc"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			return err
		}
	}
	for _, directory := range []string{sandboxTemp, "/dev/shm"} {
		if err := os.Chmod(filepath.Join(root, directory), 0o1777); err != nil {
			return err
		}
	}
	for _, path := range systemPaths {
		if err := showSystemPath(root, path); err != nil {
			return err
		}
	}
	for _, path := range toolchainMounts(config.ReadOnly) {
		if err := bindReadOnly(path, filepath.Join(root, path)); err != nil {
			return err
		}
	}
	if err := populateDevices(root); err != nil {
		return err
	}
	if err := copyTree(config.Tree, filepath.Join(root, sandboxWork), config.Limits.DiskBytes); err != nil {
		return fmt.Errorf("tree copy: %w", err)
	}
	if err := unix.Mount("proc", filepath.Join(root, "proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	if err := os.Chdir(root); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("old root: %w", err)
	}
	return os.Chdir("/")
}

func showSystemPath(root, path string) error {
	info, err := os.Lstat(path)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return err
	case info.Mode()&os.ModeSymlink != 0:
		link, err := os.Readlink(path)
		if err != nil {
			return err
		}
		return os.Symlink(link, filepath.Join(root, path))
	case info.IsDir():
		return bindReadOnly(path, filepath.Join(root, path))
	}
	return nil
}

// toolchainMounts drops paths already visible through a system path or
// through another toolchain path.
func toolchainMounts(paths []string) []string {
	var kept []string
	seen := map[string]bool{}
	for _, path := range paths {
		path = filepath.Clean(path)
		covered := seen[path]
		for _, other := range append(append([]string{}, systemPaths...), paths...) {
			if filepath.Clean(other) != path && within(other, path) {
				covered = true
				break
			}
		}
		seen[path] = true
		if !covered {
			kept = append(kept, path)
		}
	}
	return kept
}

// bindReadOnly shows source and the mounts below it read-only at target.
// A user namespace refuses a non-recursive bind of a folder with mounts
// below it, so the bind is recursive and each of those mounts is made
// read-only too.
func bindReadOnly(source, target string) error {
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		err = os.MkdirAll(target, 0o755)
	} else {
		err = createEmptyFile(target)
	}
	if err != nil {
		return err
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	mounts, err := mountsAt(target)
	if err != nil {
		return err
	}
	for _, mount := range mounts {
		if err := remountReadOnly(mount); err != nil {
			return fmt.Errorf("%s read-only: %w", mount, err)
		}
	}
	return nil
}

// mountsAt lists target and the mount points below it, parents first.
func mountsAt(target string) ([]string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	mounts := []string{target}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		point := unescapeMountPoint(fields[4])
		if point != target && within(target, point) && !slices.Contains(mounts, point) {
			mounts = append(mounts, point)
		}
	}
	return mounts, nil
}

// unescapeMountPoint undoes the octal escapes of /proc/self/mountinfo.
func unescapeMountPoint(field string) string {
	var out strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+3 < len(field) {
			if value, err := strconv.ParseUint(field[i+1:i+4], 8, 8); err == nil {
				out.WriteByte(byte(value))
				i += 3
				continue
			}
		}
		out.WriteByte(field[i])
	}
	return out.String()
}

// remountReadOnly makes one bind mount read-only, keeping its nosuid,
// nodev, noexec and access-time flags, which a user namespace may not
// clear.
func remountReadOnly(target string) error {
	var stat unix.Statfs_t
	if err := unix.Statfs(target, &stat); err != nil {
		return err
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY)
	for statFlag, mountFlag := range map[int64]uintptr{
		unix.ST_NOSUID: unix.MS_NOSUID, unix.ST_NODEV: unix.MS_NODEV, unix.ST_NOEXEC: unix.MS_NOEXEC,
		unix.ST_NOATIME: unix.MS_NOATIME, unix.ST_NODIRATIME: unix.MS_NODIRATIME, unix.ST_RELATIME: unix.MS_RELATIME,
	} {
		if stat.Flags&statFlag != 0 {
			flags |= mountFlag
		}
	}
	return unix.Mount("", target, "", flags, "")
}

func createEmptyFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

// populateDevices binds the harmless character devices and links the
// standard descriptors.
func populateDevices(root string) error {
	for _, name := range devices {
		source, target := "/dev/"+name, filepath.Join(root, "dev", name)
		if _, err := os.Stat(source); err != nil {
			continue
		}
		if err := createEmptyFile(target); err != nil {
			return err
		}
		if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
	}
	for name, link := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(link, filepath.Join(root, "dev", name)); err != nil {
			return err
		}
	}
	return nil
}
