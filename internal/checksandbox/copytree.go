package checksandbox

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// copyTree copies the regular files, folders and, except on Windows,
// symbolic links of source into target, which must exist. Executable bits
// are kept. It stops once more than limit bytes would be copied.
func copyTree(source, target string, limit int64) error {
	var total int64
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		destination := filepath.Join(target, relative)
		switch {
		case entry.IsDir():
			return os.Mkdir(destination, 0o755)
		case entry.Type()&fs.ModeSymlink != 0:
			if runtime.GOOS == "windows" {
				return nil
			}
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, destination)
		case entry.Type().IsRegular():
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if total += info.Size(); total > limit {
				return errTreeTooLarge
			}
			return copyFile(path, destination, info.Mode().Perm()&0o111|0o644)
		}
		return nil
	})
}

var errTreeTooLarge = errors.New("the tree is larger than the disk limit")

func copyFile(source, destination string, mode fs.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
