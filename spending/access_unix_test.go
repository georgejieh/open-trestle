//go:build unix

package spending

import (
	"os"
	"testing"
)

// private reports whether path is a 0700 directory or a 0600 file.
func private(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		return info.Mode().Perm() == 0o700
	}
	return info.Mode().Perm() == 0o600
}

// exposeToOthers sets the mode of path to mode, which lets others in.
func exposeToOthers(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// makePrivate sets the mode of path back to mode.
func makePrivate(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
