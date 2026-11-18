//go:build unix

package main

import (
	"os"
	"testing"
)

// privateTestFile reports whether path is a 0600 file.
func privateTestFile(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm() == 0o600
}

// exposeTestDirectory lets other accounts list path: mode 0755.
func exposeTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// privateDirectoryRefusal is part of the explanation for a directory that is
// not private.
const privateDirectoryRefusal = "0700"

// setTestMode sets the mode of path; a mode with group or other write bits
// lets other accounts write it.
func setTestMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
