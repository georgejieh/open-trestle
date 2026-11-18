//go:build unix

package filelock

import (
	"os"
	"testing"
)

// readOnlyMode is the mode of a file written with mode 0400.
const readOnlyMode os.FileMode = 0o400

// privateLockFile reports whether path has no group or other permission
// bit.
func privateLockFile(t *testing.T, path string) bool {
	t.Helper()
	info, err := os.Lstat(path)
	return err == nil && info.Mode().Perm()&0o077 == 0
}
