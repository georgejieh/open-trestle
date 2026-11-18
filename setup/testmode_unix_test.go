//go:build unix

package setup

import (
	"os"
	"testing"
)

// setTestMode sets the permission bits of path to mode.
func setTestMode(_ testing.TB, path string, mode os.FileMode) error { return os.Chmod(path, mode) }

// hasTestMode reports whether info, which describes path, has permission
// bits mode.
func hasTestMode(_ testing.TB, _ string, info os.FileInfo, mode os.FileMode) bool {
	return info.Mode().Perm() == mode
}
