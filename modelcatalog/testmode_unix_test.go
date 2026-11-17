//go:build unix

package modelcatalog

import (
	"os"
	"testing"
)

// setTestMode sets the permission bits of path to mode.
func setTestMode(_ testing.TB, path string, mode os.FileMode) error { return os.Chmod(path, mode) }
