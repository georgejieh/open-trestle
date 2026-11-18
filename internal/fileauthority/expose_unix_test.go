//go:build unix

package fileauthority_test

import (
	"os"
	"testing"
)

// changeAccess changes the permission bits of path away from the 0700 the
// fixtures create it with.
func changeAccess(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
}
