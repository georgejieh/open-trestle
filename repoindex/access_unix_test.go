//go:build unix

package repoindex

import (
	"os"
	"testing"
)

// privateTempDir returns a new directory for an index folder.
func privateTempDir(t *testing.T) string { return t.TempDir() }

// exposeToOthers lets other accounts read path.
func exposeToOthers(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}
