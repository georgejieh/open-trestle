package checksandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestSweepStaleRemovesOnlyOldLeftovers(t *testing.T) {
	temporary := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("TMP", temporary)
	} else {
		t.Setenv("TMPDIR", temporary)
	}
	old := time.Now().Add(-2 * staleAge)
	folders := map[string]bool{
		scratchFolderPrefix + "old": false,
		TreesFolderPrefix + "old":   false,
		GoSeedFolderPrefix + "old":  false,
		scratchFolderPrefix + "new": true,
		"unrelated-old":             true,
	}
	for name, kept := range folders {
		path := filepath.Join(temporary, name, "inside")
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if !kept || name == "unrelated-old" {
			if err := os.Chtimes(filepath.Dir(path), old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	SweepStale()
	for name, kept := range folders {
		if _, err := os.Stat(filepath.Join(temporary, name)); (err == nil) != kept {
			t.Errorf("%s: kept %v, want %v", name, err == nil, kept)
		}
	}
}
