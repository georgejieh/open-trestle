package checksandbox

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRemoveScratchUnlocksWithoutFollowingLinks(t *testing.T) {
	scratch, outside := t.TempDir(), t.TempDir()
	locked := filepath.Join(scratch, "work", "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"big", "immutable"} {
		if err := os.WriteFile(filepath.Join(locked, name), []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Chflags(filepath.Join(locked, "immutable"), unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(scratch, "work", "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(outside, 0o700)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if err := removeScratch(scratch); err != nil {
		t.Fatalf("the scratch was not removed: %v", err)
	}
	if info, err := os.Stat(outside); err != nil || info.Mode().Perm() != 0o500 {
		t.Fatalf("the folder behind the link changed: %v %v", info.Mode(), err)
	}
}
