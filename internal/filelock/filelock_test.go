package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLockIsExclusiveAndReclaimableAfterClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Acquire(path); !errors.Is(err, ErrLocked) || second != nil {
		t.Fatalf("second=(%#v,%v)", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reclaimed.Close()
	information, err := os.Lstat(path)
	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 {
		t.Fatalf("lock=(%v,%v)", information, err)
	}
}
func TestAcquireRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	_ = os.WriteFile(target, nil, 0o600)
	link := filepath.Join(root, "link")
	_ = os.Symlink(target, link)
	if lock, err := Acquire(link); !errors.Is(err, ErrInvalidPath) || lock != nil {
		t.Fatalf("lock=(%#v,%v)", lock, err)
	}
}

func TestAcquireReclaimsPersistentUnlockedLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
}
