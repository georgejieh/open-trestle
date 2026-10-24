package filelock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireExistingDoesNotCreateMissingLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.lock")
	if lock, err := AcquireExisting(path); err == nil || lock != nil {
		t.Fatalf("missing lock accepted: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reader created lock: %v", err)
	}
}
func TestAcquireExistingPreservesBytesAndModeAndExcludesWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	if err := os.WriteFile(path, []byte("preserved lock bytes"), 0o400); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "preserved lock bytes" {
		t.Fatal("reader changed bytes")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatal("reader changed permissions")
	}
	if other, err := AcquireExisting(path); !errors.Is(err, ErrLocked) || other != nil {
		t.Fatalf("reader did not exclude active reader: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestAcquireExistingRefusesActiveWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	writer, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if reader, err := AcquireExisting(path); !errors.Is(err, ErrLocked) || reader != nil {
		t.Fatalf("active writer not fenced: %v", err)
	}
}

func TestAcquireExistingTracksLockedInodeNotReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	before, err := os.Lstat(path)
	if err != nil || !lock.SameFile(before) {
		t.Fatal("original lock mismatch")
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if lock.SameFile(after) {
		t.Fatal("orphan flock accepted replacement inode")
	}
}
