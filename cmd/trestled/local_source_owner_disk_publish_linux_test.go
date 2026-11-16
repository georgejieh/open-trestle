//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// After the write handle is closed, publish must still hold the temporary inode
// open. Otherwise a filesystem that reuses inode numbers (ext4) can give a
// recreated temporary name the same identity, and cleanup would remove a file
// the publisher did not create.
func TestLocalSourceOwnerDiskPublishHoldsTheTemporaryAfterClose(t *testing.T) {
	path, stateRoot, _ := ownerReadFixture(t)
	held := map[string]bool{}
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, _ *os.Root, temp string, _ *os.File) error {
		if stage == "temp-recheck" || stage == "link" {
			held[stage] = processHoldsPath(t, filepath.Join(path, temp))
		}
		return nil
	}}
	if err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook); err != nil {
		t.Fatalf("publish: %v", err)
	}
	for _, stage := range []string{"temp-recheck", "link"} {
		if !held[stage] {
			t.Fatalf("no open descriptor holds the temporary at %s", stage)
		}
	}
}

func processHoldsPath(t *testing.T, want string) bool {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == want {
			return true
		}
	}
	return false
}
