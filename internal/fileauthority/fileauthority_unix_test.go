//go:build unix

package fileauthority

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type ownedInfo struct {
	os.FileInfo
	owner uint32
}

func (i ownedInfo) Sys() any { return &syscall.Stat_t{Uid: i.owner} }

func TestTrustedOwnerRejectsForeignOwner(t *testing.T) {
	foreign := uint32(os.Geteuid()) + 1
	if TrustedOwner(ownedInfo{owner: foreign}) || TrustedOwner(nil) {
		t.Fatal("foreign or missing ownership accepted")
	}
	if !TrustedOwner(ownedInfo{owner: 0}) || !TrustedOwner(ownedInfo{owner: uint32(os.Geteuid())}) {
		t.Fatal("trusted ownership rejected")
	}
}

func TestProtectedFileRejectsUnsafeAncestryAndSymlinks(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "shared")
	directory := filepath.Join(parent, "private")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "policy.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenReadOnly(path); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("replaceable ancestor accepted")
	}
	if err := CheckDirectory(directory); err == nil {
		t.Fatal("replaceable directory accepted")
	}
	if err := os.Chmod(parent, 0777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	file, err = OpenReadOnly(path)
	if err != nil {
		t.Fatalf("protected sticky parent rejected: %v", err)
	}
	file.Close()
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenReadOnly(link); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0622); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenReadOnly(path); err == nil || file != nil {
		if file != nil {
			file.Close()
		}
		t.Fatal("writable policy accepted")
	}
}
