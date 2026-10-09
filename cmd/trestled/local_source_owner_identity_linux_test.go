//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLocalSourceDirectoryIdentityOpenedLinuxInode(t *testing.T) {
	path, root, _ := ownerReadFixture(t)
	info, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	got, err := localSourceDirectoryIdentityFromInfo(info)
	stat := info.Sys().(*syscall.Stat_t)
	if err != nil || got.Device != uint64(stat.Dev) || got.Inode != uint64(stat.Ino) || got.Device == 0 || got.Inode == 0 {
		t.Fatalf("opened identity: %+v, %v", got, err)
	}
	if observed, err := observeLocalSourceDirectory(path, root); err != nil || observed != got {
		t.Fatalf("path/opened: %+v, %v", observed, err)
	}
	moved := path + "-moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := observeLocalSourceDirectory(path, root); !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("replacement: %v", err)
	}
	file := filepath.Join(path, "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localSourceDirectoryIdentityFromInfo(fi); !errors.Is(err, errLocalSourceOwnerUnsupported) {
		t.Fatalf("file identity: %v", err)
	}
}

type ownerInfoWithoutStat struct{ os.FileInfo }

func (ownerInfoWithoutStat) Sys() any { return nil }

type ownerInfoZeroStat struct{ os.FileInfo }

func (ownerInfoZeroStat) Sys() any { return &syscall.Stat_t{} }

func TestLocalSourceDirectoryIdentityUnsupportedAndArtifactSplit(t *testing.T) {
	path, root, _ := ownerReadFixture(t)
	info, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, fake := range []os.FileInfo{ownerInfoWithoutStat{info}, ownerInfoZeroStat{info}} {
		if _, err := localSourceDirectoryIdentityFromInfo(fake); !errors.Is(err, errLocalSourceOwnerUnsupported) {
			t.Fatalf("stat metadata: %v", err)
		}
	}
	child := filepath.Join(path, "artifacts")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.OpenRoot(child)
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	identity, err := observeLocalSourceArtifactDirectory(root, artifact, path)
	if err != nil || identity.Device == 0 || identity.Inode == 0 {
		t.Fatalf("child: %+v %v", identity, err)
	}
	moved := child + "-moved"
	if err := os.Rename(child, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := observeLocalSourceArtifactDirectory(root, artifact, path); !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("child replacement: %v", err)
	}
}

func TestLocalSourceArtifactChangesBetweenChildObservations(t *testing.T) {
	path, root, _ := ownerReadFixture(t)
	child := filepath.Join(path, "artifacts")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	artifact, err := os.OpenRoot(child)
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	_, err = observeLocalSourceArtifactDirectoryWithHook(root, artifact, path, func(stage string) {
		if stage != "after-child-before" {
			return
		}
		if e := os.Rename(child, child+"-original"); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(child, 0700); e != nil {
			t.Fatal(e)
		}
	})
	if !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("artifact child replaced mid-observation: %v", err)
	}
}
