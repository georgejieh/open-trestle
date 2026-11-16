//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

type foreignOwnerDirectoryInfo struct{ os.FileInfo }

func (i foreignOwnerDirectoryInfo) Sys() any {
	return &syscall.Stat_t{Uid: uint32(os.Geteuid()) + 1}
}

func TestLocalOwnerRootOldCodePathAndObservationErrors(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	state := filepath.Join(parent, "state")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := localExistingRoot(state)
	if err != nil || root == nil {
		t.Fatalf("existing root=%v err=%v", root, err)
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	if !ownerDirectoryInfo(opened) || !fileauthority.TrustedOwner(opened) {
		t.Fatal("real private owned root rejected")
	}
	if ownerDirectoryInfo(foreignOwnerDirectoryInfo{opened}) || ownerDirectoryInfo(nil) {
		t.Fatal("foreign or missing owner metadata accepted")
	}
	observed, err := observeLocalSourceDirectory(state, root)
	if err != nil {
		t.Fatal(err)
	}
	stat := opened.Sys().(*syscall.Stat_t)
	if observed.Device != uint64(stat.Dev) || observed.Inode != uint64(stat.Ino) || observed.Device == 0 || observed.Inode == 0 {
		t.Fatalf("opened directory identity=%+v stat=%+v", observed, stat)
	}
	checked, err := checkedLocalSourceDirectoryInfo(state)
	if err != nil || !os.SameFile(checked, opened) {
		t.Fatalf("checked root info=%v err=%v", checked, err)
	}
	closer, err := localPathPreflight(state)
	if err != nil || closer == nil {
		t.Fatalf("existing preflight closerPresent=%v err=%v", closer != nil, err)
	}
	closer()

	missing := filepath.Join(state, "missing", "nested")
	absent, err := localExistingRoot(missing)
	if err != nil || absent != nil {
		t.Fatalf("missing suffix root=%v err=%v", absent, err)
	}
	closer, err = localPathPreflight(missing)
	if err != nil || closer == nil {
		t.Fatalf("missing suffix preflight closerPresent=%v err=%v", closer != nil, err)
	}
	closer()
	if info, err := checkedLocalSourceDirectoryInfo(missing); info != nil || err != os.ErrNotExist {
		t.Fatalf("missing checked info=%v err=%v", info, err)
	}
	_, err = observeLocalSourceDirectory(missing, root)
	requireOldRootError(t, err, "directory chain before", true, true, false)

	linked := filepath.Join(base, "linked")
	if err := os.Symlink(parent, linked); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(linked, "state"), filepath.Join(state, "linked-leaf")} {
		if path == filepath.Join(state, "linked-leaf") {
			if err := os.Symlink(state, path); err != nil {
				t.Fatal(err)
			}
		}
		refused, walkErr := localExistingRoot(path)
		if refused != nil || walkErr != ErrInvalidDaemonConfiguration {
			t.Fatalf("linked path=%q root=%v err=%v", path, refused, walkErr)
		}
		closer, preflightErr := localPathPreflight(path)
		if closer != nil || preflightErr != ErrInvalidDaemonConfiguration {
			t.Fatalf("linked preflight closerPresent=%v err=%v", closer != nil, preflightErr)
		}
	}
	_, err = observeLocalSourceDirectory(filepath.Join(linked, "state"), root)
	requireOldRootError(t, err, "directory chain before", true, false, true)

	if err := os.Chmod(state, 0o755); err != nil {
		t.Fatal(err)
	}
	refused, walkErr := localExistingRoot(state)
	if refused != nil || walkErr != ErrInvalidDaemonConfiguration {
		t.Fatalf("public leaf root=%v err=%v", refused, walkErr)
	}
	closer, preflightErr := localPathPreflight(state)
	if closer != nil || preflightErr != ErrInvalidDaemonConfiguration {
		t.Fatalf("public preflight closerPresent=%v err=%v", closer != nil, preflightErr)
	}
	_, err = observeLocalSourceDirectory(state, root)
	requireOldRootError(t, err, "directory chain before", true, false, true)
}

func TestLocalOwnerRootOldCodeAbsentAndClosedRootErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := observeLocalSourceDirectory(path, nil)
	requireOldRootError(t, err, "absent or invalid opened root", true, false, false)
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = observeLocalSourceDirectory(path, root)
	requireOldRootError(t, err, "opened directory", true, false, false)
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed root lost os.ErrClosed: %v", err)
	}
	if _, err := observeLocalSourceArtifactDirectory(nil, root, path); err == nil || err.Error() != "local source owner persistence or changed state: absent artifact root" || !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("absent artifact root: %v", err)
	}
}

func requireOldRootError(t *testing.T, err error, stage string, persistence, absent, daemon bool) {
	t.Helper()
	want := "local source owner persistence or changed state: " + stage
	if err == nil || !strings.HasPrefix(err.Error(), want) || errors.Is(err, errLocalSourceOwnerPersistence) != persistence || errors.Is(err, os.ErrNotExist) != absent || errors.Is(err, ErrInvalidDaemonConfiguration) != daemon {
		t.Fatalf("stage=%q err=%v persistence=%v absent=%v daemon=%v", stage, err, persistence, absent, daemon)
	}
}
