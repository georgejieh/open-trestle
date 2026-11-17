package fileauthority_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

func directoryPinFixture(t *testing.T) (string, string, string) {
	t.Helper()
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	leaf := filepath.Join(parent, "leaf")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	return base, parent, leaf
}

func requireUntrustedPin(t *testing.T, pin *fileauthority.DirectoryPin, err error) {
	t.Helper()
	if pin != nil || !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("want nil pin and ErrUntrustedPath; got pin=%v err=%v", pin, err)
	}
}

func TestDirectoryPinUnchangedChain(t *testing.T) {
	_, _, leaf := directoryPinFixture(t)
	pin, err := fileauthority.PinDirectory(leaf)
	if err != nil || pin == nil {
		t.Fatalf("pin unchanged private directory: %v", err)
	}
	if err := pin.Recheck(); err != nil {
		t.Fatalf("recheck unchanged chain: %v", err)
	}
}

func TestDirectoryPinInvalidInput(t *testing.T) {
	pin, err := fileauthority.PinDirectory("")
	requireUntrustedPin(t, pin, err)
	var missing *fileauthority.DirectoryPin
	if err := missing.Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("nil pin: %v", err)
	}
	if err := (&fileauthority.DirectoryPin{}).Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("zero pin: %v", err)
	}
}

func TestDirectoryPinRejectsLinkedParentAndLeaf(t *testing.T) {
	base, parent, leaf := directoryPinFixture(t)
	linkedLeaf := filepath.Join(parent, "linked-leaf")
	if err := os.Symlink(leaf, linkedLeaf); err != nil {
		t.Fatal(err)
	}
	pin, err := fileauthority.PinDirectory(linkedLeaf)
	requireUntrustedPin(t, pin, err)
	linkedParent := filepath.Join(base, "linked-parent")
	if err := os.Symlink(parent, linkedParent); err != nil {
		t.Fatal(err)
	}
	pin, err = fileauthority.PinDirectory(filepath.Join(linkedParent, "leaf"))
	requireUntrustedPin(t, pin, err)

	stable, err := fileauthority.PinDirectory(leaf)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "moved-parent")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, parent); err != nil {
		t.Fatal(err)
	}
	if err := stable.Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("linked parent after pin: %v", err)
	}
}

func TestDirectoryPinRejectsSurvivingParentReplacementWithSameLeaf(t *testing.T) {
	base, parent, leaf := directoryPinFixture(t)
	before, err := os.Lstat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "original-parent")
	pin, err := fileauthority.PinDirectory(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(moved, "leaf"), leaf); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("fixture did not retain the original leaf inode")
	}
	if err := fileauthority.CheckDirectory(leaf); err != nil {
		t.Fatalf("new trusted chain should pass a fresh check: %v", err)
	}
	if err := pin.Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("original parent pin lost: %v", err)
	}
}

func TestDirectoryPinRejectsModeAndLeafReplacement(t *testing.T) {
	t.Run("mode", func(t *testing.T) {
		_, parent, leaf := directoryPinFixture(t)
		pin, err := fileauthority.PinDirectory(leaf)
		if err != nil {
			t.Fatal(err)
		}
		changeAccess(t, parent)
		if err := pin.Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
			t.Fatalf("changed parent mode: %v", err)
		}
	})
	t.Run("leaf mode", func(t *testing.T) {
		_, _, leaf := directoryPinFixture(t)
		pin, err := fileauthority.PinDirectory(leaf)
		if err != nil {
			t.Fatal(err)
		}
		changeAccess(t, leaf)
		if err := pin.Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
			t.Fatalf("changed leaf mode: %v", err)
		}
	})
	t.Run("leaf", func(t *testing.T) {
		_, _, leaf := directoryPinFixture(t)
		pin, err := fileauthority.PinDirectory(leaf)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(leaf, leaf+"-original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(leaf, 0700); err != nil {
			t.Fatal(err)
		}
		if err := pin.Recheck(); !errors.Is(err, fileauthority.ErrUntrustedPath) {
			t.Fatalf("replaced leaf: %v", err)
		}
	})
}
