//go:build windows

package credentialstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

// Every key below is a synthetic canary; none is a real credential.
const (
	windowsCanaryKey   = "sk-canary-0123456789abcdefghijklmnopqrstuvwxyz"
	windowsCanaryOther = "sk-canary-ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
	windowsTestName    = "OPEN_TRESTLE_PROVIDER_STORE_TEST"
)

func newWindowsStore(t *testing.T) (*Store, string) {
	t.Helper()
	parent := ownersonlytest.TempDir(t)
	// Files created in the parent without a descriptor of their own would
	// inherit read access for Users.
	ownersonlytest.Grant(t, parent, ownersonlytest.Users+":(OI)(CI)(RX)")
	store, err := NewStore(filepath.Join(parent, "open-trestle", "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	return store, parent
}

func TestWindowsSetCreatesAnOwnerOnlyFolderAndFile(t *testing.T) {
	store, parent := newWindowsStore(t)
	ctx := context.Background()
	if err := store.Set(ctx, windowsTestName, windowsCanaryKey); err != nil {
		t.Fatal(err)
	}
	ownersonlytest.RequireOwnerOnly(t, filepath.Join(parent, "open-trestle"))
	ownersonlytest.RequireOwnerOnly(t, store.Directory())
	ownersonlytest.RequireOwnerOnly(t, filepath.Join(store.Directory(), windowsTestName))
	if key, found, err := store.Get(windowsTestName); err != nil || !found || key != windowsCanaryKey {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if err := store.Set(ctx, windowsTestName, windowsCanaryOther); err != nil {
		t.Fatal(err)
	}
	if key, _, err := store.Get(windowsTestName); err != nil || key != windowsCanaryOther {
		t.Fatalf("replacement not read back: %v", err)
	}
	ownersonlytest.RequireOwnerOnly(t, filepath.Join(store.Directory(), windowsTestName))
	if names, err := store.Names(); err != nil || !slices.Equal(names, []string{windowsTestName}) {
		t.Fatalf("names: %v %v", names, err)
	}
	if removed, err := store.Remove(ctx, windowsTestName); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if entries, err := os.ReadDir(store.Directory()); err != nil || len(entries) != 0 {
		t.Fatalf("folder after remove: %v %v", entries, err)
	}
}

func TestWindowsStoreRefusesBroadAccess(t *testing.T) {
	ctx := context.Background()
	t.Run("folder others can read", func(t *testing.T) {
		store, _ := newWindowsStore(t)
		if err := store.Set(ctx, windowsTestName, windowsCanaryKey); err != nil {
			t.Fatal(err)
		}
		ownersonlytest.Grant(t, store.Directory(), ownersonlytest.Users+":(RX)")
		if _, found, err := store.Get(windowsTestName); found || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a folder others can read was used: found=%v err=%v", found, err)
		}
		if err := store.Set(ctx, windowsTestName, windowsCanaryOther); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("wrote into a folder others can read: %v", err)
		}
	})
	t.Run("existing folder that inherits", func(t *testing.T) {
		store, _ := newWindowsStore(t)
		if err := os.MkdirAll(store.Directory(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(ctx, windowsTestName, windowsCanaryKey); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("wrote into an existing folder that grants Users read access: %v", err)
		}
	})
	t.Run("file others can read", func(t *testing.T) {
		store, _ := newWindowsStore(t)
		if err := store.Set(ctx, windowsTestName, windowsCanaryKey); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(store.Directory(), windowsTestName)
		ownersonlytest.Grant(t, path, ownersonlytest.Users+":(R)")
		if _, found, err := store.Get(windowsTestName); found || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a key file others can read was read: found=%v err=%v", found, err)
		}
		if err := store.Set(ctx, windowsTestName, windowsCanaryOther); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a key file others can read was replaced: %v", err)
		}
		if _, err := store.Remove(ctx, windowsTestName); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a key file others can read was removed: %v", err)
		}
	})
	t.Run("parent others can write", func(t *testing.T) {
		store, parent := newWindowsStore(t)
		if err := store.Set(ctx, windowsTestName, windowsCanaryKey); err != nil {
			t.Fatal(err)
		}
		ownersonlytest.Grant(t, parent, ownersonlytest.Everyone+":(M)")
		if _, found, err := store.Get(windowsTestName); found || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a key below a folder others can write was read: found=%v err=%v", found, err)
		}
	})
	t.Run("junction folder", func(t *testing.T) {
		store, parent := newWindowsStore(t)
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(store.Directory()), 0o700); err != nil {
			t.Fatal(err)
		}
		ownersonlytest.Junction(t, store.Directory(), real)
		if err := store.Set(ctx, windowsTestName, windowsCanaryKey); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("wrote through a junction: %v", err)
		}
		if entries, _ := os.ReadDir(real); len(entries) != 0 {
			t.Fatal("a key was written into the junction target")
		}
	})
}
