//go:build unix

package credentialstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// Every key below is a synthetic canary; none is a real credential.
const (
	canaryKey   = "sk-canary-0123456789abcdefghijklmnopqrstuvwxyz"
	canaryOther = "sk-canary-ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
	testName    = "OPEN_TRESTLE_PROVIDER_STORE_TEST"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(parent, "open-trestle", "credentials"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

func assertNoSecret(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), canaryKey) || strings.Contains(err.Error(), canaryOther)) {
		t.Fatalf("an error carried the key: %v", err)
	}
}

func TestDefaultDirectoryPrefersAbsoluteXDGConfigHome(t *testing.T) {
	env := map[string]string{"XDG_CONFIG_HOME": "/config", "HOME": "/home/someone"}
	getenv := func(name string) string { return env[name] }
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/config/open-trestle/credentials" {
		t.Fatalf("XDG_CONFIG_HOME: %q %v", dir, err)
	}
	env["XDG_CONFIG_HOME"] = "relative/config"
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/home/someone/.config/open-trestle/credentials" {
		t.Fatalf("relative XDG_CONFIG_HOME must fall back to HOME: %q %v", dir, err)
	}
	env["XDG_CONFIG_HOME"], env["HOME"] = "", "relative-home"
	if _, err := DefaultDirectory(getenv); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a relative HOME was used: %v", err)
	}
}

func TestSetCreatesAnOwnerOnlyFolderAndFile(t *testing.T) {
	store := newTestStore(t)
	if _, found, err := store.Get(testName); err != nil || found {
		t.Fatalf("missing folder: found=%v err=%v", found, err)
	}
	if err := store.Set(context.Background(), testName, canaryKey); err != nil {
		t.Fatal(err)
	}
	folder, err := os.Lstat(store.Directory())
	if err != nil || !folder.IsDir() || folder.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode: %v %v", folder.Mode(), err)
	}
	file, err := os.Lstat(filepath.Join(store.Directory(), testName))
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", file.Mode(), err)
	}
	if content, err := os.ReadFile(filepath.Join(store.Directory(), testName)); err != nil || string(content) != canaryKey {
		t.Fatal("the file does not hold exactly the key")
	}
	if key, found, err := store.Get(testName); err != nil || !found || key != canaryKey {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if names, err := store.Names(); err != nil || !slices.Equal(names, []string{testName}) {
		t.Fatalf("names: %v %v", names, err)
	}
}

func TestSetReplacesAtomicallyThroughARename(t *testing.T) {
	store := newTestStore(t)
	if err := store.Set(context.Background(), testName, canaryKey); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Directory(), testName)
	before := inode(t, path)
	if err := store.Set(context.Background(), testName, canaryOther); err != nil {
		t.Fatal(err)
	}
	if inode(t, path) == before {
		t.Fatal("the key was rewritten in place instead of replaced by a rename")
	}
	if key, _, err := store.Get(testName); err != nil || key != canaryOther {
		t.Fatalf("replacement not read back: %v", err)
	}
	entries, err := os.ReadDir(store.Directory())
	if err != nil || len(entries) != 1 || entries[0].Name() != testName {
		t.Fatalf("a temporary file was left behind: %v %v", entries, err)
	}
	// A leftover temporary file from an interrupted write is never listed.
	if err := os.WriteFile(filepath.Join(store.Directory(), "."+testName+".0011223344556677.tmp"), []byte(canaryKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if names, err := store.Names(); err != nil || !slices.Equal(names, []string{testName}) {
		t.Fatalf("names listed a temporary file: %v %v", names, err)
	}
}

func TestStoreRefusesSymlinksAndBroadPermissions(t *testing.T) {
	ctx := context.Background()
	t.Run("file symlink", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Set(ctx, testName, canaryKey); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "elsewhere")
		if err := os.WriteFile(outside, []byte(canaryOther), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(store.Directory(), testName)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
		_, found, err := store.Get(testName)
		assertNoSecret(t, err)
		if found || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a symlinked key was read: found=%v err=%v", found, err)
		}
		err = store.Set(ctx, testName, canaryKey)
		assertNoSecret(t, err)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a symlinked key was replaced: %v", err)
		}
		if _, err := store.Remove(ctx, testName); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a symlinked key was removed: %v", err)
		}
		if content, _ := os.ReadFile(outside); string(content) != canaryOther {
			t.Fatal("the symlink target was changed")
		}
	})
	t.Run("folder symlink", func(t *testing.T) {
		store := newTestStore(t)
		real := filepath.Join(t.TempDir(), "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(store.Directory()), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, store.Directory()); err != nil {
			t.Fatal(err)
		}
		if err := store.Set(ctx, testName, canaryKey); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("wrote through a symlinked folder: %v", err)
		}
		if entries, _ := os.ReadDir(real); len(entries) != 0 {
			t.Fatal("a key was written into the symlink target")
		}
	})
	t.Run("broad folder", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Set(ctx, testName, canaryKey); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(store.Directory(), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, found, err := store.Get(testName); found || !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "0700") {
			t.Fatalf("a 0755 folder was used: found=%v err=%v", found, err)
		}
		if err := store.Set(ctx, testName, canaryOther); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("wrote into a 0755 folder: %v", err)
		}
	})
	t.Run("broad file", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.Set(ctx, testName, canaryKey); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(store.Directory(), testName)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		_, found, err := store.Get(testName)
		assertNoSecret(t, err)
		if found || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a 0644 key file was read: found=%v err=%v", found, err)
		}
		if err := store.Set(ctx, testName, canaryOther); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("a 0644 key file was replaced: %v", err)
		}
	})
}

func TestStoreRefusesBadNamesAndKeysWithoutEchoingThem(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	for _, name := range []string{"", "OPENAI_API_KEY", "OPEN_TRESTLE_PROVIDER_", "OPEN_TRESTLE_PROVIDER_lower", "OPEN_TRESTLE_PROVIDER_../X", canaryKey} {
		if err := store.Set(ctx, name, canaryKey); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("name %q accepted: %v", name, err)
		}
		if _, _, err := store.Get(name); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("get with name %q: %v", name, err)
		}
	}
	for _, key := range []string{"", " " + canaryKey, canaryKey + "\n", "with space", "tab\tkey", "ключ", strings.Repeat("k", MaxKeyBytes+1)} {
		err := store.Set(ctx, testName, key)
		assertNoSecret(t, err)
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("unusable key accepted: %v", err)
		}
	}
	if _, err := os.Lstat(store.Directory()); !os.IsNotExist(err) {
		t.Fatal("a refused write created the folder")
	}
}

func TestRemoveDeletesOnlyTheNamedKey(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	other := "OPEN_TRESTLE_PROVIDER_STORE_OTHER"
	if err := store.Set(ctx, testName, canaryKey); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(ctx, other, canaryOther); err != nil {
		t.Fatal(err)
	}
	if removed, err := store.Remove(ctx, testName); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if removed, err := store.Remove(ctx, testName); err != nil || removed {
		t.Fatalf("second remove: %v %v", removed, err)
	}
	if _, found, _ := store.Get(testName); found {
		t.Fatal("the removed key is still read")
	}
	if key, found, err := store.Get(other); err != nil || !found || key != canaryOther {
		t.Fatal("removing one key touched another")
	}
	if names, _ := store.Names(); !slices.Equal(names, []string{other}) {
		t.Fatalf("names after remove: %v", names)
	}
	// A file that does not hold a usable key is refused, not removed.
	path := filepath.Join(store.Directory(), testName)
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Remove(ctx, testName); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("removed a file that holds no key: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("the unrecognized file was deleted")
	}
}
