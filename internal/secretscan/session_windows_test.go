//go:build windows

package secretscan

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

func TestOpenCacheDirectoryOnWindows(t *testing.T) {
	t.Run("created owner-only", func(t *testing.T) {
		parent := ownersonlytest.TempDir(t)
		ownersonlytest.Grant(t, parent, ownersonlytest.Users+":(OI)(CI)(RX)")
		cache := filepath.Join(parent, "cache")
		if _, err := openCacheDirectory(cache, false); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("a missing cache was accepted without create: %v", err)
		}
		directory, err := openCacheDirectory(cache, true)
		if err != nil || directory != cache {
			t.Fatalf("openCacheDirectory = %q, %v", directory, err)
		}
		ownersonlytest.RequireOwnerOnly(t, cache)
		if directory, err := openCacheDirectory(cache, false); err != nil || directory != cache {
			t.Fatalf("the created cache was refused: %q, %v", directory, err)
		}
	})
	t.Run("cache others can read", func(t *testing.T) {
		cache := filepath.Join(ownersonlytest.TempDir(t), "cache")
		if err := ownersonly.Mkdir(cache); err != nil {
			t.Fatal(err)
		}
		ownersonlytest.Grant(t, cache, ownersonlytest.Users+":(RX)")
		for _, create := range []bool{false, true} {
			if _, err := openCacheDirectory(cache, create); !errors.Is(err, ErrCacheUntrusted) {
				t.Fatalf("create=%v: a cache others can read was accepted: %v", create, err)
			}
		}
	})
	t.Run("cache that inherits", func(t *testing.T) {
		parent := ownersonlytest.TempDir(t)
		ownersonlytest.Grant(t, parent, ownersonlytest.Users+":(OI)(CI)(RX)")
		cache := filepath.Join(parent, "cache")
		if err := os.Mkdir(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := openCacheDirectory(cache, true); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("an existing cache that inherits read access was accepted: %v", err)
		}
	})
	t.Run("parent others can change", func(t *testing.T) {
		parent := ownersonlytest.TempDir(t)
		ownersonlytest.Grant(t, parent, ownersonlytest.Everyone+":(M)")
		cache := filepath.Join(parent, "cache")
		if _, err := openCacheDirectory(cache, true); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("a cache below a folder others can change was accepted: %v", err)
		}
		if _, err := os.Lstat(cache); !os.IsNotExist(err) {
			t.Fatal("a refused open created the cache")
		}
	})
	t.Run("parent others can add to", func(t *testing.T) {
		parent := ownersonlytest.TempDir(t)
		ownersonlytest.Grant(t, parent, ownersonlytest.AuthenticatedUsers+":(AD,WD)")
		if _, err := openCacheDirectory(filepath.Join(parent, "cache"), true); err != nil {
			t.Fatalf("a cache below a folder others can only add to was refused: %v", err)
		}
	})
	t.Run("junction above", func(t *testing.T) {
		base := ownersonlytest.TempDir(t)
		target := filepath.Join(base, "target")
		if err := ownersonly.Mkdir(target); err != nil {
			t.Fatal(err)
		}
		junction := filepath.Join(base, "junction")
		ownersonlytest.Junction(t, junction, target)
		if _, err := openCacheDirectory(filepath.Join(junction, "cache"), true); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("a cache below a junction was accepted: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(target, "cache")); !os.IsNotExist(err) {
			t.Fatal("a refused open created the cache through the junction")
		}
	})
	t.Run("cache others would inherit access to", func(t *testing.T) {
		cache := filepath.Join(ownersonlytest.TempDir(t), "cache")
		if err := ownersonly.Mkdir(cache); err != nil {
			t.Fatal(err)
		}
		ownersonlytest.Grant(t, cache, ownersonlytest.Everyone+":(OI)(CI)(IO)(F)")
		if _, err := openCacheDirectory(cache, false); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("a cache that hands its entries to Everyone was accepted: %v", err)
		}
	})
	t.Run("entry inside others can write", func(t *testing.T) {
		cache := filepath.Join(ownersonlytest.TempDir(t), "cache")
		if _, err := openCacheDirectory(cache, true); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(cache, "wazero"), 0o700); err != nil {
			t.Fatal(err)
		}
		entry := filepath.Join(cache, "wazero", "module")
		if err := os.WriteFile(entry, []byte("native code"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openCacheDirectory(cache, false); err != nil {
			t.Fatalf("a cache with owner-only entries was refused: %v", err)
		}
		ownersonlytest.Grant(t, entry, ownersonlytest.Everyone+":(M)")
		if _, err := openCacheDirectory(cache, false); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("a cache entry others can write was accepted: %v", err)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		for _, path := range []string{"", "relative", `C:\`} {
			if _, err := openCacheDirectory(path, true); !errors.Is(err, ErrSessionConfig) {
				t.Fatalf("%q: %v", path, err)
			}
		}
	})
}
