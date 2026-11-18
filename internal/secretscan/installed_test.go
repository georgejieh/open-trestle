package secretscan

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInstalledConfigFindsTheHelperBesideTheProgramFolder(t *testing.T) {
	root := t.TempDir()
	program := filepath.Join(root, "bin", "trestle")
	if err := os.MkdirAll(filepath.Dir(program), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	home := filepath.Join(resolved, "home")
	config, err := installedConfig(digest, func() (string, error) { return program, nil }, func(string) string { return "" }, func() (string, error) { return home, nil })
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(resolved, "libexec", "open-trestle", "open-trestle-scan-helper")
	if runtime.GOOS == "windows" {
		helper += ".exe"
	}
	if config.HelperPath != helper || config.HelperSHA256 != digest || config.CacheDirectory != filepath.Join(home, ".cache", "open-trestle", "scan-cache") {
		t.Fatalf("config = %+v", config)
	}
	cache := filepath.Join(resolved, "xdg")
	config, err = installedConfig(digest, func() (string, error) { return program, nil }, func(name string) string {
		if name == "XDG_CACHE_HOME" {
			return cache
		}
		return ""
	}, func() (string, error) { return "", errors.New("no home") })
	if err != nil || config.CacheDirectory != filepath.Join(cache, "open-trestle", "scan-cache") {
		t.Fatalf("config = %+v, %v", config, err)
	}
}

func TestInstalledConfigRefusals(t *testing.T) {
	program := func() (string, error) { return os.Executable() }
	none := func(string) string { return "" }
	home := func() (string, error) { return t.TempDir(), nil }
	if _, err := installedConfig("", program, none, home); !errors.Is(err, ErrHelperNotPinned) {
		t.Fatalf("unpinned build: %v", err)
	}
	if _, err := installedConfig(strings.Repeat("A", 64), program, none, home); !errors.Is(err, ErrHelperNotPinned) {
		t.Fatalf("malformed pin: %v", err)
	}
	if _, err := installedConfig(strings.Repeat("a", 64), func() (string, error) { return "", errors.New("unknown") }, none, home); !errors.Is(err, ErrHelperNotInstalled) {
		t.Fatalf("unknown program: %v", err)
	}
	relative := func(string) string { return "relative" }
	if _, err := installedConfig(strings.Repeat("a", 64), program, relative, func() (string, error) { return "relative", nil }); !errors.Is(err, ErrCacheUnavailable) {
		t.Fatalf("relative cache: %v", err)
	}
}

func TestCheckInstalledRefusesAnUnpinnedBuild(t *testing.T) {
	if err := CheckInstalled(); !errors.Is(err, ErrHelperNotPinned) {
		t.Fatalf("CheckInstalled = %v, want %v", err, ErrHelperNotPinned)
	}
}
