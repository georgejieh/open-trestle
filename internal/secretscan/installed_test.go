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
	homeVariable := "HOME"
	if runtime.GOOS == "windows" {
		homeVariable = "USERPROFILE"
	}
	config, err := installedConfig(digest, func() (string, error) { return program, nil }, func(name string) string {
		if name == homeVariable {
			return home
		}
		return ""
	})
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
	})
	if err != nil || config.CacheDirectory != filepath.Join(cache, "open-trestle", "scan-cache") {
		t.Fatalf("config = %+v, %v", config, err)
	}
}

func TestInstalledConfigRefusals(t *testing.T) {
	program := func() (string, error) { return os.Executable() }
	home := func(string) string { return t.TempDir() }
	if _, err := installedConfig("", program, home); !errors.Is(err, ErrHelperNotPinned) {
		t.Fatalf("unpinned build: %v", err)
	}
	if _, err := installedConfig(strings.Repeat("A", 64), program, home); !errors.Is(err, ErrHelperNotPinned) {
		t.Fatalf("malformed pin: %v", err)
	}
	if _, err := installedConfig(strings.Repeat("a", 64), func() (string, error) { return "", errors.New("unknown") }, home); !errors.Is(err, ErrHelperNotInstalled) {
		t.Fatalf("unknown program: %v", err)
	}
	for name, getenv := range map[string]func(string) string{"relative": func(string) string { return "relative" }, "unset": func(string) string { return "" }} {
		if _, err := installedConfig(strings.Repeat("a", 64), program, getenv); !errors.Is(err, ErrCacheUnavailable) {
			t.Fatalf("%s home: %v", name, err)
		}
	}
}

func TestCheckInstalledNeedsNoHomeFolder(t *testing.T) {
	program := func() (string, error) { return filepath.Join(t.TempDir(), "bin", "trestle"), nil }
	if err := checkInstalled(strings.Repeat("a", 64), program); !errors.Is(err, ErrHelperNotInstalled) {
		t.Fatalf("a missing helper without a home folder: %v", err)
	}
}

func TestCheckInstalledRefusesAnUnpinnedBuild(t *testing.T) {
	if err := CheckInstalled(); !errors.Is(err, ErrHelperNotPinned) {
		t.Fatalf("CheckInstalled = %v, want %v", err, ErrHelperNotPinned)
	}
}
