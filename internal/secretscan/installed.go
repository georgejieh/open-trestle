package secretscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// expectedHelperSHA256 is the SHA-256 of the scan helper built from the same
// source and for the same system as this program. The packaging tool sets it
// at link time; a plain go build leaves it empty, and such a build sends
// nothing to a model.
var expectedHelperSHA256 string

// helperName is the helper's file name. It lives in libexec/open-trestle
// next to the folder that holds the running program.
const helperName = "open-trestle-scan-helper"

// Installation refusals. They carry no path or content.
var (
	ErrHelperNotPinned            = errors.New("this build pins no secret scan helper; build trestle with its helper by python3 tools/package_secret_scanner.py --development DIR")
	ErrHelperNotInstalled         = errors.New("the secret scan helper is missing from libexec/open-trestle next to this program's folder, or does not match the SHA-256 this program pins")
	ErrCacheUnavailable           = errors.New("the secret scan cache folder cannot be found; set XDG_CACHE_HOME, or HOME (USERPROFILE on Windows)")
	ErrScannerUnsupportedPlatform = errors.New("the secret scan helper does not run on this system")
)

// InstalledConfig returns the session configuration of this program: the
// helper at ../libexec/open-trestle/open-trestle-scan-helper (.exe on
// Windows) from the folder of the running executable, the SHA-256 this build
// pins, and the current user's cache folder,
// $XDG_CACHE_HOME/open-trestle/scan-cache when XDG_CACHE_HOME is absolute,
// otherwise ~/.cache/open-trestle/scan-cache, with the home folder from HOME
// (USERPROFILE on Windows). getenv reads the environment.
func InstalledConfig(getenv func(string) string) (SessionConfig, error) {
	return installedConfig(expectedHelperSHA256, os.Executable, getenv)
}

func installedConfig(digest string, executable func() (string, error), getenv func(string) string) (SessionConfig, error) {
	helper, err := installedHelperPath(digest, executable)
	if err != nil {
		return SessionConfig{}, err
	}
	cache, err := cacheDirectory(getenv)
	if err != nil {
		return SessionConfig{}, err
	}
	return SessionConfig{HelperPath: helper, HelperSHA256: digest, CacheDirectory: cache}, nil
}

// installedHelperPath is the helper path for the running program, once the
// build is known to pin a helper.
func installedHelperPath(digest string, executable func() (string, error)) (string, error) {
	if !validDigest(digest) {
		return "", ErrHelperNotPinned
	}
	program, err := executable()
	if err == nil {
		program, err = filepath.EvalSymlinks(program)
	}
	if err != nil || !filepath.IsAbs(program) {
		return "", ErrHelperNotInstalled
	}
	name := helperName
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(filepath.Dir(program)), "libexec", "open-trestle", name), nil
}

func cacheDirectory(getenv func(string) string) (string, error) {
	if cache := getenv("XDG_CACHE_HOME"); cache != "" && filepath.IsAbs(cache) {
		return filepath.Join(filepath.Clean(cache), "open-trestle", "scan-cache"), nil
	}
	home := "HOME"
	if runtime.GOOS == "windows" {
		home = "USERPROFILE"
	}
	directory := getenv(home)
	if directory == "" || !filepath.IsAbs(directory) {
		return "", ErrCacheUnavailable
	}
	return filepath.Join(filepath.Clean(directory), ".cache", "open-trestle", "scan-cache"), nil
}

// CheckInstalled verifies, without running it, that this build pins a helper
// and that the installed helper is a trusted file with that SHA-256. It does
// not look at the cache.
func CheckInstalled() error {
	return checkInstalled(expectedHelperSHA256, os.Executable)
}

func checkInstalled(digest string, executable func() (string, error)) error {
	helper, err := installedHelperPath(digest, executable)
	if err != nil {
		return err
	}
	return checkHelper(helper, digest)
}

func checkHelper(path, digest string) error {
	helper, err := openVerifiedHelper(path, digest)
	if errors.Is(err, ErrScannerUnsupportedPlatform) {
		return err
	}
	if err != nil {
		return ErrHelperNotInstalled
	}
	helper.close()
	return nil
}

// PrepareCache fills the cache of config once per helper. Unless an earlier
// call recorded success for config.HelperSHA256 in the cache, it calls
// announce, creates the missing folders above the cache with mode 0700, runs
// Prewarm and records the success. A review calls it before its session, so
// that the session starts within its start allowance.
func PrepareCache(ctx context.Context, config SessionConfig, announce func()) error {
	if !validDigest(config.HelperSHA256) || !validAbsolutePath(config.CacheDirectory) || filepath.Dir(config.CacheDirectory) == config.CacheDirectory {
		return ErrSessionConfig
	}
	marker := filepath.Join(config.CacheDirectory, "prepared-"+config.HelperSHA256)
	if info, err := os.Lstat(marker); err == nil && info.Mode().IsRegular() {
		return nil
	}
	if announce != nil {
		announce()
	}
	if err := os.MkdirAll(filepath.Dir(config.CacheDirectory), 0o700); err != nil {
		return ErrCacheUntrusted
	}
	if err := Prewarm(ctx, config); err != nil {
		return err
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		return ErrCacheUntrusted
	}
	return nil
}
