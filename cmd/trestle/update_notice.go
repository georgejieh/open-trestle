package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/update"
	"github.com/georgejieh/open-trestle/spending"
)

// The update notice on the home screen and after `trestle review`. It reads
// the release list at most once a day, caching the newest versions in
// update-check.json in the state folder, and the local update folder for a
// development install. That GET is its only request, and it sends nothing
// about this machine. It says nothing when it cannot tell, and
// OPEN_TRESTLE_UPDATE_CHECK=off turns it off.

const (
	updateCheckInterval = 24 * time.Hour
	updateNoticeTimeout = 3 * time.Second
	updateCacheContract = "open-trestle/update-check"
)

// updateNow is the notice's clock. Tests replace it.
var updateNow = time.Now

type updateCheckCache struct {
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	CheckedAt     string `json:"checked_at"`
	// Newest is the highest qualifying release, prereleases included, and
	// NewestStable the highest without them; "" when there is none.
	Newest       string `json:"newest"`
	NewestStable string `json:"newest_stable"`
}

func (c updateCheckCache) valid() bool {
	if _, err := time.Parse(time.RFC3339, c.CheckedAt); err != nil || c.Contract != updateCacheContract || c.SchemaVersion != 1 {
		return false
	}
	for _, version := range []string{c.Newest, c.NewestStable} {
		if _, err := update.ParseVersion(version); version != "" && err != nil {
			return false
		}
	}
	return true
}

// updateCheckDisabled reports OPEN_TRESTLE_UPDATE_CHECK=off (or 0, false, no).
func updateCheckDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("OPEN_TRESTLE_UPDATE_CHECK"))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// updatePackageInstalled reports a readable package receipt on a platform
// trestle update supports.
func updatePackageInstalled() (update.Installed, bool) {
	if updatePlatform != "linux/amd64" {
		return update.Installed{}, false
	}
	installed, err := update.ReadReceipt(updateReceiptPath, updateRootOwner)
	return installed, err == nil
}

// updateNotice is the one-line notice, or "" when there is nothing newer, the
// check is off, or it cannot tell.
func updateNotice(ctx context.Context) string { return updateNoticeFrom(ctx, true) }

// updateNoticeFrom is the notice; without fetch it reads only the cache and
// writes nothing.
func updateNoticeFrom(ctx context.Context, fetch bool) string {
	if updateCheckDisabled() {
		return ""
	}
	installed, ok := updatePackageInstalled()
	if !ok {
		return ""
	}
	var local update.Version
	hasLocal := false
	if installed.Version.Development() {
		if dir, err := update.LocalDirectory(os.Getenv); err == nil {
			if build, found, err := update.FindLocal(dir); err == nil && found && build.Version.Compare(installed.Version) > 0 {
				local, hasLocal = build.Version, true
			}
		}
	}
	release, hasRelease := updateNewestRelease(ctx, installed.Version, fetch)
	switch {
	case hasRelease && (!hasLocal || release.Compare(local) >= 0):
		return fmt.Sprintf("Update available: %s (you have %s). Run trestle update.", release, installed.Version)
	case hasLocal:
		return fmt.Sprintf("Update available: %s, an unsigned local build (you have %s). Run trestle update.", local, installed.Version)
	}
	return ""
}

func updateCachePath() (string, error) {
	usage, err := spending.DefaultDirectory(os.Getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(usage), "update-check.json"), nil
}

// updateNewestRelease is the newest release installed may move to, from
// the cache when it is under a day old and otherwise from one GET. Without a
// pinned key, or without a usable state folder to rate-limit the GET, it
// does not check. Without fetch it uses the cache whatever its age.
func updateNewestRelease(ctx context.Context, installed update.Version, fetch bool) (update.Version, bool) {
	if ring, err := updateKeys(); err != nil || len(ring) == 0 {
		return update.Version{}, false
	}
	path, err := updateCachePath()
	if err != nil {
		return update.Version{}, false
	}
	if fetch && (os.MkdirAll(filepath.Dir(path), 0o700) != nil || fileauthority.CheckDirectory(filepath.Dir(path)) != nil) {
		return update.Version{}, false
	}
	now := updateNow().UTC()
	cache, cached := readUpdateCache(path)
	checked, _ := time.Parse(time.RFC3339, cache.CheckedAt)
	if fetch && (!cached || !now.Before(checked.Add(updateCheckInterval)) || checked.After(now.Add(time.Hour))) {
		fresh := updateCheckCache{Contract: updateCacheContract, SchemaVersion: 1, CheckedAt: now.Format(time.RFC3339)}
		releases, err := update.Client{Transport: updateTransport}.Releases(ctx, updateNoticeTimeout)
		switch {
		case err == nil:
			if newest, ok := update.Latest(releases, true); ok {
				fresh.Newest = newest.Version.String()
			}
			if newest, ok := update.Latest(releases, false); ok {
				fresh.NewestStable = newest.Version.String()
			}
		case cached:
			// Offline: keep what was last known, and wait a day to ask again.
			fresh.Newest, fresh.NewestStable = cache.Newest, cache.NewestStable
		}
		if encoded, err := json.Marshal(fresh); err == nil {
			_ = replaceProtectedFile(context.WithoutCancel(ctx), path, append(encoded, '\n'))
		}
		cache = fresh
	}
	pick := cache.NewestStable
	if installed.Prerelease() {
		pick = cache.Newest
	}
	version, err := update.ParseVersion(pick)
	if err != nil || version.Compare(installed) <= 0 {
		return update.Version{}, false
	}
	return version, true
}

func readUpdateCache(path string) (updateCheckCache, bool) {
	content, err := readSetupBootstrapFile(path)
	if err != nil {
		return updateCheckCache{}, false
	}
	var cache updateCheckCache
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cache) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || !cache.valid() {
		return updateCheckCache{}, false
	}
	return cache, true
}

// startUpdateNotice checks in the background while the caller prints.
func startUpdateNotice(ctx context.Context) <-chan string {
	notice := make(chan string, 1)
	go func() { notice <- updateNotice(ctx) }()
	return notice
}

// sayUpdateNotice prints the notice once it is known.
func sayUpdateNotice(ctx context.Context, w *initWizard, notice <-chan string) {
	select {
	case line := <-notice:
		if line != "" {
			w.say("\n  %s", line)
		}
	case <-ctx.Done():
	}
}
