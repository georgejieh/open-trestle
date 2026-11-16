package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/internal/update"
)

// useNoticeClock pins the notice's clock and gives the test its own state
// folder for update-check.json.
func useNoticeClock(t *testing.T) *time.Time {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	previous := updateNow
	updateNow = func() time.Time { return now }
	t.Cleanup(func() { updateNow = previous })
	return &now
}

func noticeCachePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(os.Getenv("XDG_STATE_HOME"), "open-trestle", "update-check.json")
}

func TestUpdateNoticeChecksAtMostOnceADay(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	now := useNoticeClock(t)
	f.release("0.2.0", false)
	want := "Update available: 0.2.0 (you have 0.1.0). Run trestle update."
	if got := updateNotice(context.Background()); got != want {
		t.Fatalf("notice %q", got)
	}
	if got := updateNotice(context.Background()); got != want || len(f.github.Requests()) != 1 {
		t.Fatalf("notice %q after %d requests", got, len(f.github.Requests()))
	}
	*now = now.Add(23 * time.Hour)
	updateNotice(context.Background())
	if len(f.github.Requests()) != 1 {
		t.Fatalf("checked again within a day: %d requests", len(f.github.Requests()))
	}
	*now = now.Add(2 * time.Hour)
	updateNotice(context.Background())
	if len(f.github.Requests()) != 2 {
		t.Fatalf("did not check after a day: %d requests", len(f.github.Requests()))
	}
	// The release list GET is the only request: no signature, sidecar or
	// archive, and nothing but the fixed headers.
	for _, request := range f.github.Requests() {
		if request.Method != "GET" || request.URL != update.ReleasesURL || len(request.Header) != 2 {
			t.Fatalf("request %+v", request)
		}
	}
	info, err := os.Lstat(noticeCachePath(t))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache %v %v", info, err)
	}
	var cache map[string]any
	raw, _ := os.ReadFile(noticeCachePath(t))
	if json.Unmarshal(raw, &cache) != nil || cache["newest_stable"] != "0.2.0" || cache["checked_at"] != "2026-11-16T13:00:00Z" || len(cache) != 5 {
		t.Fatalf("cache %s", raw)
	}
	if len(f.commands) != 0 {
		t.Fatalf("the notice ran %q", f.commands)
	}
}

func TestUpdateNoticeIsSilentOfflineAndKeepsWhatItKnew(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	now := useNoticeClock(t)
	if got := updateNotice(context.Background()); got != "" {
		t.Fatalf("offline notice %q", got)
	}
	if updateNotice(context.Background()); len(f.github.Requests()) != 1 {
		t.Fatalf("an offline check was retried within a day: %d requests", len(f.github.Requests()))
	}
	*now = now.Add(25 * time.Hour)
	f.release("0.2.0", false)
	if got := updateNotice(context.Background()); got == "" {
		t.Fatal("no notice once online")
	}
	f.github.Set(update.ReleasesURL, testsupport.FakeResponse{Status: 503})
	*now = now.Add(25 * time.Hour)
	if got := updateNotice(context.Background()); got != "Update available: 0.2.0 (you have 0.1.0). Run trestle update." {
		t.Fatalf("a failed check forgot the known release: %q", got)
	}
	// A cache that is not the contract is checked again.
	os.WriteFile(noticeCachePath(t), []byte("{}\n"), 0o600)
	before := len(f.github.Requests())
	updateNotice(context.Background())
	if len(f.github.Requests()) != before+1 {
		t.Fatal("an unreadable cache was trusted")
	}
}

func TestUpdateNoticeOff(t *testing.T) {
	for _, value := range []string{"off", "OFF", "0", "false", "no"} {
		f := useUpdateFakes(t, "0.1.5-dev")
		useNoticeClock(t)
		f.release("0.2.0", false)
		f.localBuild("0.1.6-dev")
		t.Setenv("OPEN_TRESTLE_UPDATE_CHECK", value)
		if got := updateNotice(context.Background()); got != "" || len(f.github.Requests()) != 0 {
			t.Fatalf("%s: notice %q after %d requests", value, got, len(f.github.Requests()))
		}
		if _, err := os.Lstat(noticeCachePath(t)); err == nil {
			t.Fatalf("%s: the cache was written", value)
		}
	}
}

func TestUpdateNoticeNeedsAPackageAndAKey(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	useNoticeClock(t)
	f.release("0.2.0", false)
	f.noKeys()
	if got := updateNotice(context.Background()); got != "" || len(f.github.Requests()) != 0 {
		t.Fatalf("without a key: %q after %d requests", got, len(f.github.Requests()))
	}
	f = useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	updateReceiptPath = filepath.Join(t.TempDir(), "receipt.json")
	if got := updateNotice(context.Background()); got != "" || len(f.github.Requests()) != 0 {
		t.Fatalf("without a package: %q after %d requests", got, len(f.github.Requests()))
	}
}

func TestUpdateNoticeForALocalBuild(t *testing.T) {
	f := useUpdateFakes(t, "0.1.5-dev")
	useNoticeClock(t)
	f.noKeys()
	f.localBuild("0.1.6-dev")
	if got := updateNotice(context.Background()); got != "Update available: 0.1.6-dev, an unsigned local build (you have 0.1.5-dev). Run trestle update." || len(f.github.Requests()) != 0 {
		t.Fatalf("notice %q after %d requests", got, len(f.github.Requests()))
	}
	// A prerelease install hears of a newer prerelease, which beats the local build.
	f = useUpdateFakes(t, "0.1.5-dev")
	useNoticeClock(t)
	f.localBuild("0.1.6-dev")
	f.release("0.2.0-rc.1", true)
	if got := updateNotice(context.Background()); got != "Update available: 0.2.0-rc.1 (you have 0.1.5-dev). Run trestle update." {
		t.Fatalf("notice %q", got)
	}
}

func TestHomeShowsTheUpdateNoticeAndAction(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	useInteractiveHome(t)
	f := useUpdateFakes(t, "0.1.0")
	useNoticeClock(t)
	f.release("0.2.0", false)
	code, out, _ := runHomeScript(t, checkout, "\n")
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	initAssertWidth(t, out)
	for _, want := range []string{
		"Update available: 0.2.0 (you have 0.1.0). Run trestle update.",
		"5) Read the guides docs/getting-started.md",
		"6) Update Open Trestle trestle update",
		"Choose 1-6, or Enter to quit:",
	} {
		if !initHas(out, want) {
			t.Fatalf("home screen lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "Update available") > strings.Index(out, "1) Review the latest change") {
		t.Fatalf("the notice is not above the actions:\n%s", out)
	}
	// Two steps: trestle, then 6, installs it after the usual question.
	f.upgradeTo = "0.2.0"
	code, out, _ = runHomeScript(t, checkout, "6\ny\n")
	if code != 0 || len(f.installed) != 1 || !initHas(out, "Open Trestle is now 0.2.0") {
		t.Fatalf("update from home: exit=%d installed=%v\n%s", code, f.installed, out)
	}
}

func TestReviewShowsTheUpdateNoticeOnlyOnATerminal(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	f := useUpdateFakes(t, "0.1.0")
	useNoticeClock(t)
	f.release("0.2.0", false)
	latestFixtureTransport(t)
	if _, _, stderr := runReviewCommand(t, checkout); strings.Contains(stderr, "Update available") || len(f.github.Requests()) != 0 {
		t.Fatalf("a review without a terminal checked for updates:\n%s", stderr)
	}
	initAsTerminal(t)
	latestFixtureTransport(t)
	_, stdout, stderr := runReviewCommand(t, checkout)
	if !initHas(initANSI.ReplaceAllString(stderr, ""), "Update available: 0.2.0 (you have 0.1.0). Run trestle update.") || strings.Contains(stdout, "Update available") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
}
