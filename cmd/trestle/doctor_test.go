package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/modelcatalog"
	"github.com/georgejieh/open-trestle/spending"
)

// trestle doctor runs against temporary repositories and setups, with fakes
// for the sandbox, the scan helper and every network read.

func useDoctorSandbox(t *testing.T, err error) {
	t.Helper()
	previous := doctorSandbox
	doctorSandbox = func() error { return err }
	t.Cleanup(func() { doctorSandbox = previous })
}

func usePlatform(t *testing.T, platform string) {
	t.Helper()
	previous := updatePlatform
	updatePlatform = platform
	t.Cleanup(func() { updatePlatform = previous })
}

// doctorReady is a repository with a ready setup whose key is in the
// environment and whose checks are on, on a supported platform.
func doctorReady(t *testing.T) (checkout, dir string) {
	t.Helper()
	checkout = latestChangeCheckout(t)
	dir = latestChangeSetup(t, checkout)
	if err := writeChecksConsent(context.Background(), dir, checksRepository(context.Background(), checkout), true); err != nil {
		t.Fatal(err)
	}
	useDoctorSandbox(t, nil)
	usePlatform(t, "linux/amd64")
	return checkout, dir
}

func runDoctorIn(t *testing.T, folder string, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(folder)
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"doctor"}, args...), &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
		t.Fatal("trestle doctor printed the key")
	}
	return code, stdout.String(), stderr.String()
}

// doctorRow finds a row of the report by its label and the start of its value.
func doctorRow(t *testing.T, sections []doctorSection, label, value string) healthRow {
	t.Helper()
	for _, section := range sections {
		for _, row := range section.Rows {
			if row.Label == label && strings.HasPrefix(row.Value, value) {
				return row
			}
		}
	}
	t.Fatalf("no %s row starting %q in %+v", label, value, sections)
	return healthRow{}
}

// assertInOrder fails unless each text appears after the one before it, with
// any run of spaces and line breaks counting as one space.
func assertInOrder(t *testing.T, out string, wants ...string) {
	t.Helper()
	flat, last := strings.Join(strings.Fields(out), " "), -1
	for _, want := range wants {
		at := strings.Index(flat[last+1:], strings.Join(strings.Fields(want), " "))
		if at < 0 {
			t.Fatalf("output lacks %q after the text before it:\n%s", want, out)
		}
		last += 1 + at
	}
}

// files lists every file under the folders with its size and time, so a test
// can tell that nothing was written.
func files(t *testing.T, folders ...string) string {
	t.Helper()
	var list strings.Builder
	for _, folder := range folders {
		_ = filepath.WalkDir(folder, func(path string, entry os.DirEntry, err error) error {
			if info, statErr := os.Lstat(path); err == nil && statErr == nil {
				list.WriteString(path + " " + info.ModTime().String() + " " + info.Mode().String() + "\n")
			}
			return nil
		})
	}
	return list.String()
}

func TestDoctorPassesAHealthySetupAndChangesNothing(t *testing.T) {
	checkout, dir := doctorReady(t)
	before := files(t, checkout, dir, os.Getenv("XDG_STATE_HOME"), os.Getenv("XDG_CONFIG_HOME"))
	code, out, errText := runDoctorIn(t, checkout)
	if code != 0 || errText != "" {
		t.Fatalf("exit=%d\n%s%s", code, out, errText)
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("control characters without a terminal:\n%q", out)
	}
	assertInOrder(t, out,
		"Open Trestle · doctor",
		"Install", "✓ Version development build", "✓ Scanner found, and it matches the SHA-256", "✓ Platform linux/amd64, supported",
		"Repository", "(on branch review)", "✓ Branch default branch main", "✓ History complete", "✓ Changes clean",
		"Setup", "✓ Folder loads from ~/.local/state/open-trestle/", "✓ Provider Ollama Cloud (https://ollama.com/v1)", "✓ Models finder gemma4:31b · checker qwen3.5:397b", "✓ Route ready",
		"Keys", "✓ Key OPEN_TRESTLE_PROVIDER_REMOTE_TEST from the environment · "+keysMaskedSuffix(remoteTestKey),
		"Spending", "– Spending $0.00 recorded this month; no limit set", "-> trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_REMOTE_TEST --limit USD",
		"Repository checks", "✓ Checks on: each review", "✓ Sandbox available here",
		"Update", "– Update not a packaged install",
		"All checks passed.",
	)
	if !strings.HasSuffix(out, "\n\nAll checks passed.\n") || !strings.Contains(out, "\n    -> trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_REMOTE_TEST --limit USD\n") {
		t.Fatalf("the summary or a command line is not on its own line:\n%s", out)
	}
	initAssertWidth(t, out)
	if after := files(t, checkout, dir, os.Getenv("XDG_STATE_HOME"), os.Getenv("XDG_CONFIG_HOME")); after != before {
		t.Fatalf("doctor changed files:\n%s\nwas\n%s", after, before)
	}
}

func TestDoctorNamesTheFixForAMissingKey(t *testing.T) {
	checkout, _ := doctorReady(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
	code, out, _ := runDoctorIn(t, checkout)
	if code != 1 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	assertInOrder(t, out, "✗ Key OPEN_TRESTLE_PROVIDER_REMOTE_TEST is not set in this shell and not saved", "-> trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "Spending")
	if want := "\n1 problem to fix:\n  1. Key: OPEN_TRESTLE_PROVIDER_REMOTE_TEST is not set in\n     this shell and not saved\n     -> trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST\n"; !strings.HasSuffix(out, want) {
		t.Fatalf("summary is not\n%s\nin\n%s", want, out)
	}
	if strings.Contains(out, "All checks passed.") {
		t.Fatal("a missing key passed")
	}
	// A saved key passes, with its last four characters only.
	saveTestKey(t, "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	if code, out, _ := runDoctorIn(t, checkout); code != 0 || !initHas(out, "✓ Key OPEN_TRESTLE_PROVIDER_REMOTE_TEST saved · "+keysMaskedSuffix(remoteTestKey)) {
		t.Fatalf("saved key: exit=%d\n%s", code, out)
	}
}

func TestDoctorOutsideARepositoryRunsTheRest(t *testing.T) {
	keyStoreForTest(t)
	t.Setenv("HOME", t.TempDir())
	useDoctorSandbox(t, nil)
	usePlatform(t, "linux/amd64")
	code, out, _ := runDoctorIn(t, t.TempDir())
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	assertInOrder(t, out,
		"✓ Scanner", "… Checkout this folder is not inside a Git checkout, or git is not installed", "-> cd REPOSITORY && trestle doctor",
		"– Folder not checked: no Git checkout here", "– Key not checked: no usable setup", "– Spending not checked: no usable setup",
		"– Checks not checked: no usable setup", "✓ Sandbox available here", "– Update", "Nothing to fix. 1 row above needs a look.")
	// A repository without a setup fails on the setup.
	code, out, _ = runDoctorIn(t, latestChangeCheckout(t))
	if code != 1 || !initHas(out, "✗ Folder none for this repository; looked in") || !strings.Contains(out, "  1. Folder: none for this repository") || !strings.HasSuffix(out, "\n     -> trestle init\n") {
		t.Fatalf("no setup: exit=%d\n%s", code, out)
	}
}

func TestDoctorRowsForEachState(t *testing.T) {
	checkout, dir := doctorReady(t)
	ctx := context.Background()
	repo, err := loadRepositorySetup(ctx, checkout, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("install", func(t *testing.T) {
		usePlatform(t, "darwin/arm64")
		previous := setupBootstrapScannerPrerequisite
		t.Cleanup(func() { setupBootstrapScannerPrerequisite = previous })
		for _, test := range []struct {
			err  error
			want string
		}{
			{secretscan.ErrHelperNotPinned, "this build pins none, so every review is refused"},
			{secretscan.ErrHelperNotInstalled, "missing next to this program"},
		} {
			setupBootstrapScannerPrerequisite = func() error { return test.err }
			rows := []doctorSection{{Rows: doctorInstall()}}
			if row := doctorRow(t, rows, "Scanner", test.want); row.State != healthFail || row.Next[0] != "python3 tools/package_secret_scanner.py --development DIR" {
				t.Fatalf("scan helper: %+v", row)
			}
			if row := doctorRow(t, rows, "Platform", "darwin/arm64 is not supported"); row.State != healthAttention || row.Next[0] != "docs/platforms.md" {
				t.Fatalf("platform: %+v", row)
			}
		}
		usePlatform(t, "linux/arm64")
		if row := doctorRow(t, []doctorSection{{Rows: doctorInstall()}}, "Platform", "linux/arm64, which builds but is untested"); row.State != healthOptional {
			t.Fatalf("arm64: %+v", row)
		}
	})
	t.Run("repository", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(checkout, "new.go"), []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(filepath.Join(checkout, "new.go")) })
		shallow := filepath.Join(t.TempDir(), "shallow")
		checkoutGit(t, t.TempDir(), "clone", "-q", "--depth", "1", "--branch", "review", "file://"+checkout, shallow)
		checkoutGit(t, shallow, "branch", "-q", "-m", "review", "work")
		checkoutGit(t, shallow, "remote", "remove", "origin")
		rows := []doctorSection{{Rows: append(doctorRepository(ctx, checkout), doctorRepository(ctx, shallow)...)}}
		if row := doctorRow(t, rows, "Changes", "uncommitted changes, which reviews leave out"); row.State != healthOK {
			t.Fatalf("uncommitted: %+v", row)
		}
		if row := doctorRow(t, rows, "History", "a shallow clone"); row.State != healthAttention || row.Next[0] != "git fetch --unshallow" {
			t.Fatalf("shallow: %+v", row)
		}
		if row := doctorRow(t, rows, "Branch", "no default branch: no main or master"); row.State != healthAttention || row.Next[0] != "trestle review --base REF" {
			t.Fatalf("no default branch: %+v", row)
		}
	})
	t.Run("setup", func(t *testing.T) {
		other := latestChangeCheckout(t)
		resolved, _ := filepath.EvalSymlinks(other)
		if err := os.MkdirAll(filepath.Dir(defaultSetupDirectory(resolved)), 0o700); err != nil {
			t.Fatal(err)
		}
		broken := defaultSetupDirectory(resolved)
		if err := os.Mkdir(broken, 0o700); err != nil || os.WriteFile(filepath.Join(broken, "bootstrap.json"), []byte("{}\n"), 0o600) != nil {
			t.Fatal("the broken setup could not be written")
		}
		rows, usable := doctorSetup(ctx, resolved)
		if usable != nil || rows[0].State != healthFail || !strings.Contains(rows[0].Value, "cannot be used (") || rows[0].Next[0] != "trestle setup bootstrap inspect --directory "+initShellQuote(broken) || rows[0].Next[1] != "trestle init" {
			t.Fatalf("unreadable setup: %+v", rows)
		}
		// trestle review names trestle doctor for it.
		if code, _, errText := runReviewCommand(t, other); code != 4 || !strings.HasSuffix(errText, "Nothing was sent.\n  -> trestle doctor\n  -> trestle init\n") {
			t.Fatalf("review of an unreadable setup: exit=%d %q", code, errText)
		}
	})
	t.Run("keys and spending", func(t *testing.T) {
		store := spendingTestStore(t)
		spendingTestLimit(t, store, 10_000_000, []int{80, 100})
		entry := spending.Entry{RecordedAt: spendingTestNow.Add(-time.Hour), ReviewRunID: "local-a", RuntimePolicyIdentity: strings.Repeat("ab", 32), Scopes: []spending.Scope{spendingTestScope(t)}, Models: []string{"gemma4:31b"}, RequestsSent: 2, UsageKnown: true, CostMicroUSD: 8_500_000}
		if err := store.Append(ctx, entry); err != nil {
			t.Fatal(err)
		}
		row := doctorSpending(repo.setup)[0]
		if row.State != healthAttention || row.tone != initToneWarning || !strings.Contains(row.Value, "(85%)") || row.Next[0] != "trestle usage" {
			t.Fatalf("at the alert: %+v", row)
		}
		entry.ReviewRunID = "local-b"
		if err := store.Append(ctx, entry); err != nil {
			t.Fatal(err)
		}
		row = doctorSpending(repo.setup)[0]
		if row.State != healthFail || row.tone != initToneDanger || row.Next[0] != "trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_REMOTE_TEST --limit USD" {
			t.Fatalf("over the limit: %+v", row)
		}
		local := initSetup{provider: initProviders[3]}
		if keys, spend := doctorKeys(local)[0], doctorSpending(local)[0]; keys.State != healthOptional || spend.State != healthOptional {
			t.Fatalf("local setup: %+v %+v", keys, spend)
		}
	})
	t.Run("repository checks", func(t *testing.T) {
		useDoctorSandbox(t, errors.New("user namespaces are off"))
		rows := []doctorSection{{Rows: doctorChecks(ctx, &repo)}}
		if row := doctorRow(t, rows, "Sandbox", "not available on this machine"); row.State != healthAttention || row.Next[0] != "trestle checks off" || !strings.Contains(row.Value, "(user namespaces are off)") {
			t.Fatalf("sandbox with checks on: %+v", row)
		}
		if err := os.Remove(filepath.Join(dir, "checks.json")); err != nil {
			t.Fatal(err)
		}
		rows = []doctorSection{{Rows: doctorChecks(ctx, &repo)}}
		if row := doctorRow(t, rows, "Checks", "not decided yet"); row.State != healthAttention || len(row.Next) != 2 {
			t.Fatalf("undecided: %+v", row)
		}
		if row := doctorRow(t, rows, "Sandbox", "not available"); row.State != healthOptional {
			t.Fatalf("sandbox with checks undecided: %+v", row)
		}
	})
	t.Run("update", func(t *testing.T) {
		useUpdateFakes(t, "0.1.0")
		if row := doctorUpdate(ctx); row.State != healthOptional || row.Value != "not checked yet" || row.Next[0] != "trestle update --check" {
			t.Fatalf("no cache: %+v", row)
		}
		path, err := updateCachePath()
		if err != nil || os.MkdirAll(filepath.Dir(path), 0o700) != nil {
			t.Fatal("no state folder")
		}
		cache := updateCheckCache{Contract: updateCacheContract, SchemaVersion: 1, CheckedAt: "2026-01-02T03:04:05Z", Newest: "0.2.0", NewestStable: "0.2.0"}
		encoded, _ := json.Marshal(cache)
		if err := replaceProtectedFile(ctx, path, append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
		// The cache is days old: doctor uses it and does not ask again.
		if row := doctorUpdate(ctx); row.State != healthAttention || row.Value != "Update available: 0.2.0 (you have 0.1.0)." || row.Next[0] != "trestle update" {
			t.Fatalf("newer release: %+v", row)
		}
		cache.Newest, cache.NewestStable = "0.1.0", "0.1.0"
		encoded, _ = json.Marshal(cache)
		if err := replaceProtectedFile(ctx, path, append(encoded, '\n')); err != nil {
			t.Fatal(err)
		}
		if row := doctorUpdate(ctx); row.State != healthOK || row.Value != "no newer version known (checked 2 Jan 03:04 UTC)" {
			t.Fatalf("up to date: %+v", row)
		}
	})
}

func TestDoctorJSONHasTheSameRows(t *testing.T) {
	checkout, _ := doctorReady(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
	code, out, _ := runDoctorIn(t, checkout, "--json")
	var report struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Live, Passed  bool
		Sections      []struct {
			Title string
			Rows  []map[string]any
		}
		Problems []map[string]any
	}
	if code != 1 || strings.Count(out, "\n") != 1 || json.Unmarshal([]byte(out), &report) != nil {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	titles := []string{}
	for _, section := range report.Sections {
		titles = append(titles, section.Title)
		for _, row := range section.Rows {
			if row["label"] == "" || row["value"] == "" || row["state"] == "" {
				t.Fatalf("row without a label, value or state: %v", row)
			}
		}
	}
	if report.Contract != doctorContract || report.SchemaVersion != 1 || report.Live || report.Passed || strings.Join(titles, ",") != "Install,Repository,Setup,Keys,Spending,Repository checks,Update" {
		t.Fatalf("report: %+v", report)
	}
	if len(report.Problems) != 1 || report.Problems[0]["state"] != "fail" || report.Problems[0]["next"].([]any)[0] != "trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST" {
		t.Fatalf("problems: %v", report.Problems)
	}
}

func TestDoctorOnATerminal(t *testing.T) {
	checkout, _ := doctorReady(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
	initAsTerminal(t)
	for _, test := range []struct {
		term string
		want []string
	}{
		{"xterm-256color", []string{"\x1b[1;38;5;25mOpen Trestle · doctor\x1b[0m\n", "  \x1b[38;5;131m✗\x1b[0m Key ", "\x1b[2m    -> trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST\x1b[0m\n", "\x1b[38;5;131m1 problem to fix:\x1b[0m\n"}},
		{"dumb", []string{"  [x] Key ", "  [ok] Scanner ", "  [--] Spending ", "\n1 problem to fix:\n"}},
	} {
		initColorEnv(t, test.term, "")
		_, out, _ := runDoctorIn(t, checkout)
		for _, want := range test.want {
			if !strings.Contains(out, want) {
				t.Fatalf("TERM=%s lacks %q:\n%s", test.term, want, out)
			}
		}
		initAssertWidth(t, out)
	}
}

func TestDoctorLiveReadsTheModelList(t *testing.T) {
	checkout, _ := doctorReady(t)
	calls := initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
	code, out, _ := runDoctorIn(t, checkout, "--live")
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	assertInOrder(t, out, "Open Trestle · doctor --live", "Update", "Network checks (--live)", "✓ Model list read from ollama.com with OPEN_TRESTLE_PROVIDER_REMOTE_TEST, 2 models", "✓ Finder gemma4:31b is listed", "✓ Checker qwen3.5:397b is listed", "All checks passed.")
	if len(*calls) != 1 || (*calls)[0] != "https://ollama.com/api/tags with OPEN_TRESTLE_PROVIDER_REMOTE_TEST" {
		t.Fatalf("model list reads: %v", *calls)
	}
	// Without --live, nothing is read.
	if runDoctorIn(t, checkout); len(*calls) != 1 {
		t.Fatalf("doctor without --live read the model list: %v", *calls)
	}
	initFakeModelList(t, "gemma4:31b")
	code, out, _ = runDoctorIn(t, checkout, "--live")
	if code != 1 || !initHas(out, "✗ Checker qwen3.5:397b is no longer listed") || !strings.Contains(out, "  1. Checker: qwen3.5:397b is no longer listed\n     -> trestle init\n") {
		t.Fatalf("missing model: exit=%d\n%s", code, out)
	}
	previous := initListModels
	initListModels = func(context.Context, modelcatalog.Source, bool, modelcatalog.CredentialResolver) ([]modelcatalog.Model, error) {
		return nil, modelcatalog.ErrInvalid
	}
	t.Cleanup(func() { initListModels = previous })
	code, out, _ = runDoctorIn(t, checkout, "--live")
	if code != 1 || !initHas(out, "✗ Model list could not be read from ollama.com") || !strings.Contains(out, "-> trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST") {
		t.Fatalf("unreadable list: exit=%d\n%s", code, out)
	}
}

// The OpenRouter key check is the GET of trestle keys set, against a stub
// transport.
func TestDoctorLiveChecksAnOpenRouterKey(t *testing.T) {
	report := useKeyCheckReport(t)
	ctx := context.Background()
	if row := doctorOpenRouterKey(ctx, "OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey); row.State != healthOK || row.Value != "OpenRouter accepts OPEN_TRESTLE_PROVIDER_OPENROUTER" {
		t.Fatalf("accepted: %+v", row)
	}
	if row := doctorOpenRouterKey(ctx, "OPEN_TRESTLE_PROVIDER_OPENROUTER", "another-synthetic-key-not-a-real-one"); row.State != healthFail || row.Next[0] != "trestle keys set OPEN_TRESTLE_PROVIDER_OPENROUTER" || !strings.Contains(row.Value, "(HTTP 401)") {
		t.Fatalf("refused: %+v", row)
	}
	if len(report.bearers) != 2 {
		t.Fatalf("requests: %d", len(report.bearers))
	}
}

func TestDoctorUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"doctor", "--help"}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "usage: trestle doctor [--live] [--json]\n") {
		t.Fatalf("help: exit=%d %q", code, stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"doctor", "--fix"}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "usage: trestle doctor") {
		t.Fatalf("unknown flag: exit=%d %q", code, stderr.String())
	}
}
