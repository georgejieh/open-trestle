package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/spending"
)

// Scripts read the plain output of these commands, so without a terminal it
// stays exactly as pinned here.

func TestKeysListPlainOutputIsUnchanged(t *testing.T) {
	keyStoreForTest(t)
	clearSessionKeys(t)
	t.Chdir(t.TempDir())
	for _, name := range []string{"OPEN_TRESTLE_PROVIDER_OPENROUTER", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST"} {
		t.Setenv(name, "")
	}
	dir := providerCredentialDisplayDirectory()
	code, out, _ := runKeysCommand(t, "")
	want := "API keys (the environment first, then the keys saved in " + dir + "):\n" +
		"  No API key is set or saved.\n" +
		"  Save one: trestle keys set OPEN_TRESTLE_PROVIDER_NAME   (for example OPEN_TRESTLE_PROVIDER_OPENROUTER)\n"
	if code != 0 || out != want {
		t.Fatalf("empty list: exit=%d\n%q\nwant\n%q", code, out, want)
	}
	saveTestKey(t, "OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	code, out, _ = runKeysCommand(t, "")
	want = "API keys (the environment first, then the keys saved in " + dir + "):\n" +
		"  OPEN_TRESTLE_PROVIDER_OPENROUTER   saved in " + dir + " · " + keysMaskedSuffix(remoteTestKey) + "\n" +
		"  OPEN_TRESTLE_PROVIDER_REMOTE_TEST  from the environment · " + keysMaskedSuffix(remoteTestKey) + "\n" +
		"Change one: trestle keys set NAME · delete a saved one: trestle keys remove NAME\n"
	if code != 0 || out != want {
		t.Fatalf("list: exit=%d\n%q\nwant\n%q", code, out, want)
	}
}

func TestUsagePlainOutputIsUnchanged(t *testing.T) {
	store := spendingTestStore(t)
	keyStoreForTest(t)
	clearSessionKeys(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	folder := spending.DisplayDirectory(store.Directory())
	code, out, _ := runUsageCommand(t)
	want := "Spending recorded by Open Trestle (usage folder " + folder + "):\n" +
		"  No spending limit is set and no spend is recorded this month.\n" +
		"  Set one: trestle usage set --credential-env OPEN_TRESTLE_PROVIDER_NAME --limit USD [--period week|month|year]\n" +
		spending.Note + "\n"
	if code != 0 || out != want {
		t.Fatalf("empty: exit=%d\n%q\nwant\n%q", code, out, want)
	}
	usageTestSpend(t, store)
	code, out, _ = runUsageCommand(t)
	want = "Spending recorded by Open Trestle (usage folder " + folder + "):\n" +
		"  OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter): $9.00 of your $10.00 monthly limit this month (90%), alerts at 80% and 100%\n" +
		"    OpenRouter's own figures are not read: OPEN_TRESTLE_PROVIDER_OPENROUTER is not set in this shell and no key is saved for it.\n" +
		"  OPEN_TRESTLE_PROVIDER_REMOTE_TEST (ollama-cloud): $0.07 recorded this month; no limit set\n" +
		spending.Note + "\n"
	if code != 0 || out != want {
		t.Fatalf("status: exit=%d\n%q\nwant\n%q", code, out, want)
	}
}

// usageTestSpend sets a $10 monthly limit on the OpenRouter key and records
// $9.00 against it and $0.07 against the test key, which has no limit.
func usageTestSpend(t *testing.T, store *spending.Store) {
	t.Helper()
	scope, _ := spending.NewScope("openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	limit, err := spending.NewLimit(scope, spending.PeriodMonth, 10_000_000, []int{80, 100}, spendingTestNow)
	if err != nil || store.SetLimit(t.Context(), limit) != nil {
		t.Fatal("the limit could not be set")
	}
	entry := spending.Entry{RecordedAt: spendingTestNow.Add(-time.Hour), ReviewRunID: "local-a", RuntimePolicyIdentity: strings.Repeat("ab", 32), Scopes: []spending.Scope{scope}, Models: []string{"vendor/generator"}, RequestsSent: 2, UsageKnown: true, CostMicroUSD: 9_000_000}
	other := entry
	other.ReviewRunID, other.Scopes, other.CostMicroUSD = "local-c", []spending.Scope{spendingTestScope(t)}, 70_000
	for _, e := range []spending.Entry{entry, other} {
		if err := store.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChecksStatusPlainOutputIsUnchanged(t *testing.T) {
	checkout := latestChangeCheckout(t)
	t.Chdir(checkout)
	dir := checksTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sandbox := "Sandbox: available here. Turn checks on or off with trestle checks on or trestle checks off.\n"
	for _, test := range []struct{ command, first string }{
		{"status", "Repository checks: not decided yet. The next review asks before it runs any.\n"},
		{"on", "Repository checks: on. Each review runs this repository's tests for the changed area in a sandbox first.\n"},
		{"off", "Repository checks: off. Reviews do not run this repository's code.\n"},
	} {
		var stdout, stderr bytes.Buffer
		code := runChecks(context.Background(), []string{test.command, "--directory", dir}, &stdout, &stderr)
		first, second, _ := strings.Cut(stdout.String(), "\n")
		if code != 0 || first+"\n" != test.first || second != sandbox && !strings.HasPrefix(second, "Sandbox: not available on this machine, so checks would be reported as could not run (") {
			t.Fatalf("checks %s: exit=%d\n%q\n%s", test.command, code, stdout.String(), stderr.String())
		}
	}
}

// On a terminal the same commands print rows with marks, the next command
// after "->", and no line wider than initWidth.
func TestCommandOutputOnATerminal(t *testing.T) {
	store := spendingTestStore(t)
	keyStoreForTest(t)
	clearSessionKeys(t)
	t.Chdir(t.TempDir())
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	initAsTerminal(t)
	usageTestSpend(t, store)
	for _, test := range []struct {
		name, term string
		noColor    bool
		want       []string
	}{
		{"colors", "xterm-256color", false, []string{
			"\x1b[1;38;5;25mAPI keys\x1b[0m\n",
			"  \x1b[38;5;65m✓\x1b[0m OPEN_TRESTLE_PROVIDER_REMOTE_TEST  from the environment\n",
			"\x1b[2m  -> trestle keys set NAME\x1b[0m\n",
			"  \x1b[38;5;94m…\x1b[0m OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter)\n",
			"\x1b[38;5;94m    $9.00 of your $10.00 monthly limit this month (90%),\x1b[0m\n",
			"  \x1b[2m–\x1b[0m OPEN_TRESTLE_PROVIDER_REMOTE_TEST (ollama-cloud)\n",
		}},
		{"NO_COLOR", "xterm-256color", true, []string{
			"API keys\n",
			"  ✓ OPEN_TRESTLE_PROVIDER_REMOTE_TEST  from the environment\n",
			"  -> trestle keys remove NAME\n",
			"  … OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter)\n",
			"    $9.00 of your $10.00 monthly limit this month (90%),\n",
		}},
		{"TERM=dumb", "dumb", false, []string{
			"  [ok] OPEN_TRESTLE_PROVIDER_REMOTE_TEST  from the\n",
			"  [..] OPEN_TRESTLE_PROVIDER_OPENROUTER (openrouter)\n",
			"  [--] OPEN_TRESTLE_PROVIDER_REMOTE_TEST (ollama-cloud)\n",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			initColorEnv(t, test.term, "")
			if test.noColor {
				t.Setenv("NO_COLOR", "1")
			}
			_, keys, _ := runKeysCommand(t, "")
			_, usage, _ := runUsageCommand(t)
			out := keys + usage
			for _, want := range test.want {
				if !strings.Contains(out, want) {
					t.Fatalf("output lacks %q:\n%s", want, out)
				}
			}
			if test.noColor || test.term == "dumb" {
				if strings.Contains(out, "\x1b[") {
					t.Fatalf("color without a color terminal:\n%s", out)
				}
				// The temporary folders stand in for short ones under ~.
				short := strings.NewReplacer(spending.DisplayDirectory(store.Directory()), "~/usage", providerCredentialDisplayDirectory(), "~/keys")
				initAssertWidth(t, short.Replace(out))
			}
		})
	}
}

func TestSpendingStateNeverDependsOnColorAlone(t *testing.T) {
	initAsTerminal(t)
	initColorEnv(t, "dumb", "")
	p := newOutPrinter(context.Background(), &bytes.Buffer{})
	scope, _ := spending.NewScope("openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	limit, err := spending.NewLimit(scope, spending.PeriodMonth, 10_000_000, []int{75, 100}, spendingTestNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		spent uint64
		mark  string
		tone  initTone
	}{
		{4_900_000, "[ok]", initToneDim},
		{5_000_000, "[ok]", initToneBody},
		{7_500_000, "[..]", initToneWarning},
		{10_000_000, "[x]", initToneDanger},
		{12_000_000, "[x]", initToneDanger},
	} {
		status := spending.Status{Limit: limit, Spend: spending.Spend{MicroUSD: test.spent}}
		if mark, tone := p.spendingState(status); mark != test.mark || tone != test.tone || !strings.Contains(status.Brief(), "%)") {
			t.Fatalf("$%d: %q %d, want %q %d", test.spent, mark, tone, test.mark, test.tone)
		}
	}
}

func TestChecksStatusAndUpdateCheckOnATerminal(t *testing.T) {
	checkout := latestChangeCheckout(t)
	t.Chdir(checkout)
	dir := checksTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initAsTerminal(t)
	initColorEnv(t, "dumb", "")
	var stdout, stderr bytes.Buffer
	if code := runChecks(context.Background(), []string{"on", "--directory", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"Repository checks\n", "  [ok] Checks   on: each review first runs this repository's\n", "  -> trestle checks off\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("checks lack %q:\n%s", want, out)
		}
	}
	initAssertWidth(t, out)
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	code, out, _ := runUpdateScript(t, "", "--check")
	if want := "  [..] Update available: 0.2.0 (you have 0.1.0), the signed\n       release v0.2.0 on GitHub Releases.\n  -> trestle update\n"; code != updateExitAvailable || out != want {
		t.Fatalf("update --check: exit=%d\n%q\nwant\n%q", code, out, want)
	}
}
