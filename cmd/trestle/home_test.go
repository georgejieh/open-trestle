package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// The home screen runs against temporary repositories and setups; reviews go
// to the offline remote fixture.

func useInteractiveHome(t *testing.T) {
	t.Helper()
	previous := homeInteractive
	homeInteractive = func(io.Reader, io.Writer) bool { return true }
	t.Cleanup(func() { homeInteractive = previous })
}

func runHomeScript(t *testing.T, checkout string, input string) (int, string, string) {
	t.Helper()
	t.Chdir(checkout)
	var stdout, stderr bytes.Buffer
	code := runHome(context.Background(), strings.NewReader(input), &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
		t.Fatal("the home screen printed the key")
	}
	// The card's frame is not text: compare its rows as words.
	return code, strings.ReplaceAll(stdout.String(), "│", " "), stderr.String()
}

func TestHomeShowsTheStatusCardAndRunsTheChosenAction(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	useInteractiveHome(t)
	code, out, _ := runHomeScript(t, checkout, "\n")
	if code != 0 {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	// The home screen's own lines fit the wizard's 60 columns.
	initAssertWidth(t, out)
	for _, want := range []string{
		"Open Trestle",
		"Repository ", "(on branch review)",
		"Setup ~/.local/state/open-trestle/",
		"Models finder gemma4:31b · checker qwen3.5:397b",
		"Runs on Ollama Cloud (https://ollama.com/v1)",
		"Key OPEN_TRESTLE_PROVIDER_REMOTE_TEST (from the environment)",
		"Spending $0.00 recorded this month; no limit set",
		"Last run none recorded yet",
		"1) Review the latest change trestle review",
		"2) See spending trestle usage",
		"3) Change the API key trestle keys",
		"4) Re-run setup trestle init",
		"5) Read the guides docs/getting-started.md",
		"Choose 1-5, or Enter to quit:",
	} {
		if !initHas(out, want) {
			t.Fatalf("home screen lacks %q:\n%s", want, out)
		}
	}
	// Two steps: trestle, then 1, reviews the latest change.
	transport := latestFixtureTransport(t)
	code, out, _ = runHomeScript(t, checkout, "1\n")
	if code != 4 || len(transport.requests) != 2 || !initHas(out, "Review finished: 1 confirmed finding.") || !strings.Contains(out, "status: findings\n") {
		t.Fatalf("review from home: exit=%d requests=%v\n%s", code, transport.requests, out)
	}
	_, out, _ = runHomeScript(t, checkout, "q\n")
	head := checkoutGit(t, checkout, "rev-parse", "HEAD")
	if !initHas(out, "Last run 1 confirmed finding · ") || !initHas(out, initShort(head)) {
		t.Fatalf("the last review is not shown:\n%s", out)
	}
	// See spending is one choice away and prints trestle usage's report.
	if code, out, _ := runHomeScript(t, checkout, "2\n"); code != 0 || !strings.Contains(out, "Spending recorded by Open Trestle") {
		t.Fatalf("spending from home: exit=%d\n%s", code, out)
	}
	// An unusable answer is asked again; end of input quits.
	if code, out, _ := runHomeScript(t, checkout, "9\n"); code != 0 || !initHas(out, "Please type a number from 1 to 5") {
		t.Fatalf("bad choice: exit=%d\n%s", code, out)
	}
}

func TestHomeOffersSetupInAnUnconfiguredRepository(t *testing.T) {
	checkout := latestChangeCheckout(t)
	t.Setenv("HOME", t.TempDir())
	useInteractiveHome(t)
	code, out, _ := runHomeScript(t, checkout, "\n")
	if code != 0 || !initHas(out, "has no Open Trestle setup yet") || !initHas(out, "1) Set up this repository trestle init") || initHas(out, "2)") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
	code, out, _ = runHomeScript(t, t.TempDir(), "")
	if code != 0 || !initHas(out, "not inside a Git repository") {
		t.Fatalf("outside a repository: exit=%d\n%s", code, out)
	}
}

// Without a terminal, `trestle` keeps printing the usage text and exiting 2.
func TestHomeIsUsageTextWhenNotInteractive(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	var usage bytes.Buffer
	writeUsage(&usage)
	code, out, errText := runHomeScript(t, checkout, "1\n")
	if code != 2 || out != "" || errText != usage.String() {
		t.Fatalf("non-interactive home: exit=%d out=%q", code, out)
	}
	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usage.String() {
		t.Fatalf("run without arguments: exit=%d", code)
	}
}

func TestUsageNamesTheEverydayCommands(t *testing.T) {
	var usage bytes.Buffer
	writeUsage(&usage)
	text := usage.String()
	for _, want := range []string{
		"usage: trestle init ",
		"       trestle   (in a terminal: this repository's status and next actions)\n",
		"usage: trestle review [--format text|json|sarif|markdown] [--all]",
		"       trestle review <path>   (review a local fixture file)\n",
		"usage: trestle keys [list]",
		"       trestle keys set OPEN_TRESTLE_PROVIDER_NAME",
		"       trestle keys remove OPEN_TRESTLE_PROVIDER_NAME",
		"usage: trestle usage ",
		"usage: trestle update [--check] [--yes]",
		"usage: trestle local-git submit-review --objects-root PATH",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("usage lacks %q:\n%s", want, text)
		}
	}
	for _, everyday := range []string{"trestle review [", "trestle update ["} {
		if strings.Index(text, everyday) > strings.Index(text, "trestle validate-fixture") {
			t.Fatalf("%s is not near the top of the usage text", everyday)
		}
	}
}
