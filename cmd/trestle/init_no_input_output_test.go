package main

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// With --no-input nothing is asked, so the output carries no keyboard hints
// and no step header without anything under it.
func TestInitNoInputPrintsNoPromptHintsOrEmptySteps(t *testing.T) {
	remoteScannerInstalled(t)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "local"})
	if result.code != initExitUsage {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	top, _, err := initGit(context.Background(), checkout, "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatal(err)
	}
	branch, _, err := initGit(context.Background(), checkout, "symbolic-ref", "-q", "--short", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	base := checkoutGit(t, checkout, "rev-parse", "refs/heads/base")[:12]
	head := checkoutGit(t, checkout, "rev-parse", "refs/heads/review")[:12]
	want := strings.Join([]string{
		`   |X|\            /|X|`,
		` __|X| \___----___/ |X|__   Open Trestle · setup`,
		"===|X|=|==|==|==|===|X|===",
		"",
		"  --no-input: every answer comes from a flag.",
		"",
		"●○○○○○○○  Step 1 of 8 · What will be reviewed",
		"─────────────────────────────────────────────",
		"  Repository: " + initDisplayPath(top) + "  (on branch " + branch + ")",
		"  Base:       refs/heads/base  (" + base + ")",
		"  Head:       refs/heads/review  (" + head + ")",
		"  Changes:    1 commit · 1 file changed, 1 insertion(+), 1",
		"              deletion(-)",
		"  Open Trestle compares exactly these two commits; it does",
		"  not fetch.",
		"",
		"●●○○○○○○  Step 2 of 8 · How a review works",
		"──────────────────────────────────────────",
		"  Open Trestle uses two AI models. The first reads your",
		"  change and lists possible problems; a second, different",
		"  model double-checks each one, and only confirmed findings",
		"  are reported. Setup sends none of your source anywhere: it",
		"  is sent to the models only when you run a review.",
		"",
		"●●●○○○○○  Step 3 of 8 · Where should the models run?",
		"────────────────────────────────────────────────────",
		"  Using: A model server on this machine (Ollama, llama.cpp,",
		"  vLLM, LM Studio)",
		"",
		"●●●●●○○○  Step 5 of 8 · API key",
		"───────────────────────────────",
		"  No key: requests to your local server are sent without",
		"  one.",
		"",
		"",
	}, "\n")
	if result.stdout != want {
		t.Fatalf("stdout differs.\ngot:\n%s\nwant:\n%s", result.stdout, want)
	}
	for _, missing := range []string{"--endpoint", "--generation-model", "--verification-model", "--context-tokens", "--output-tokens", "--declare-local-capabilities"} {
		if !initHas(result.stderr, "\n  "+missing+"\n") {
			t.Fatalf("stderr does not list %s:\n%s", missing, result.stderr)
		}
	}
	initAssertAbsent(t, dir)
}

var initStepHeader = regexp.MustCompile(`(?m)^[●○#.]+  Step \d of \d · .*\n─+\n`)

// A complete --no-input setup shows every step that has something to say, and
// only those.
func TestInitNoInputCompleteSetupHasNoEmptySteps(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"})
	if result.code != initExitDone {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	for _, unwanted := range []string{"Press Enter", "Ctrl-D", "[brackets]", "Step 4 of 8", "Step 7 of 8"} {
		if initHas(result.stdout, unwanted) {
			t.Fatalf("--no-input output contains %q:\n%s", unwanted, result.stdout)
		}
	}
	headers := initStepHeader.FindAllStringIndex(result.stdout, -1)
	for i, at := range headers {
		end := len(result.stdout)
		if i+1 < len(headers) {
			end = headers[i+1][0]
		}
		if strings.TrimSpace(result.stdout[at[1]:end]) == "" {
			t.Fatalf("a step header has nothing under it:\n%s", result.stdout)
		}
	}
	if got := len(headers); got != 6 {
		t.Fatalf("shown steps = %d, want 1, 2, 3, 5, 6 and 8:\n%s", got, result.stdout)
	}
}
