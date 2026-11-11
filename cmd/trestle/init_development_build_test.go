package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// initSetupChecks returns the rendered setup-check block of one wizard run.
func initSetupChecks(t *testing.T, stdout string) string {
	t.Helper()
	_, block, found := strings.Cut(stdout, "  Setup checks:\n")
	if !found {
		t.Fatalf("no setup checks were shown:\n%s", stdout)
	}
	block, _, _ = strings.Cut(block, "\n\n")
	return block
}

// A development build can save a remote setup, but its scanner check refuses
// remote egress. The first run must report the saved setup the way a re-run
// finds it, not as a refused setup to abandon.
func TestInitDevelopmentBuildReportsSavedRemoteSetup(t *testing.T) {
	flags := []string{"--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "--declare-remote-route"}
	for _, tc := range []struct {
		name   string
		args   []string
		script []string
	}{
		{name: "provider flag without input", args: append([]string{"--no-input"}, flags...)},
		{name: "set it up anyway", script: []string{
			"2", "y", // Ollama Cloud with a development build: set it up anyway
			"1", "2", // the two listed models
			"128000", "8192",
			"n",   // no per-token charge
			"",    // the proposed key variable, which is set
			"yes", // route declaration
			"",    // keep names
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := setupBootstrapScannerPrerequisite
			setupBootstrapScannerPrerequisite = func() error { return secretscan.ErrScannerDigestsMissing }
			t.Cleanup(func() { setupBootstrapScannerPrerequisite = previous })
			initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
			t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", remoteTestKey)
			checkout := remoteBootstrapCheckout(t)
			dir := filepath.Join(t.TempDir(), "setup")
			args := append([]string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"}, tc.args...)
			first := runInitScript(t, checkout, args, tc.script...)
			for _, unwanted := range []string{"setup was refused", "new --directory", "Some files were written"} {
				if initHas(first.stdout+first.stderr, unwanted) {
					t.Fatalf("a saved setup was reported as refused (%q): exit=%d\n%s\n%s", unwanted, first.code, first.stdout, first.stderr)
				}
			}
			for _, want := range []string{
				"✓ Saved protected configuration in",
				"✗ The secret scanner is installed",
				"Your setup is saved, but this development build cannot send source to Ollama Cloud.",
				"python3 tools/vulnerability_gate.py --staging .container",
				"/usr/local/bin/trestle init --directory " + initShellQuote(dir),
				"it finds this setup and re-checks it",
			} {
				if !initHas(first.stdout, want) {
					t.Fatalf("output lacks %q:\n%s", want, first.stdout)
				}
			}
			initAssertProtected(t, dir, "routes.json", "policy.json", "bootstrap.json", "NEXT-STEPS.txt")

			again := runInitScript(t, checkout, []string{"--no-input", "--directory", dir})
			if !initHas(again.stdout, "already has an Open Trestle setup") {
				t.Fatalf("the re-run did not find the saved setup:\n%s\n%s", again.stdout, again.stderr)
			}
			if again.code != first.code || initSetupChecks(t, again.stdout) != initSetupChecks(t, first.stdout) {
				t.Fatalf("first run and re-run disagree: exit %d and %d\nfirst:\n%s\nre-run:\n%s", first.code, again.code, first.stdout, again.stdout)
			}
			if !initHas(again.stdout, "Your setup is saved, but this development build cannot send source to Ollama Cloud.") {
				t.Fatalf("the re-run lacks the next step:\n%s", again.stdout)
			}
		})
	}
}
