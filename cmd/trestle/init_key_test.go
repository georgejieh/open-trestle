package main

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/spending"
)

// The keys below are synthetic canaries. OpenRouter's key report is an
// offline fake that accepts only remoteTestKey; no test reaches a provider.

const initRefusedTestKey = "synthetic-refused-key-not-a-real-credential"

// useFakeTerminal makes the wizard treat its scripted input as an
// interactive terminal whose echo can be turned off.
func useFakeTerminal(t *testing.T) *fakeEchoTerminal {
	t.Helper()
	terminal := newFakeEchoTerminal()
	terminal.hiddenSignal = make(chan struct{}, 64)
	previous := openEchoTerminal
	openEchoTerminal = func(io.Reader) (echoTerminal, bool) { return terminal, true }
	t.Cleanup(func() { openEchoTerminal = previous })
	return terminal
}

// keyCheckReport answers OpenRouter's GET /api/v1/key: 200 for
// remoteTestKey, 401 for any other bearer.
type keyCheckReport struct {
	mu      sync.Mutex
	bearers []string
}

func (k *keyCheckReport) RoundTrip(request *http.Request) (*http.Response, error) {
	bearer := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	k.mu.Lock()
	k.bearers = append(k.bearers, bearer)
	k.mu.Unlock()
	status, body := http.StatusUnauthorized, `{"error":{"message":"No auth credentials found"}}`
	if request.Method == http.MethodGet && request.URL.String() == spending.OpenRouterKeyURL && bearer == remoteTestKey {
		status, body = http.StatusOK, fakeKeyReportBody
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func initAssertKeyAbsent(t *testing.T, roots ...string) {
	t.Helper()
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return nil
			}
			if content, err := os.ReadFile(path); err == nil && (bytes.Contains(content, []byte(remoteTestKey)) || bytes.Contains(content, []byte(initRefusedTestKey))) {
				t.Errorf("%s holds a typed key", path)
			}
			return nil
		})
	}
}

func TestInitAsksForAMissingKeyHiddenChecksItAndSavesItAfterTheSetup(t *testing.T) {
	keys := keyStoreForTest(t)
	clearSessionKeys(t)
	spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	fakeOpenRouter(t, initOpenRouterModels()...)
	report := &keyCheckReport{}
	previous := usageOpenRouterTransport
	usageOpenRouterTransport = report
	t.Cleanup(func() { usageOpenRouterTransport = previous })
	terminal := useFakeTerminal(t)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "", "other/verifier",
		"",                 // require zero data retention
		initRefusedTestKey, // OpenRouter refuses it: asked again
		remoteTestKey,      // accepted
		"",                 // save it (the default)
		"",                 // no spending limit
		"",                 // use the settings shown
		"yes",              // consent
		"n",                // no review now
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	if strings.Contains(result.stdout+result.stderr, initRefusedTestKey) {
		t.Fatal("the refused key was printed")
	}
	initAssertOutput(t, result,
		"API key: OPEN_TRESTLE_PROVIDER_OPENROUTER has no key in this shell",
		"It stays hidden while you type",
		"API key for OpenRouter (hidden):",
		"✗ OpenRouter refused this key (OpenRouter answered with HTTP status 401).",
		"✓ OpenRouter accepted the key (one GET /api/v1/key, which costs nothing and sends no source).",
		"It will be saved in",
		"OpenRouter reports $0.08 used this month",
		"Key OPEN_TRESTLE_PROVIDER_OPENROUTER (to be saved",
		"✓ Saved the key for OPEN_TRESTLE_PROVIDER_OPENROUTER in",
		"✓ API key variable OPEN_TRESTLE_PROVIDER_OPENROUTER is set (saved in",
	)
	shown := strings.Join(strings.Fields(result.stdout), " ")
	if strings.Index(shown, "Saved protected configuration") > strings.Index(shown, "Saved the key for") {
		t.Fatal("the key was saved before the setup")
	}
	if len(report.bearers) < 2 || report.bearers[0] != initRefusedTestKey || report.bearers[1] != remoteTestKey {
		t.Fatalf("the key checks were not one GET per typed key: %d", len(report.bearers))
	}
	if _, hides, restores, readWhileShown := terminal.state(); hides != 2 || restores != 2 || readWhileShown {
		t.Fatalf("hidden reads: hides=%d restores=%d readWhileShown=%v", hides, restores, readWhileShown)
	}
	info, err := os.Lstat(filepath.Join(keys, "OPEN_TRESTLE_PROVIDER_OPENROUTER"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the saved key is not a 0600 file: %v", err)
	}
	if content, _ := os.ReadFile(filepath.Join(keys, "OPEN_TRESTLE_PROVIDER_OPENROUTER")); string(content) != remoteTestKey {
		t.Fatal("the store does not hold the accepted key")
	}
	initAssertKeyAbsent(t, dir)
	for _, name := range []string{"routes.json", "policy.json", "bootstrap.json"} {
		if !strings.Contains(stringMustRead(t, filepath.Join(dir, name)), "OPEN_TRESTLE_PROVIDER_OPENROUTER") && name != "routes.json" {
			t.Fatalf("%s no longer names the key variable", name)
		}
	}
}

func TestInitTypedKeyIsNotSavedWhenTheSetupIsDeclined(t *testing.T) {
	keys := keyStoreForTest(t)
	clearSessionKeys(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "")
	useFakeTerminal(t)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD"}
	result := runInitScript(t, checkout, args, remoteTestKey, "", "", "no")
	if result.code != initExitRefused || !initHas(result.stderr, "Nothing was written") {
		t.Fatalf("declined setup: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "Ollama Cloud has no call that checks a key for free, so the key is not checked now")
	if _, err := os.Lstat(keys); !os.IsNotExist(err) {
		t.Fatalf("a key was saved although the setup was declined: %v", err)
	}
	initAssertAbsent(t, dir)
}

func TestInitKeyForThisSessionOnlyRunsTheFirstReviewAndIsNotSaved(t *testing.T) {
	keys := keyStoreForTest(t)
	clearSessionKeys(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
	useFakeTerminal(t)
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}
	remoteModelClient(t, transport)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"}
	result := runInitScript(t, checkout, args, remoteTestKey, "n", "", "y")
	if result.code != initExitDone || len(transport.requests) != 2 {
		t.Fatalf("session key review: exit=%d requests=%v\n%s\n%s", result.code, transport.requests, result.stdout, result.stderr)
	}
	initAssertOutput(t, result,
		"The key is used for this session only.",
		"read -rs OPEN_TRESTLE_PROVIDER_REMOTE_TEST && export OPEN_TRESTLE_PROVIDER_REMOTE_TEST",
		"✓ API key variable OPEN_TRESTLE_PROVIDER_REMOTE_TEST is set (entered for this session only)",
		"Review finished")
	if _, err := os.Lstat(keys); !os.IsNotExist(err) {
		t.Fatal("a session-only key was saved")
	}
	initAssertKeyAbsent(t, dir)
}

// Without a terminal on standard input (a pipe, a script, CI), the wizard
// never asks for a key and keeps the environment-variable instructions.
func TestInitWithoutATerminalNeverAsksForTheKey(t *testing.T) {
	keyStoreForTest(t)
	clearSessionKeys(t)
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "")
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD"}
	result := runInitScript(t, checkout, args, "", "yes")
	if result.code != initExitPending || initHas(result.stdout, "(hidden)") {
		t.Fatalf("exit=%d\n%s", result.code, result.stdout)
	}
	initAssertOutput(t, result, "trestle keys set OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "read -rs OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD && export OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
}
