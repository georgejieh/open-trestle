package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Keys are the synthetic canaries remoteTestKey and initRefusedTestKey; the
// OpenRouter check goes to the offline keyCheckReport fake.

func runKeysCommand(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runKeys(context.Background(), args, strings.NewReader(stdin), &stdout, &stderr)
	for _, key := range []string{remoteTestKey, initRefusedTestKey} {
		if strings.Contains(stdout.String()+stderr.String(), key) {
			t.Fatalf("trestle keys %v printed a key:\n%s%s", args, stdout.String(), stderr.String())
		}
	}
	return code, stdout.String(), stderr.String()
}

func useKeyCheckReport(t *testing.T) *keyCheckReport {
	t.Helper()
	report := &keyCheckReport{}
	previous := usageOpenRouterTransport
	usageOpenRouterTransport = report
	t.Cleanup(func() { usageOpenRouterTransport = previous })
	return report
}

func TestKeysSetListAndRemove(t *testing.T) {
	keys := keyStoreForTest(t)
	clearSessionKeys(t)
	report := useKeyCheckReport(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "")
	t.Chdir(t.TempDir())
	code, out, _ := runKeysCommand(t, "")
	if code != 0 || !strings.Contains(out, "No API key is set or saved.") {
		t.Fatalf("empty list: exit=%d\n%s", code, out)
	}
	// A key OpenRouter refuses is not saved.
	code, _, errText := runKeysCommand(t, initRefusedTestKey+"\n", "set", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if code != 4 || !strings.Contains(errText, "OpenRouter refused this key (HTTP 401); nothing was saved") {
		t.Fatalf("refused key: exit=%d %s", code, errText)
	}
	if _, err := os.Lstat(filepath.Join(keys, "OPEN_TRESTLE_PROVIDER_OPENROUTER")); !os.IsNotExist(err) {
		t.Fatal("a refused key was saved")
	}
	// A piped key is read without a prompt, checked, and saved owner-only.
	code, out, errText = runKeysCommand(t, remoteTestKey+"\n", "set", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if code != 0 || !strings.Contains(out, "OpenRouter accepted the key") || !strings.Contains(out, "Saved the key for OPEN_TRESTLE_PROVIDER_OPENROUTER in") || strings.Contains(out, "(hidden)") {
		t.Fatalf("set: exit=%d\n%s%s", code, out, errText)
	}
	if len(report.bearers) != 2 || report.bearers[1] != remoteTestKey {
		t.Fatalf("checks: %d", len(report.bearers))
	}
	if !privateTestFile(t, filepath.Join(keys, "OPEN_TRESTLE_PROVIDER_OPENROUTER")) {
		t.Fatal("the saved key file is not private")
	}
	// A provider without a free check is saved with a note.
	code, out, _ = runKeysCommand(t, initRefusedTestKey+"\n", "set", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
	if code != 0 || !strings.Contains(out, "no call that checks a key for free") {
		t.Fatalf("unchecked set: exit=%d\n%s", code, out)
	}
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "environment-value-for-this-test-1234")
	code, out, _ = runKeysCommand(t, "")
	want := []string{
		"OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD  from the environment; a saved key exists too, and the environment wins · ends in …1234",
		"OPEN_TRESTLE_PROVIDER_OPENROUTER    saved in ",
		"· ends in …tial",
	}
	for _, line := range want {
		if code != 0 || !strings.Contains(out, line) {
			t.Fatalf("list lacks %q:\n%s", line, out)
		}
	}
	code, out, _ = runKeysCommand(t, "", "remove", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
	if code != 0 || !strings.Contains(out, "Removed the saved key for OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD.") || !strings.Contains(out, "still set in this shell") {
		t.Fatalf("remove: exit=%d\n%s", code, out)
	}
	code, out, _ = runKeysCommand(t, "", "remove", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
	if code != 0 || !strings.Contains(out, "No key is saved for OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD; nothing was changed.") {
		t.Fatalf("second remove: exit=%d\n%s", code, out)
	}
}

func TestKeysSetUsesHiddenInputOnATerminal(t *testing.T) {
	keyStoreForTest(t)
	clearSessionKeys(t)
	useKeyCheckReport(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	terminal := useFakeTerminal(t)
	code, out, errText := runKeysCommand(t, remoteTestKey+"\n", "set", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if code != 0 || !strings.Contains(out, "API key for OPEN_TRESTLE_PROVIDER_OPENROUTER (hidden):") {
		t.Fatalf("exit=%d\n%s%s", code, out, errText)
	}
	if _, hides, restores, _ := terminal.state(); hides != 1 || restores != 1 {
		t.Fatalf("hides=%d restores=%d", hides, restores)
	}
}

func TestKeysRefusesValuesAndUnusableNames(t *testing.T) {
	keyStoreForTest(t)
	for _, args := range [][]string{{"set", remoteTestKey}, {"set", "OPENAI_API_KEY"}, {"remove", "lowercase_name"}, {"set"}, {"rotate", "OPEN_TRESTLE_PROVIDER_X"}} {
		if code, _, _ := runKeysCommand(t, remoteTestKey+"\n", args...); code != 2 {
			t.Fatalf("%v: exit=%d", args[0], code)
		}
	}
	for _, input := range []string{"", "\n", "two words\n"} {
		if code, _, _ := runKeysCommand(t, input, "set", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD"); code != 2 {
			t.Fatalf("input %q: exit=%d", input, code)
		}
	}
}
