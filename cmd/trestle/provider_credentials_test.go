package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every key below is the synthetic canary remoteTestKey or another made-up
// value; none is a real credential.

const keyStoreTestVariable = "OPEN_TRESTLE_PROVIDER_REMOTE_TEST"

// keyStoreForTest gives the test its own credential folder.
func keyStoreForTest(t *testing.T) string {
	t.Helper()
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	return filepath.Join(config, "open-trestle", "credentials")
}

func saveTestKey(t *testing.T, name, key string) {
	t.Helper()
	store, err := providerCredentialStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(context.Background(), name, key); err != nil {
		t.Fatal(err)
	}
}

func clearSessionKeys(t *testing.T) {
	t.Helper()
	providerSessionKeys.Lock()
	providerSessionKeys.keys = map[string]string{}
	providerSessionKeys.Unlock()
	t.Cleanup(func() {
		providerSessionKeys.Lock()
		providerSessionKeys.keys = map[string]string{}
		providerSessionKeys.Unlock()
	})
}

func TestProviderKeyLookupReadsTheEnvironmentThenTheStoreThenTheSession(t *testing.T) {
	keyStoreForTest(t)
	clearSessionKeys(t)
	t.Setenv(keyStoreTestVariable, "")
	if value, state := providerKey(keyStoreTestVariable); value != "" || state.available() || state.where() != "not set" {
		t.Fatalf("no key anywhere: %q %q", value, state.where())
	}
	setProviderSessionKey(keyStoreTestVariable, "session-key-for-this-run")
	if value, state := providerKey(keyStoreTestVariable); value != "session-key-for-this-run" || state.where() != "entered for this session only" {
		t.Fatalf("session key: %q", state.where())
	}
	saveTestKey(t, keyStoreTestVariable, remoteTestKey)
	if value, state := providerKey(keyStoreTestVariable); value != remoteTestKey || state.source != providerKeyFromStore || !strings.HasPrefix(state.where(), "saved in ") {
		t.Fatalf("the store did not win over the session: %q", state.where())
	}
	t.Setenv(keyStoreTestVariable, "environment-key-wins")
	if value, state := providerKey(keyStoreTestVariable); value != "environment-key-wins" || state.where() != "from the environment" {
		t.Fatalf("the environment did not win: %q", state.where())
	}
	if providerCredentialLookup(keyStoreTestVariable) != "environment-key-wins" {
		t.Fatal("the resolver lookup differs from the key lookup")
	}
	// A variable outside OPEN_TRESTLE_PROVIDER_ is never read from the store.
	if value, state := providerKey("HOME"); value == "" || state.source != providerKeyFromEnvironment {
		t.Fatal("an ordinary environment variable was not read from the environment")
	}
}

func TestProviderKeyLookupReportsAnUnusableStoreWithoutUsingIt(t *testing.T) {
	dir := keyStoreForTest(t)
	clearSessionKeys(t)
	t.Setenv(keyStoreTestVariable, "")
	saveTestKey(t, keyStoreTestVariable, remoteTestKey)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	value, state := providerKey(keyStoreTestVariable)
	if value != "" || state.available() || !strings.Contains(state.where(), "the saved key cannot be used") || !strings.Contains(state.where(), "0700") {
		t.Fatalf("a 0755 credential folder was used (%v) or not explained: %q", value != "", state.where())
	}
	if strings.Contains(state.where(), remoteTestKey) {
		t.Fatal("the explanation carried the key")
	}
}

// A key saved in the credential store drives a real policy-approved review
// through the production session: the setup check finds it, the fake provider
// receives it only as the bearer credential (remoteModelTransport refuses a
// request whose body contains it), and it appears in no output, result, setup
// file or usage ledger.
func TestSavedKeyReachesOnlyTheAuthorizationHeader(t *testing.T) {
	keyStoreForTest(t)
	clearSessionKeys(t)
	store := spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv(keyStoreTestVariable, "")
	saveTestKey(t, keyStoreTestVariable, remoteTestKey)
	bootstrap, dir := remoteBootstrapArgs(t, "ollama-cloud")
	ready, _ := remoteBootstrapInvoke(t, bootstrap, 0)
	if !ready.Ready || len(ready.Pending) != 0 {
		t.Fatalf("the setup check did not find the saved key: %+v", ready)
	}
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}
	remoteModelClient(t, transport)
	for _, format := range []string{"json", "text", "sarif"} {
		var stdout, stderr bytes.Buffer
		code := run(replaceLocalGitChangeValue(ready.ReviewCommand[1:], "--format", format), &stdout, &stderr)
		// The fake confirms one high finding, which blocks (exit 4).
		if code != 4 || !strings.Contains(stdout.String(), "Zero-valued caller now panics") {
			t.Fatalf("%s review exit=%d\n%s\n%s", format, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
			t.Fatalf("the %s review printed the key", format)
		}
	}
	if len(transport.requests) != 6 {
		t.Fatalf("requests: %v", transport.requests)
	}
	for _, root := range []string{dir, store.Directory()} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			content, err := os.ReadFile(path)
			if err == nil && bytes.Contains(content, []byte(remoteTestKey)) {
				t.Errorf("%s holds the key", path)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
