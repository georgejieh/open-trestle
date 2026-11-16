package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/routehint"
	"github.com/georgejieh/open-trestle/internal/update"
)

// All Ollama daemons below are in-process loopback httptest servers with
// synthetic model lists. No test contacts a real Ollama daemon or Ollama Cloud.

// TestMain keeps every test in this package away from a real local Ollama
// daemon: by default the tags read finds no daemon, the sign-in probe fails,
// no ollama command is found and none is run. Tests that exercise the
// production readers install them explicitly against a fake daemon.
func TestMain(m *testing.M) {
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, bool, error) { return nil, false, errOllamaTagsUnavailable }
	ollamaSigninProbe = func(context.Context, string, string) (ollamaProbeOutcome, string) {
		return ollamaProbeFailed, "no daemon in tests"
	}
	ollamaLookPath = func() (string, error) { return "", errors.New("ollama is not installed in tests") }
	ollamaRunSigninChild = func(context.Context) error { return errors.New("ollama signin is not run in tests") }
	// OpenRouter's key report is never read over the network in tests; a test
	// that needs it installs a fake.
	usageOpenRouterTransport = offlineKeyTransport{}
	// No test reads this machine's package receipt, reaches GitHub, or runs
	// sudo, the installed trestle or a candidate archive; update tests install
	// fakes for each.
	updateReceiptPath = filepath.Join(os.TempDir(), "open-trestle-test-no-receipt", "receipt.json")
	updateTransport = offlineKeyTransport{}
	updateKeys = func() (update.KeyRing, error) { return nil, nil }
	updateRun = func(context.Context, updateCommand) (int, error) { return -1, errors.New("no program runs in tests") }
	updateSudoPaths = []string{filepath.Join(os.TempDir(), "open-trestle-test-no-sudo")}
	updateTrestlePath = filepath.Join(os.TempDir(), "open-trestle-test-no-trestle")
	updateDaemonRunning = func() bool { return false }
	// Reviews record their spend in the usage folder under XDG_STATE_HOME, so
	// every test of this package writes to a private temporary folder, never
	// to the operator's ~/.local/state. A test that inspects the ledger sets
	// its own folder with t.Setenv. Child processes of this test binary
	// inherit the folder instead of making their own.
	// Saved provider keys live under XDG_CONFIG_HOME, so no test reads or
	// writes the operator's ~/.config/open-trestle/credentials either.
	const marker = "OPEN_TRESTLE_TEST_STATE_FOLDER"
	if os.Getenv(marker) != "" {
		os.Exit(m.Run())
	}
	state, err := os.MkdirTemp("", "trestle-test-state-")
	if err != nil || os.Setenv("XDG_STATE_HOME", state) != nil || os.Setenv(marker, state) != nil {
		os.Exit(1)
	}
	config, err := os.MkdirTemp("", "trestle-test-config-")
	if err != nil || os.Setenv("XDG_CONFIG_HOME", config) != nil {
		os.Exit(1)
	}
	// The local update folder lives under XDG_DATA_HOME.
	data, err := os.MkdirTemp("", "trestle-test-data-")
	if err != nil || os.Setenv("XDG_DATA_HOME", data) != nil {
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(state)
	_ = os.RemoveAll(config)
	_ = os.RemoveAll(data)
	os.Exit(code)
}

func useRealOllamaTags(t *testing.T) {
	t.Helper()
	previous := ollamaReadTags
	ollamaReadTags = readOllamaDaemonTags
	t.Cleanup(func() { ollamaReadTags = previous })
}

func useRealOllamaProbe(t *testing.T) {
	t.Helper()
	previous := ollamaSigninProbe
	ollamaSigninProbe = probeOllamaSignin
	t.Cleanup(func() { ollamaSigninProbe = previous })
}

const (
	ollamaTestGenerator = "gpt-oss:120b-cloud"
	ollamaTestVerifier  = "qwen3.5:397b-cloud"
)

func ollamaFixtureTags() []map[string]any {
	return []map[string]any{
		{"name": ollamaTestGenerator, "model": ollamaTestGenerator, "remote_model": "gpt-oss:120b", "remote_host": "https://ollama.com", "details": map[string]any{"context_length": 131072}},
		{"name": ollamaTestVerifier, "model": ollamaTestVerifier, "remote_model": "qwen3.5:397b", "remote_host": "https://ollama.com", "details": map[string]any{"context_length": 262144}},
		{"name": "llama3.2:3b", "model": "llama3.2:3b", "details": map[string]any{"context_length": 131072}},
		{"name": "imposter:7b-cloud", "model": "imposter:7b-cloud", "details": map[string]any{}},
		{"name": "elsewhere:1b-cloud", "model": "elsewhere:1b-cloud", "remote_model": "elsewhere:1b", "remote_host": "https://other.example", "details": map[string]any{}},
	}
}

// ollamaFakeDaemon answers GET /api/tags and POST /v1/chat/completions on a
// loopback httptest server. Review requests are checked by the remote fixture
// transport; the fixed sign-in probe is answered directly.
type ollamaFakeDaemon struct {
	t         *testing.T
	server    *httptest.Server
	tags      []map[string]any
	transport *remoteModelTransport
	mu        sync.Mutex
	signedIn  bool
	probes    int
	refused   int
	chats     int
	// refusal, when set, answers every chat with that status and an Ollama
	// error body carrying ollamaRefusalText.
	refusal int
}

// ollamaRefusalText marks the provider's own message in a refusal body; it
// must never reach the wizard's output.
const ollamaRefusalText = "OLLAMA_REFUSAL_TEXT_3318"

func (d *ollamaFakeDaemon) setRefusal(status int) {
	d.mu.Lock()
	d.refusal = status
	d.mu.Unlock()
}

func newOllamaFakeDaemon(t *testing.T, tags []map[string]any, transport *remoteModelTransport) *ollamaFakeDaemon {
	t.Helper()
	d := &ollamaFakeDaemon{t: t, tags: tags, transport: transport, signedIn: true}
	d.server = httptest.NewServer(http.HandlerFunc(d.serve))
	t.Cleanup(d.server.Close)
	if transport != nil {
		transport.target = d.endpoint() + "/chat/completions"
	}
	return d
}

func (d *ollamaFakeDaemon) endpoint() string { return d.server.URL + "/v1" }

func (d *ollamaFakeDaemon) setSignedIn(value bool) {
	d.mu.Lock()
	d.signedIn = value
	d.mu.Unlock()
}

func (d *ollamaFakeDaemon) counts() (chats, probes, refused int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.chats, d.probes, d.refused
}

func (d *ollamaFakeDaemon) serve(w http.ResponseWriter, r *http.Request) {
	if _, present := r.Header["Authorization"]; present || r.Header.Get("Cookie") != "" {
		d.t.Error("a request to the local Ollama daemon carried a credential")
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/tags":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"models": d.tags})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/completions":
		body, err := io.ReadAll(io.LimitReader(r.Body, (8<<20)+1))
		_ = r.Body.Close()
		if err != nil {
			http.Error(w, "unreadable", http.StatusBadRequest)
			return
		}
		d.mu.Lock()
		d.chats++
		signedIn, refusal := d.signedIn, d.refusal
		if !signedIn {
			d.refused++
		}
		d.mu.Unlock()
		if refusal != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(refusal)
			_, _ = w.Write([]byte(`{"error":{"message":"Add usage credits or the model was retired on September 25, 2026 (ref: ` + ollamaRefusalText + `)","type":"api_error","param":null,"code":null}}`))
			return
		}
		if !signedIn {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		var probe struct {
			Model    string `json:"model"`
			Messages []struct{ Role, Content string }
		}
		if json.Unmarshal(body, &probe) == nil && len(probe.Messages) == 1 && probe.Messages[0].Content == ollamaSigninProbePrompt {
			d.mu.Lock()
			d.probes++
			d.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "probe", "object": "chat.completion", "model": probe.Model, "choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "OK"}, "finish_reason": "stop"}}})
			return
		}
		if d.transport == nil {
			d.t.Error("unexpected review request to the fake Ollama daemon")
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		forwarded := r.Clone(r.Context())
		forwarded.URL.Scheme, forwarded.URL.Host = "http", r.Host
		forwarded.Body = io.NopCloser(bytes.NewReader(body))
		response, err := d.transport.RoundTrip(forwarded)
		if err != nil {
			d.t.Errorf("review request refused by the fixture: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	default:
		d.t.Errorf("unexpected request to the fake Ollama daemon: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func ollamaSigninBootstrapArgs(t *testing.T, endpoint string) ([]string, string) {
	t.Helper()
	args, dir := remoteBootstrapArgs(t, "ollama-cloud")
	args = replaceLocalGitChangeValue(args, "--provider", ollamaSigninProvider)
	args = replaceLocalGitChangeValue(args, "--generation-model", ollamaTestGenerator)
	args = replaceLocalGitChangeValue(args, "--verification-model", ollamaTestVerifier)
	index := slices.Index(args, "--generation-credential-environment")
	args = slices.Delete(args, index, index+2)
	return append(args, "--endpoint", endpoint, "--declare-ollama-cloud-signin"), dir
}

// TestSetupBootstrapOllamaSigninPolicyApprovedReview proves the documented
// journey: init reads the daemon's tags, writes a private_remote route bound to
// the loopback daemon with no credential, and the printed review command sends
// sanitized generation and verification requests, without a key, to that daemon.
func TestSetupBootstrapOllamaSigninPolicyApprovedReview(t *testing.T) {
	remoteScannerInstalled(t)
	useRealOllamaTags(t)
	transport := &remoteModelTransport{t: t, anonymous: true, models: map[string]string{ollamaTestGenerator: "", ollamaTestVerifier: ""}}
	daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), transport)
	args, dir := ollamaSigninBootstrapArgs(t, daemon.endpoint())
	ready, _ := remoteBootstrapInvoke(t, args, 0)
	if !ready.Ready || ready.Provider != ollamaSigninProvider || len(ready.Pending) != 0 || len(ready.Refused) != 0 || !slices.Contains(ready.Limitations, "ollama_cloud_signin_not_verified_by_setup") || slices.Contains(ready.Limitations, "no_network_or_model_call_during_setup") {
		t.Fatalf("Ollama sign-in bootstrap not ready or mislabelled: %+v", ready)
	}
	if again, _ := remoteBootstrapInvoke(t, args, 0); again.Policy != ready.Policy || again.Inventory != ready.Inventory {
		t.Fatal("repeated init changed derived identities")
	}
	policy := stringMustRead(t, filepath.Join(dir, "policy.json"))
	for _, want := range []string{`"schema_version":7`, `"request_profile":"ollama_signin_chat_v1"`, `"credential_mode":"none"`, `"allowed_zones":["private_remote"]`, `"endpoint":"` + daemon.endpoint() + `"`} {
		if !strings.Contains(policy, want) {
			t.Fatalf("policy lacks %s: %s", want, policy)
		}
	}
	if strings.Contains(policy, "credential_environment") {
		t.Fatal("the Ollama sign-in policy named a credential")
	}
	routes := stringMustRead(t, filepath.Join(dir, "routes.json"))
	if !strings.Contains(routes, `"zone":"private_remote"`) || !strings.Contains(routes, `"provider_id":"ollama-signin"`) || strings.Contains(routes, `"zone":"local"`) {
		t.Fatalf("routes are not private_remote ollama-signin routes: %s", routes)
	}
	if evidence := initDecodedEvidence(t, routes); !strings.Contains(evidence, `"remote_host":"https://ollama.com"`) || !strings.Contains(evidence, "ollama_daemon_observation") {
		t.Fatalf("route evidence lacks the daemon observation: %s", evidence)
	}
	command := ready.ReviewCommand
	if !slices.Contains(command, "policy-approved") || slices.Contains(command, "local-only") {
		t.Fatal("review command does not use the sanitized policy-approved path")
	}
	var stdout, stderr bytes.Buffer
	code := run(replaceLocalGitChangeValue(command[1:], "--format", "json"), &stdout, &stderr)
	var receipt localModelReceipt
	if code != 4 || json.Unmarshal(stdout.Bytes(), &receipt) != nil {
		t.Fatalf("review exit=%d out=%s err=%s requests=%v", code, stdout.String(), stderr.String(), transport.requests)
	}
	if receipt.Status != "findings" || receipt.RunStatus != "succeeded" || receipt.Policy != ready.Policy || receipt.GenerationRoute == receipt.VerificationRoute || receipt.Independence != "distinct_model" {
		t.Fatalf("review did not complete with independent routes: %+v", receipt)
	}
	if !slices.Equal(transport.requests, []string{"candidate_generation:" + ollamaTestGenerator, "candidate_verification:" + ollamaTestVerifier}) {
		t.Fatalf("review did not use the two cloud models: %v", transport.requests)
	}
	if _, probes, _ := daemon.counts(); probes != 0 {
		t.Fatal("setup or review sent a sign-in probe")
	}
	// The local-only egress mode refuses this route even though its endpoint is loopback.
	var localOut, localErr bytes.Buffer
	code = run(replaceLocalGitChangeValue(replaceLocalGitChangeValue(command[1:], "--format", "json"), "--egress", "local-only"), &localOut, &localErr)
	var localReceipt localModelReceipt
	if json.Unmarshal(localOut.Bytes(), &localReceipt) != nil || localReceipt.Status != "refused" || len(transport.requests) != 2 {
		t.Fatalf("local-only egress ran the Ollama Cloud route: exit=%d out=%s requests=%v", code, localOut.String(), transport.requests)
	}
	daemon.server.Close()
	stopped, _ := remoteBootstrapInvoke(t, []string{"check", "--directory", dir}, 3)
	if stopped.Ready || !slices.Equal(stopped.Pending, []string{"ollama_cloud_models_listed"}) || !strings.Contains(strings.Join(stopped.Messages, " "), "ollama serve") {
		t.Fatalf("a stopped daemon was not a clear pending prerequisite: %+v", stopped)
	}
}

func TestSetupBootstrapOllamaSigninRefusals(t *testing.T) {
	remoteScannerInstalled(t)
	useRealOllamaTags(t)
	daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), nil)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedEndpoint := closed.URL + "/v1"
	closed.Close()
	without := func(args []string, name string) []string {
		index := slices.Index(args, name)
		return slices.Delete(slices.Clone(args), index, index+1)
	}
	for _, test := range []struct {
		name, reason string
		mutate       func([]string) []string
	}{
		{"missing sign-in declaration", "refusing to send source to Ollama Cloud without consent", func(a []string) []string { return without(a, "--declare-ollama-cloud-signin") }},
		{"non-cloud model", "is not an Ollama Cloud model", func(a []string) []string { return replaceLocalGitChangeValue(a, "--verification-model", "llama3.2:3b") }},
		{"cloud name the daemon runs locally", "not as an Ollama Cloud model", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--verification-model", "imposter:7b-cloud")
		}},
		{"cloud name relayed elsewhere", "not as an Ollama Cloud model", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--generation-model", "elsewhere:1b-cloud")
		}},
		{"unlisted model", "is not listed by the Ollama daemon", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--generation-model", "kimi-k2:1t-cloud")
		}},
		{"same model", "must differ", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--verification-model", ollamaTestGenerator)
		}},
		{"credential variable", "sends no key", func(a []string) []string {
			return append(a, "--generation-credential-environment", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST")
		}},
		{"remote endpoint", "must be exactly http://127.0.0.1:PORT/v1", func(a []string) []string { return replaceLocalGitChangeValue(a, "--endpoint", "https://ollama.com/v1") }},
		{"ipv6 loopback endpoint", "must be exactly http://127.0.0.1:PORT/v1", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--endpoint", "http://[::1]:11434/v1")
		}},
		{"daemon not running", "no Ollama model list could be read", func(a []string) []string { return replaceLocalGitChangeValue(a, "--endpoint", closedEndpoint) }},
		{"witness flag", "does not apply", func(a []string) []string {
			return append(a, "--account-evidence", "https://evidence.fixture.invalid/account,"+remoteTestDigest)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, dir := ollamaSigninBootstrapArgs(t, daemon.endpoint())
			result, stderr := remoteBootstrapInvoke(t, test.mutate(args), 4)
			if result.Ready || result.Status != "refused" || !strings.Contains(strings.Join(result.Messages, " "), test.reason) || !strings.Contains(stderr, test.reason) {
				t.Fatalf("refusal lacked clear reason %q: %+v %s", test.reason, result, stderr)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatal("refused init wrote configuration")
			}
		})
	}
	if chats, _, _ := daemon.counts(); chats != 0 {
		t.Fatal("bootstrap sent a model request")
	}
}

// TestSetupBootstrapLocalRefusesOllamaCloudModels proves the local route
// refuses a model the local Ollama relays to Ollama Cloud: by the daemon's
// remote_host when it lists the model, and by the cloud name suffix when no
// model list can be read.
func TestSetupBootstrapLocalRefusesOllamaCloudModels(t *testing.T) {
	invoke := func(t *testing.T, args []string, want int) string {
		t.Helper()
		var out, errOut bytes.Buffer
		code := runSetupWithClock(append([]string{"bootstrap"}, args...), &out, &errOut, fixedSetupClock{setupTimeCLI()})
		var result setupBootstrapResult
		if code != want || json.Unmarshal(out.Bytes(), &result) != nil {
			t.Fatalf("bootstrap code=%d want=%d out=%s err=%s", code, want, out.String(), errOut.String())
		}
		return errOut.String()
	}
	for _, test := range []struct{ name, flag, model string }{
		{"-cloud name without a model list", "--generation-model", "gpt-oss:20b-cloud"},
		{":cloud name without a model list", "--verification-model", "deepseek-v4-pro:cloud"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, dir, _, _ := bootstrapFixture(t)
			stderr := invoke(t, replaceLocalGitChangeValue(args, test.flag, test.model), 4)
			if !strings.Contains(stderr, test.model+": "+ollamaCloudLocalRefusal) {
				t.Fatalf("local route did not refuse %s clearly: %s", test.model, stderr)
			}
			initAssertAbsent(t, filepath.Join(dir, "routes.json"))
		})
	}
	t.Run("remote_host in the daemon's model list", func(t *testing.T) {
		useRealOllamaTags(t)
		daemon := newOllamaFakeDaemon(t, []map[string]any{{"name": "tuned:latest", "model": "tuned:latest", "remote_model": "tuned", "remote_host": "https://ollama.com"}}, nil)
		args, dir, _, _ := bootstrapFixture(t)
		args = replaceLocalGitChangeValue(replaceLocalGitChangeValue(args, "--generation-endpoint", daemon.endpoint()), "--generation-model", "tuned")
		stderr := invoke(t, args, 4)
		if !strings.Contains(stderr, "tuned: "+ollamaCloudLocalRefusal) {
			t.Fatalf("local route did not refuse a remote_host model without a cloud name: %s", stderr)
		}
		initAssertAbsent(t, filepath.Join(dir, "routes.json"))
		if chats, _, _ := daemon.counts(); chats != 0 {
			t.Fatal("the local check sent a model request")
		}
	})
	t.Run("a model the daemon runs locally passes", func(t *testing.T) {
		useRealOllamaTags(t)
		daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), nil)
		args, dir, _, _ := bootstrapFixture(t)
		// Both roles point at the fake daemon, so neither tags read reaches a model fixture.
		args = replaceLocalGitChangeValue(replaceLocalGitChangeValue(args, "--generation-endpoint", daemon.endpoint()), "--generation-model", "llama3.2:3b")
		args = replaceLocalGitChangeValue(args, "--verification-endpoint", daemon.endpoint())
		if stderr := invoke(t, args, 3); stderr != "" {
			t.Fatalf("a local model was refused: %s", stderr)
		}
		if _, err := os.Stat(filepath.Join(dir, "routes.json")); err != nil {
			t.Fatal("the local bootstrap did not write its configuration")
		}
	})
}

// TestInitOllamaSigninNotSignedInThenConsentedSigninRechecks walks the wizard
// option: only cloud models are offered, the one synthetic test message is
// sent only with consent, an authentication answer offers `ollama signin`
// (run only on y), the same message is sent once more, and the first review
// goes to the daemon with no key.
func TestInitOllamaSigninNotSignedInThenConsentedSigninRechecks(t *testing.T) {
	remoteScannerInstalled(t)
	useRealOllamaTags(t)
	useRealOllamaProbe(t)
	transport := &remoteModelTransport{t: t, anonymous: true, models: map[string]string{ollamaTestGenerator: "", ollamaTestVerifier: ""}}
	daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), transport)
	daemon.setSignedIn(false)
	previousLook, previousRun := ollamaLookPath, ollamaRunSigninChild
	signins := 0
	ollamaLookPath = func() (string, error) { return "/fixture/bin/ollama", nil }
	ollamaRunSigninChild = func(context.Context) error {
		signins++
		daemon.setSignedIn(true)
		return nil
	}
	t.Cleanup(func() { ollamaLookPath, ollamaRunSigninChild = previousLook, previousRun })
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--endpoint", daemon.endpoint()},
		"5",           // Ollama on this machine, signed in to Ollama Cloud
		"1",           // finder: the first listed cloud model
		"llama3.2:3b", // a local model is not offered: must re-prompt
		"2",           // checker
		"y",           // send the one test message
		"y",           // run ollama signin
		"", "8192",    // accept the listed context; output limit
		"n",   // the plan does not charge per token
		"",    // use the settings shown
		"yes", // route declaration
		"yes", // Ollama Cloud sign-in declaration
		"y",   // run the first review
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	for _, want := range []string{"The ollama command is installed", "Found 2 Ollama Cloud models", "llama3.2:3b is not one of the Ollama Cloud models", "uses your Ollama Cloud usage", "not signed in to Ollama Cloud (HTTP 401)", "ollama signin finished", "Your local Ollama is signed in", "No API key", "Your local Ollama lists both models as Ollama Cloud models", "A review sends the selected source to Ollama Cloud through your signed-in local Ollama (" + daemon.endpoint() + ")", "Review finished: 1 confirmed finding"} {
		if !initHas(result.stdout, want) {
			t.Fatalf("output lacks %q:\n%s", want, result.stdout)
		}
	}
	for _, unwanted := range []string{"imposter:7b-cloud", "elsewhere:1b-cloud", "API key variable"} {
		if initHas(result.stdout, unwanted) {
			t.Fatalf("output offered or mentioned %q:\n%s", unwanted, result.stdout)
		}
	}
	if _, probes, refused := daemon.counts(); signins != 1 || probes != 1 || refused != 1 {
		t.Fatalf("sign-in check: signins=%d probes=%d unauthorized=%d (want 1 each)", signins, probes, refused)
	}
	if !slices.Equal(transport.requests, []string{"candidate_generation:" + ollamaTestGenerator, "candidate_verification:" + ollamaTestVerifier}) {
		t.Fatalf("review did not use the two chosen models: %v", transport.requests)
	}
	initAssertProtected(t, dir, "routes.json", "policy.json", "bootstrap.json", "NEXT-STEPS.txt")
	if policy := stringMustRead(t, filepath.Join(dir, "policy.json")); strings.Contains(policy, "credential_environment") || !strings.Contains(policy, "ollama_signin_chat_v1") {
		t.Fatal("the wizard wrote a credential or lost the profile")
	}
}

// The sign-in check names a provider refusal by its status alone, the same
// way a review does, and never reads or repeats the provider's message.
func TestOllamaSigninProbeNamesProviderRefusals(t *testing.T) {
	daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), nil)
	for _, test := range []struct {
		status  int
		outcome ollamaProbeOutcome
		detail  string
		class   string
	}{
		{http.StatusPaymentRequired, ollamaProbePaymentRequired, "HTTP 402", "provider_payment_required"},
		{http.StatusNotFound, ollamaProbeModelUnavailable, "HTTP 404", "provider_model_unavailable"},
		{http.StatusGone, ollamaProbeModelRetired, "HTTP 410", "provider_model_retired"},
	} {
		daemon.setRefusal(test.status)
		outcome, detail := probeOllamaSignin(context.Background(), daemon.endpoint(), ollamaTestGenerator)
		if outcome != test.outcome || detail != test.detail {
			t.Fatalf("status %d = (%d, %q)", test.status, outcome, detail)
		}
		wantDetail, wantHint, _ := routehint.ProviderRefusal(ollamaProbeRefusalClass[outcome])
		if wantDetail != test.class || ollamaProbeRefusalHint(outcome) != wantHint || wantHint == "" {
			t.Fatalf("status %d names %q with hint %q", test.status, wantDetail, ollamaProbeRefusalHint(outcome))
		}
	}
}

// A sign-in check that Ollama Cloud refuses for billing prints the review's
// payment hint and offers to continue; a retired model stops before anything
// is written, with the review's retired-model hint.
func TestInitOllamaSigninReportsProviderRefusals(t *testing.T) {
	remoteScannerInstalled(t)
	useRealOllamaTags(t)
	useRealOllamaProbe(t)
	_, payment, _ := routehint.ProviderRefusal(gateway.RouteFailurePaymentRequired)
	_, retired, _ := routehint.ProviderRefusal(gateway.RouteFailureModelRetired)
	for _, test := range []struct {
		name   string
		status int
		script []string
		want   []string
	}{
		{"payment required", http.StatusPaymentRequired, []string{"5", "1", "2", "y", "n"}, []string{"Ollama Cloud refused the test message for billing (HTTP 402):", payment, "Add credit or a subscription to your Ollama account. Then run `trestle init` again, or continue now and add it before the first review."}},
		{"model retired", http.StatusGone, []string{"5", "1", "2", "y"}, []string{"Ollama Cloud does not serve " + ollamaTestGenerator + " (HTTP 410):", retired}},
	} {
		t.Run(test.name, func(t *testing.T) {
			daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), nil)
			daemon.setRefusal(test.status)
			checkout := remoteBootstrapCheckout(t)
			dir := filepath.Join(t.TempDir(), "setup")
			result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--endpoint", daemon.endpoint()}, test.script...)
			output := result.stdout + result.stderr
			if result.code != initExitPending {
				t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
			}
			for _, want := range test.want {
				if !strings.Contains(strings.Join(strings.Fields(output), " "), strings.Join(strings.Fields(want), " ")) {
					t.Fatalf("output lacks %q:\n%s", want, output)
				}
			}
			for _, forbidden := range []string{ollamaRefusalText, "usage credits", "September 25"} {
				if strings.Contains(output, forbidden) {
					t.Fatalf("output repeated the provider's message %q:\n%s", forbidden, output)
				}
			}
			if chats, _, _ := daemon.counts(); chats != 1 {
				t.Fatalf("sign-in check sent %d messages", chats)
			}
			initAssertAbsent(t, dir)
		})
	}
}

func TestInitOllamaSigninSendsNothingWithoutConsent(t *testing.T) {
	remoteScannerInstalled(t)
	useRealOllamaTags(t)
	useRealOllamaProbe(t)
	daemon := newOllamaFakeDaemon(t, ollamaFixtureTags(), nil)
	daemon.setSignedIn(false)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--endpoint", daemon.endpoint()},
		"5", "1", "2",
		"n", // do not send the test message
	)
	if result.code != initExitUsage || !initHas(result.stdout, "The ollama command was not found on PATH") || !initHas(result.stdout, "Not checked.") {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	if chats, _, _ := daemon.counts(); chats != 0 {
		t.Fatal("a chat request was sent without consent")
	}
	initAssertAbsent(t, dir)
}

func TestInitLocalRefusesOllamaCloudModel(t *testing.T) {
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "local", "--endpoint", "http://127.0.0.1:9/v1", "--verification-endpoint", "http://127.0.0.1:9/v1", "--generation-model", "gpt-oss:20b-cloud", "--verification-model", "llama3.2:3b"})
	if result.code != initExitUsage || !initHas(result.stderr, "gpt-oss:20b-cloud: "+ollamaCloudLocalRefusal) {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertAbsent(t, dir)
}

func TestOllamaTagsReaderIsBoundedToLoopbackTagsDocuments(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"not found":           http.NotFound,
		"not a tags document": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://ollama.com/api/tags", http.StatusFound)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte(" "), ollamaTagsMaxBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			if _, _, err := readOllamaDaemonTags(context.Background(), server.URL+"/v1"); !errors.Is(err, errOllamaTagsUnavailable) {
				t.Fatalf("tags reader accepted %s: %v", name, err)
			}
		})
	}
	for _, endpoint := range []string{"https://ollama.com/v1", "http://localhost:11434/v1", "http://192.0.2.1:11434/v1"} {
		if _, _, err := readOllamaDaemonTags(context.Background(), endpoint); !errors.Is(err, errOllamaTagsUnavailable) {
			t.Fatalf("tags reader contacted a non-loopback address %s", endpoint)
		}
	}
}
