package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/modelcatalog"
)

// Every provider, account, evidence and model value below is a synthetic offline
// fixture. Remote model lists and model requests go to in-process fakes; the
// local path uses loopback httptest servers only.

type initRun struct {
	code           int
	stdout, stderr string
}

// initOfflineTransport answers every setup fetch with an error, so a test
// that installs no fake never reaches the network.
type initOfflineTransport struct{}

func (initOfflineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

// runInitScript runs the wizard for a test of the single general review: it
// adds --specialists none unless the test chose specialists itself.
// runInitScriptAsIs keeps the wizard's own default.
func runInitScript(t *testing.T, checkout string, args []string, script ...string) initRun {
	t.Helper()
	if !slices.Contains(args, "--specialists") {
		args = append(append([]string(nil), args...), "--specialists", "none")
	}
	return runInitScriptAsIs(t, checkout, args, script...)
}

func runInitScriptAsIs(t *testing.T, checkout string, args []string, script ...string) initRun {
	t.Helper()
	t.Chdir(checkout)
	if initEvidenceTransport == nil {
		initEvidenceTransport = initOfflineTransport{}
		defer func() { initEvidenceTransport = nil }()
	}
	// No test reaches a real model server on this machine's default ports.
	previousDetect := initDetectLocalServers
	initDetectLocalServers = func(context.Context) []initLocalServer { return initFakeLocalServers }
	defer func() { initDetectLocalServers = previousDetect }()
	var stdout, stderr bytes.Buffer
	input := strings.Join(script, "\n")
	if len(script) != 0 {
		input += "\n"
	}
	code := runInitWithClock(context.Background(), args, strings.NewReader(input), &stdout, &stderr, systemSetupClock{})
	result := initRun{code, stdout.String(), stderr.String()}
	if initHas(result.stdout+result.stderr, remoteTestKey) {
		t.Fatal("init output disclosed a credential value")
	}
	// Every wizard run, in every test, stays within the shown width.
	initAssertWidth(t, result.stdout)
	initAssertWidth(t, result.stderr)
	return result
}

// initFakeLocalServers are the local servers the wizard's detection finds in
// a test; none unless a test sets them.
var initFakeLocalServers []initLocalServer

// initHas reports whether text contains want once line wrapping is undone:
// every run of spaces and line breaks counts as one space.
func initHas(text, want string) bool {
	return strings.Contains(strings.Join(strings.Fields(text), " "), strings.Join(strings.Fields(want), " "))
}

func initFakeModelList(t *testing.T, models ...string) *[]string {
	t.Helper()
	calls := &[]string{}
	previous := initListModels
	initListModels = func(_ context.Context, source modelcatalog.Source, allowRemote bool, resolver modelcatalog.CredentialResolver) ([]modelcatalog.Model, error) {
		if (source.CredentialEnvironment != "") != (resolver != nil) {
			t.Error("a credential variable was named without a resolver, or a resolver was passed without one")
		}
		call := source.URL
		if source.CredentialEnvironment != "" {
			call += " with " + source.CredentialEnvironment
		}
		*calls = append(*calls, call)
		listed := []modelcatalog.Model{}
		for _, model := range models {
			listed = append(listed, modelcatalog.Model{Selector: model, Metadata: json.RawMessage(`{"name":"` + model + `"}`)})
		}
		return listed, nil
	}
	t.Cleanup(func() { initListModels = previous })
	return calls
}

func initAssertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s was created: %v", path, err)
	}
}

func initAssertProtected(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if !privateTestFile(t, filepath.Join(dir, name)) {
			t.Fatalf("%s is not a protected file", name)
		}
	}
}

// initFakeEvidencePages serves public evidence pages through the wizard's fetch
// transport and refuses any request carrying a credential, cookie or query.
type initFakeEvidencePages struct {
	t        *testing.T
	pages    map[string]string
	requests []string
}

func (f *initFakeEvidencePages) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody {
		f.t.Errorf("evidence fetch sent more than a plain GET: %s %s", request.Method, request.URL)
	}
	f.requests = append(f.requests, request.URL.String())
	response := &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}
	if page, ok := f.pages[request.URL.String()]; ok {
		if target, redirect := strings.CutPrefix(page, "redirect:"); redirect {
			response.StatusCode, response.Header = http.StatusFound, http.Header{"Location": []string{target}}
		} else {
			response.StatusCode, response.Body = http.StatusOK, io.NopCloser(strings.NewReader(page))
		}
	}
	return response, nil
}

func initFakeEvidence(t *testing.T, pages map[string]string) *initFakeEvidencePages {
	t.Helper()
	fake := &initFakeEvidencePages{t: t, pages: pages}
	previous := initEvidenceTransport
	initEvidenceTransport = fake
	t.Cleanup(func() { initEvidenceTransport = previous })
	return fake
}

func initSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func initDecodedEvidence(t *testing.T, routes string) string {
	t.Helper()
	var inventory struct {
		Routes []struct {
			Manifest []byte `json:"evidence_manifest_base64"`
		} `json:"routes"`
	}
	if json.Unmarshal([]byte(routes), &inventory) != nil || len(inventory.Routes) == 0 {
		t.Fatal("routes.json is not readable")
	}
	return string(inventory.Routes[0].Manifest)
}

// initLocalModelServers wraps the local model fixture with loopback servers that also
// answer GET /v1/models, so the wizard's probe sees exactly one model per server.
// With packed set, the checkout is an ordinary `git clone --no-local` of the
// fixture: objects in a pack file, objects folder mode 0755.
// A generation mode, when given, selects how the first server answers.
func initLocalModelServers(t *testing.T, packed bool, generationMode ...string) (string, string, string, *localModelFixture) {
	t.Helper()
	f := newLocalModelFixture(t, localModelFixtureOptions{noAuth: true, chatCompletions: true, generationMode: strings.Join(generationMode, "")})
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init")
	if err := os.CopyFS(filepath.Join(checkout, ".git", "objects"), os.DirFS(f.objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "update-ref", "refs/heads/base", f.base)
	checkoutGit(t, checkout, "update-ref", "refs/heads/review", f.head)
	mode := os.FileMode(0o700)
	if packed {
		checkoutGit(t, checkout, "symbolic-ref", "HEAD", "refs/heads/review")
		clone := filepath.Join(t.TempDir(), "clone")
		checkoutGit(t, checkout, "clone", "--quiet", "--no-local", "--no-hardlinks", checkout, clone)
		checkoutGit(t, clone, "update-ref", "refs/heads/base", "refs/remotes/origin/base")
		checkout, mode = clone, 0o755
		if packs, _ := filepath.Glob(filepath.Join(clone, ".git", "objects", "pack", "*.pack")); len(packs) == 0 {
			t.Fatal("the clone has no pack file")
		}
		if _, err := os.Lstat(filepath.Join(clone, ".git", "objects", f.head[:2], f.head[2:])); !os.IsNotExist(err) {
			t.Fatal("the clone kept the head commit loose")
		}
	}
	if err := os.Chmod(filepath.Join(checkout, ".git", "objects"), mode); err != nil {
		t.Fatal(err)
	}
	urls := []string{}
	for _, endpoint := range []*localModelEndpoint{f.generation, f.verification} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/v1/models" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []any{map[string]any{"id": endpoint.model, "object": "model", "max_model_len": 128000}}})
				return
			}
			endpoint.serve(t, w, r)
		}))
		t.Cleanup(server.Close)
		urls = append(urls, server.URL+"/v1")
	}
	return checkout, urls[0], urls[1], f
}

func TestInitLocalServerProbedModelsThroughFirstReview(t *testing.T) {
	for _, packed := range []bool{false, true} {
		t.Run(map[bool]string{false: "private loose objects", true: "ordinary packed clone"}[packed], func(t *testing.T) {
			t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
			t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "")
			checkout, generation, verification, f := initLocalModelServers(t, packed)
			objects := filepath.Join(checkout, ".git", "objects")
			before, err := os.Stat(objects)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), "setup")
			result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
				"4",             // a model server on this machine
				"5", generation, // another address
				"1",               // the only listed model
				"5", verification, // the second server
				"1",
				"",    // use the settings shown
				"yes", // local capabilities
				"n",   // no synthetic test requests
				"y",
			)
			if result.code != initExitDone {
				t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
			}
			for _, want := range []string{"Found 1 model.", "model-a  (context 128000)", "This server offers one model", "Limits: context 32768 and output 4096 tokens; start both servers with this context length", "✓ Model configuration approved", "✓ Dry run without models", "– Test requests to both models (optional; not sent)", "– Background-service tokens and backup", "Ready for the first review", "Review finished"} {
				if !initHas(result.stdout, want) {
					t.Fatalf("output lacks %q:\n%s", want, result.stdout)
				}
			}
			if initHas(result.stdout, "OPEN_TRESTLE_API_TOKEN") {
				t.Fatal("the direct review asked for daemon tokens")
			}
			if calls, _ := f.generation.snapshot(); calls != 1 {
				t.Fatalf("finder server received %d model requests", calls)
			}
			if calls, _ := f.verification.snapshot(); calls != 1 {
				t.Fatalf("checker server received %d model requests", calls)
			}
			initAssertProtected(t, dir, "routes.json", "policy.json", "bootstrap.json", "NEXT-STEPS.txt")
			if policy := stringMustRead(t, filepath.Join(dir, "policy.json")); !strings.Contains(policy, generation) || !strings.Contains(policy, verification) || !strings.Contains(policy, "openai_chat_completions") {
				t.Fatal("policy lost the chosen local servers or transport")
			}
			if manifest := stringMustRead(t, filepath.Join(dir, "bootstrap.json")); !strings.Contains(manifest, `"scope":"direct-review"`) || !strings.Contains(manifest, `"launch_command":null`) {
				t.Fatalf("the wizard did not record a direct-review setup: %s", manifest)
			}
			if next := stringMustRead(t, filepath.Join(dir, "NEXT-STEPS.txt")); !strings.Contains(next, "--scope direct-review") {
				t.Fatal("NEXT-STEPS.txt check command lost the direct-review scope")
			}
			after, err := os.Stat(objects)
			if err != nil || after.Mode() != before.Mode() {
				t.Fatalf("the wizard changed the objects folder: %v -> %v (%v)", before.Mode(), after.Mode(), err)
			}
		})
	}
}

// TestInitDevelopmentBuildExplainsScannerAndOffersLocal checks that a build
// without a pinned helper explains the scanner before the provider question
// and asks before it sets up any provider, a local one included, since every
// review needs the scanner.
func TestInitDevelopmentBuildExplainsScannerAndOffersLocal(t *testing.T) {
	previous := setupBootstrapScannerPrerequisite
	setupBootstrapScannerPrerequisite = func() error { return secretscan.ErrHelperNotPinned }
	t.Cleanup(func() { setupBootstrapScannerPrerequisite = previous })
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"}, "1", "n", "4", "y")
	if result.code != initExitUsage || !initHas(result.stderr, "input ended") {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	provider := result.stdout[strings.Index(result.stdout, "Step 2 of 6"):]
	wants := []string{"development build has no secret scanner", "secret-scanned before it", "python3 tools/package_secret_scanner.py --development DIR", "DIR/bin/trestle init", "This build cannot send source to OpenRouter", "This build cannot send source to your local model server", "Using: A model server on this machine"}
	if runtime.GOOS == "linux" {
		wants = append(wants, "python3 tools/package_secret_scanner.py --output .container", "sudo ./open-trestle-linux-amd64.pyz install", "/usr/local/bin/trestle init")
	}
	for _, want := range wants {
		if !initHas(provider, want) {
			t.Fatalf("step 2 lacks %q:\n%s", want, provider)
		}
	}
	if initHas(provider, "packaged build]") {
		t.Fatalf("a provider is still labelled as needing the packaged build:\n%s", provider)
	}
	if strings.Index(provider, "secret-scanned before it") > strings.Index(provider, "1) OpenRouter") {
		t.Fatal("the scanner explanation came after the provider question")
	}
	initAssertAbsent(t, dir)
}

// Scripted answers are not echoed, so a prompt and the next output share a
// captured line; the width check measures each part separately.
var initPromptEnd = regexp.MustCompile(`: {2,}|\((?:y/N|Y/n|1-\d+)\): |Type yes or no: `)

func TestInitUnreadableObjectStorageStopsBeforeQuestions(t *testing.T) {
	source := remoteBootstrapCheckout(t)
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init")
	alternates := filepath.Join(checkout, ".git", "objects", "info", "alternates")
	if err := os.WriteFile(alternates, []byte(filepath.Join(source, ".git", "objects")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"base", "review"} {
		checkoutGit(t, checkout, "update-ref", "refs/heads/"+ref, checkoutGit(t, source, "rev-parse", "refs/heads/"+ref))
	}
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"})
	if result.code != initExitRefused || !initHas(result.stderr, "cannot read the selected commits") || !initHas(result.stderr, "git clone --no-local --no-hardlinks") || initHas(result.stdout, "Step 2 of 6") {
		t.Fatalf("exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertAbsent(t, dir)
}

func TestInitFetchEvidenceIsBoundedAndPublicOnly(t *testing.T) {
	big := strings.Repeat("x", initEvidenceMaxBytes+1)
	pages := initFakeEvidence(t, map[string]string{
		"https://docs.fixture.example/zdr":   "reviewed page",
		"https://docs.fixture.example/moved": "redirect:https://docs.fixture.example/zdr",
		"https://docs.fixture.example/plain": "redirect:http://docs.fixture.example/zdr",
		"https://docs.fixture.example/big":   big,
	})
	ctx := context.Background()
	got, err := initFetchEvidence(ctx, "https://docs.fixture.example/zdr")
	if err != nil || got.digest != initSHA256("reviewed page") || got.size != int64(len("reviewed page")) || got.url != "https://docs.fixture.example/zdr" {
		t.Fatalf("fetch = %+v, %v", got, err)
	}
	if moved, err := initFetchEvidence(ctx, "https://docs.fixture.example/moved"); err != nil || moved.url != "https://docs.fixture.example/zdr" || moved.digest != got.digest {
		t.Fatalf("redirected fetch = %+v, %v", moved, err)
	}
	for location, want := range map[string]string{
		"https://docs.fixture.example/plain":   "https://",
		"https://docs.fixture.example/big":     "8 MiB",
		"https://docs.fixture.example/missing": "status 404",
	} {
		if _, err := initFetchEvidence(ctx, location); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: err=%v, want %q", location, err, want)
		}
	}
	count := len(pages.requests)
	for _, refused := range []string{"http://docs.fixture.example/zdr", "https://docs.fixture.example/zdr?x=1", "https://user@docs.fixture.example/zdr", "https://docs.fixture.example/zdr#part", "https://127.0.0.1/zdr", "https://10.1.2.3/zdr", "https://[::1]/zdr", "https://localhost/zdr", "https://intranet/zdr"} {
		if _, err := initFetchEvidence(ctx, refused); err == nil {
			t.Fatalf("fetched a non-public or unrecordable address %s", refused)
		}
	}
	if len(pages.requests) != count {
		t.Fatalf("a refused address was requested: %v", pages.requests[count:])
	}
}

func TestInitDisplayPathShortensForReadingOnly(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		t.Skip("no home folder")
	}
	short := filepath.Join(home, "project")
	if got := initDisplayPath(short); got != "~"+string(filepath.Separator)+"project" {
		t.Fatalf("short path = %q", got)
	}
	long := filepath.Join(home, strings.Repeat("nested-folder/", 8), "setup-a1b2c3d4")
	got := initDisplayPath(long)
	if !strings.HasPrefix(got, "~/") || !strings.Contains(got, "/.../") || !strings.HasSuffix(got, "/setup-a1b2c3d4") || len([]rune(got)) > initDisplayPathLimit+2 {
		t.Fatalf("long path = %q", got)
	}
	if other := "/srv/" + strings.Repeat("x", 80); len([]rune(initDisplayPath(other))) > initDisplayPathLimit+2 {
		t.Fatalf("a path without separators was not shortened: %q", initDisplayPath(other))
	}
}

func TestInitDecliningDeclarationWritesNothing(t *testing.T) {
	remoteScannerInstalled(t)
	calls := initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--credential-env", "OPEN_TRESTLE_PROVIDER_UNSET_FOR_TEST"},
		"2", "1", "2", "128000", "8192", "n", "y", "no")
	if result.code != initExitRefused || !initHas(result.stderr, "did not confirm") || !initHas(result.stderr, "Nothing was written") {
		t.Fatalf("declined declaration exit=%d stderr=%s", result.code, result.stderr)
	}
	if !slices.Equal(*calls, []string{"https://ollama.com/api/tags"}) {
		t.Fatalf("remote model list was not read through the catalog source: %v", *calls)
	}
	initAssertAbsent(t, dir)
}

func TestInitMissingCredentialThenRerunRechecks(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "")
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD"}
	first := runInitScript(t, checkout, args, "", "yes")
	if first.code != initExitPending || !initHas(first.stdout, "read -rs OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD && export OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD") || !initHas(first.stdout, "Not ready for a review yet") {
		t.Fatalf("missing key was not a pending setup: exit=%d\n%s\n%s", first.code, first.stdout, first.stderr)
	}
	before := map[string]string{}
	for _, name := range []string{"routes.json", "policy.json", "bootstrap.json", "NEXT-STEPS.txt"} {
		before[name] = stringMustRead(t, filepath.Join(dir, name))
	}
	t.Setenv("OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", remoteTestKey)
	again := runInitScript(t, checkout, []string{"--directory", dir}, "2")
	if again.code != initExitDone || !initHas(again.stdout, "already has an Open Trestle setup") || !initHas(again.stdout, "1) Review the latest change (sends it to Ollama Cloud)") || !initHas(again.stdout, "✓ API key variable OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD is set (from the environment)") || !initHas(again.stdout, "Review the latest change any time with: trestle review --directory") || initHas(again.stdout, "--egress policy-approved") {
		t.Fatalf("rerun did not re-check the existing setup: exit=%d\n%s\n%s", again.code, again.stdout, again.stderr)
	}
	quit := runInitScript(t, checkout, []string{"--directory", dir}, "3")
	if quit.code != initExitDone || !initHas(quit.stdout, "Nothing was changed") {
		t.Fatalf("quit on rerun: exit=%d %s", quit.code, quit.stderr)
	}
	for name, content := range before {
		if stringMustRead(t, filepath.Join(dir, name)) != content {
			t.Fatalf("rerun changed %s", name)
		}
	}
}

func TestInitNoInputListsMissingAnswersAndWritesNothing(t *testing.T) {
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	// No fake API: the offline transport makes OpenRouter's API unreachable,
	// so the facts it would have supplied are listed too.
	result := runInitScript(t, checkout, []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "openrouter-zdr", "--generation-model", "vendor/generator"})
	if result.code != initExitUsage {
		t.Fatalf("exit=%d stderr=%s", result.code, result.stderr)
	}
	for _, want := range []string{"--verification-model", "--context-tokens", "--output-tokens", "--declare-remote-route"} {
		if !initHas(result.stderr, "\n  "+want+"\n") && !strings.HasSuffix(strings.SplitN(result.stderr, "\nSee", 2)[0], "\n  "+want) {
			t.Fatalf("missing answer %s not listed:\n%s", want, result.stderr)
		}
	}
	// The per-request cost bound is computed and the spending limit is
	// optional, so neither is a missing answer.
	for _, unwanted := range []string{"--generation-model\n", "--yes", "slug", "evidence", "reviewed-at", "valid-until", "declare-openrouter-zdr-account", "--max-cost-micro-usd", "--spending-limit"} {
		if initHas(result.stderr, unwanted) {
			t.Fatalf("listed %q, which is given, detected or no longer asked:\n%s", unwanted, result.stderr)
		}
	}
	initAssertAbsent(t, dir)
	noProvider := runInitScript(t, checkout, []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"})
	if noProvider.code != initExitUsage || !initHas(noProvider.stderr, "--provider") || !initHas(noProvider.stderr, "add --provider first") {
		t.Fatalf("missing provider: exit=%d %s", noProvider.code, noProvider.stderr)
	}
	initAssertAbsent(t, dir)
}

func TestInitNoInputCompleteSetupRunsReviewOnlyWithFlag(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}
	remoteModelClient(t, transport)
	checkout := latestChangeCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"}
	setup := runInitScript(t, checkout, args)
	if setup.code != initExitDone || len(transport.requests) != 0 || !initHas(setup.stdout, "No review was run") {
		t.Fatalf("setup without --run-review: exit=%d requests=%v\n%s\n%s", setup.code, transport.requests, setup.stdout, setup.stderr)
	}
	reviewed := runInitScript(t, checkout, []string{"--no-input", "--directory", dir, "--run-review"})
	if reviewed.code != initExitDone || len(transport.requests) != 2 || !initHas(reviewed.stdout, "Review finished") {
		t.Fatalf("rerun with --run-review: exit=%d requests=%v\n%s\n%s", reviewed.code, transport.requests, reviewed.stdout, reviewed.stderr)
	}
	progress, result := strings.Index(reviewed.stdout, "│ Indexing the repository"), strings.Index(reviewed.stdout, "│ status: ")
	if progress < 0 || result < 0 || progress > result {
		t.Fatalf("progress is not shown before the result:\n%s", reviewed.stdout)
	}
}

func TestInitFailedReviewPointsToItsReason(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}, verificationStatus: http.StatusServiceUnavailable}
	remoteModelClient(t, transport)
	checkout := latestChangeCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--no-input", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route", "--run-review"}
	reviewed := runInitScript(t, checkout, args)
	if reviewed.code != initExitFailed || !initHas(reviewed.stdout, "│ hint: ") || !initHas(reviewed.stdout, "for the reason shown above") || initHas(reviewed.stdout, "reachable") {
		t.Fatalf("failed review: exit=%d\n%s\n%s", reviewed.code, reviewed.stdout, reviewed.stderr)
	}
}

func TestInitEndOfInputMidFlowLeavesNoFiles(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", "")
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"}, "1", "vendor/generator")
	if result.code != initExitUsage || !initHas(result.stderr, "input ended") || !initHas(result.stderr, "Nothing was written") {
		t.Fatalf("EOF: exit=%d stderr=%s", result.code, result.stderr)
	}
	initAssertAbsent(t, dir)
}

func TestInitSameModelThreeTimesStops(t *testing.T) {
	remoteScannerInstalled(t)
	initFakeModelList(t, "gemma4:31b", "qwen3.5:397b")
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"}, "2", "1", "1", "gemma4:31b", "1")
	if result.code != initExitUsage || strings.Count(result.stdout, "same model as the finder") != 3 || !initHas(result.stderr, "three answers") {
		t.Fatalf("same model: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertAbsent(t, dir)
}

func TestInitRefusesCredentialValueAndForeignDirectory(t *testing.T) {
	checkout := remoteBootstrapCheckout(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	foreign := runInitScript(t, checkout, []string{"--directory", dir})
	if foreign.code != initExitRefused || !initHas(foreign.stderr, "no finished Open Trestle setup") || stringMustRead(t, filepath.Join(dir, "unrelated.txt")) != "keep me" {
		t.Fatalf("foreign directory: exit=%d %s", foreign.code, foreign.stderr)
	}
	fresh := filepath.Join(t.TempDir(), "setup")
	key := remoteTestKey
	result := runInitScript(t, checkout, []string{"--no-input", "--directory", fresh, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--credential-env", key})
	if result.code != initExitUsage || !initHas(result.stderr, "looks like a key") {
		t.Fatalf("credential value: exit=%d %s", result.code, result.stderr)
	}
	initAssertAbsent(t, fresh)
}

func TestInitSelectionHelpers(t *testing.T) {
	repo := t.TempDir()
	checkoutGit(t, repo, "init", "-b", "trunk")
	checkoutGit(t, repo, "commit", "--allow-empty", "-m", "base")
	checkoutGit(t, repo, "update-ref", "refs/remotes/origin/trunk", "HEAD")
	checkoutGit(t, repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk")
	checkoutGit(t, repo, "checkout", "-b", "feature")
	checkoutGit(t, repo, "commit", "--allow-empty", "-m", "change")
	ctx := context.Background()
	if got := initDefaultBase(ctx, repo); got != "refs/heads/trunk" {
		t.Fatalf("default base from origin/HEAD = %q", got)
	}
	if got, err := initNormalizeSelection(ctx, repo, "feature"); err != nil || got != "refs/heads/feature" {
		t.Fatalf("branch name normalized to %q, %v", got, err)
	}
	head := checkoutGit(t, repo, "rev-parse", "HEAD")
	if got, err := initNormalizeSelection(ctx, repo, head[:8]); err != nil || got != head {
		t.Fatalf("short commit normalized to %q, %v", got, err)
	}
	if _, err := initNormalizeSelection(ctx, repo, "--output=x"); err == nil {
		t.Fatal("option-like selection accepted")
	}
	summary := initSummarizeChange(ctx, repo, "refs/heads/trunk", "HEAD")
	if summary.commits != 1 || summary.currentLabel != "feature" {
		t.Fatalf("summary %+v", summary)
	}
	// The proposal is the merge base of the default branch and HEAD, not the
	// default branch tip, once the default branch has moved on.
	fork := checkoutGit(t, repo, "rev-parse", "refs/heads/trunk")
	checkoutGit(t, repo, "checkout", "trunk")
	checkoutGit(t, repo, "commit", "--allow-empty", "-m", "trunk moved")
	checkoutGit(t, repo, "checkout", "feature")
	if got, label := initDefaultMergeBase(ctx, repo, "HEAD"); got != fork || label != "merge base with trunk" {
		t.Fatalf("default merge base = %q (%q), want %s", got, label, fork)
	}
	if summary := initSummarizeChange(ctx, repo, fork, head); summary.commits != 1 {
		t.Fatalf("merge-base summary %+v", summary)
	}
	if _, problem := (&initWizard{ctx: ctx, checkout: repo}).resolvePair("refs/heads/feature", "HEAD"); !strings.Contains(problem, "same commit") {
		t.Fatalf("same-commit selection explanation: %q", problem)
	}
}

func TestInitFormattingHelpers(t *testing.T) {
	for value, want := range map[string]string{"3": "3000000", "0.15": "150000", "$1.5": "1500000", ".000001": "1"} {
		if got, err := initUSD(value); err != nil || got != want {
			t.Fatalf("initUSD(%q) = %q, %v", value, got, err)
		}
	}
	for _, bad := range []string{"1.0000001", "-1", "abc", "1e6"} {
		if _, err := initUSD(bad); err == nil {
			t.Fatalf("initUSD accepted %q", bad)
		}
	}
	if got := initFormatUSD(8192); got != "$0.008192" {
		t.Fatalf("initFormatUSD = %q", got)
	}
	if got := initShellQuote("it's a path"); got != `'it'\''s a path'` {
		t.Fatalf("quote = %s", got)
	}
	rendered := initRenderCommand([]string{"trestle", "local-git", "model-review", "--checkout", "/a b", "--format", "text"})
	if rendered != "    trestle local-git model-review \\\n      --checkout '/a b' \\\n      --format text" {
		t.Fatalf("rendered command:\n%s", rendered)
	}
	if initValidSelector("sk-or-v1-"+strings.Repeat("a", 40)) == nil || initValidSelector("vendor/model-name") != nil {
		t.Fatal("model ID guard misclassified a key or a model ID")
	}
	if !initSmallModel(modelcatalog.Model{Selector: "gemma3:4b"}) || initSmallModel(modelcatalog.Model{Selector: "qwen3:8b"}) || initSmallModel(modelcatalog.Model{Selector: "mixtral-8x7b"}) {
		t.Fatal("small-model heuristic misclassified a selector")
	}
	if !initSmallModel(modelcatalog.Model{Selector: "custom", Metadata: json.RawMessage(`{"details":{"parameter_size":"3.8B"}}`)}) {
		t.Fatal("parameter_size metadata ignored")
	}
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", initMaxAnswerBytes+10)+"\nnext\npartial"), initMaxAnswerBytes)
	for _, want := range []string{"\x00too-long", "next", "partial"} {
		if got, err := readInitLine(reader); err != nil || got != want {
			t.Fatalf("line = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := readInitLine(reader); err != errInitInputEnded {
		t.Fatalf("end of input = %v", err)
	}
}

func TestInitPublicAddressRejectsNonPublicRanges(t *testing.T) {
	for _, value := range []string{
		"10.1.2.3", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1", "::1", "fe80::1", "fc00::1",
		"0.0.0.0", "0.1.2.3", "198.18.0.1", "198.19.255.254", "240.0.0.1", "255.255.255.254", "255.255.255.255",
		"64:ff9b::808:808", "::ffff:10.0.0.1", "::ffff:198.18.0.1",
	} {
		if initPublicAddress(netip.MustParseAddr(value)) {
			t.Fatalf("%s accepted as a public address", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "1.1.1.1", "198.20.0.1", "223.255.255.1", "2606:4700:4700::1111"} {
		if !initPublicAddress(netip.MustParseAddr(value)) {
			t.Fatalf("%s rejected as a public address", value)
		}
	}
}
