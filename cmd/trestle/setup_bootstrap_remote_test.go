package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// All provider, account and evidence values below are synthetic offline fixtures.
// No test contacts a provider; every model request goes to remoteModelTransport.

const remoteTestKey = "synthetic-remote-key-not-a-real-credential"

var remoteTestDigest = strings.Repeat("ab", 32)

type remoteModelTransport struct {
	t      *testing.T
	target string
	// models maps each model to the JSON list its request must pin with
	// OpenRouter's only and order ("[]" requires zero data retention without
	// pinning), or "" for a request without provider controls.
	models map[string]string
	// anonymous expects no Authorization header at all (the Ollama sign-in route).
	anonymous bool
	// maxTokens is the review output allowance every request must send; zero
	// means the default 4096.
	maxTokens uint32
	// verificationStatus, when set, answers every verification request with
	// that HTTP status and no usage.
	verificationStatus int
	mu                 sync.Mutex
	requests           []string                     // "task:model"
	providers          []map[string]json.RawMessage // each request's provider object, nil when absent
}

func (r *remoteModelTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_, hasAuthorization := request.Header["Authorization"]
	if request.Method != http.MethodPost || request.URL.String() != r.target || r.anonymous == hasAuthorization || !r.anonymous && request.Header.Get("Authorization") != "Bearer "+remoteTestKey {
		return nil, fmt.Errorf("remote fixture refused target %s", request.URL.String())
	}
	if strings.HasPrefix(r.target, "https://opencode.ai/") != strings.HasPrefix(request.Header.Get("x-opencode-session"), "trestle_") {
		return nil, errors.New("OpenCode session header missing or leaked to another provider")
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, (8<<20)+1))
	if err != nil || len(body) > 8<<20 {
		return nil, errors.New("unbounded remote request")
	}
	var wire struct {
		Model     string                           `json:"model"`
		MaxTokens uint32                           `json:"max_tokens"`
		Stream    bool                             `json:"stream"`
		Messages  []struct{ Role, Content string } `json:"messages"`
		Provider  map[string]json.RawMessage       `json:"provider"`
	}
	allowance := r.maxTokens
	if allowance == 0 {
		allowance = 4096
	}
	if json.Unmarshal(body, &wire) != nil || wire.MaxTokens != allowance || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" {
		return nil, errors.New("remote request lost the bounded Chat Completions wire")
	}
	slugs, known := r.models[wire.Model]
	if !known {
		return nil, fmt.Errorf("remote request used undeclared model %q", wire.Model)
	}
	if slugs == "" && wire.Provider != nil {
		return nil, errors.New("direct remote request carried provider routing controls")
	}
	if slugs != "" {
		expected := map[string]string{"zdr": "true", "only": slugs, "allow_fallbacks": "true", "require_parameters": "true"}
		if _, ordered := wire.Provider["order"]; ordered {
			return nil, errors.New("an OpenRouter request fixed the endpoint order")
		}
		if slugs == "[]" {
			delete(expected, "only")
			if _, pinned := wire.Provider["only"]; pinned {
				return nil, errors.New("an unpinned OpenRouter request sent a slug list")
			}
		}
		for key, want := range expected {
			var compact bytes.Buffer
			if json.Compact(&compact, wire.Provider[key]) != nil || compact.String() != want {
				return nil, fmt.Errorf("OpenRouter routing control %s lost", key)
			}
		}
	}
	payload := []byte(wire.Messages[1].Content)
	if instructions, err := review.TrustedModelRequestInstructions(payload); err != nil || instructions != wire.Messages[0].Content {
		return nil, errors.New("remote request changed trusted instructions")
	}
	if bytes.Contains(body, []byte(remoteTestKey)) {
		return nil, errors.New("credential value entered the request body")
	}
	var packet localModelPacket
	neutral, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if err != nil || json.Unmarshal(payload, &packet) != nil {
		return nil, errors.New("remote request lost the review context")
	}
	var changed, caller localModelSource
	for _, source := range packet.Sources {
		switch source.Path {
		case "a.go":
			changed = source
		case "caller.go":
			caller = source
		}
	}
	if changed.ID == "" || caller.ID == "" {
		return nil, errors.New("remote request omitted changed code or caller")
	}
	evidenceIDs := []string{changed.ID, caller.ID}
	var output any
	switch packet.Task {
	case "candidate_generation":
		if review.ValidateCandidateModelRequest(neutral, packet.Scope) != nil {
			return nil, errors.New("invalid generation request")
		}
		output = map[string]any{"schema_version": 2, "candidates": []any{map[string]any{"title": "Zero-valued caller now panics", "claim": "Consume passes zero to Changed after removal of the division guard.", "severity_hint": "high", "category": "correctness", "source_range": map[string]any{"source_id": changed.ID, "start_line": 2, "end_line": 2}, "evidence_ids": evidenceIDs}}}
	case "candidate_verification":
		if review.ValidateVerificationModelRequest(neutral, packet.Scope) != nil {
			return nil, errors.New("invalid verification request")
		}
		verdicts := []any{}
		for _, candidate := range packet.Candidates {
			verdicts = append(verdicts, map[string]any{"candidate_id": candidate.ID, "outcome": "verified", "severity": "high", "rationale": "The cited caller passes zero to the unguarded integer division.", "evidence_ids": evidenceIDs})
		}
		output = map[string]any{"schema_version": 1, "verdicts": verdicts}
	default:
		return nil, errors.New("unexpected task")
	}
	r.mu.Lock()
	r.requests = append(r.requests, packet.Task+":"+wire.Model)
	r.providers = append(r.providers, wire.Provider)
	r.mu.Unlock()
	if packet.Task == "candidate_verification" && r.verificationStatus != 0 {
		return &http.Response{StatusCode: r.verificationStatus, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	text, _ := json.Marshal(output)
	usage := map[string]any{"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200}
	if strings.HasPrefix(r.target, "https://openrouter.ai/") {
		usage["cost"], usage["is_byok"] = 0.0012, false
		usage["cost_details"] = map[string]any{"upstream_inference_prompt_cost": 0.0008, "upstream_inference_completions_cost": 0.0004, "upstream_inference_cost": nil}
	}
	response, _ := json.Marshal(map[string]any{"id": "fixture-remote-chat", "object": "chat.completion", "model": wire.Model, "choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": string(text)}, "finish_reason": "stop"}}, "usage": usage})
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
}

func remoteBootstrapCheckout(t *testing.T) string {
	t.Helper()
	base := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n// " + localModelSecret + "\n"),
		"caller.go": []byte("package p\nfunc Consume() int { return Changed(0) }\n"),
	}
	head := map[string][]byte{"a.go": []byte("package p\nfunc Changed(x int) int { return 10 / x }\n// " + localModelSecret + "\n"), "caller.go": base["caller.go"]}
	objects, baseCommit, headCommit := writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init")
	if err := os.CopyFS(filepath.Join(checkout, ".git", "objects"), os.DirFS(objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "update-ref", "refs/heads/base", baseCommit)
	checkoutGit(t, checkout, "update-ref", "refs/heads/review", headCommit)
	return checkout
}

func remoteBootstrapArgs(t *testing.T, providerName string) ([]string, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	reviewed := now.Add(-2 * time.Hour).Format(time.RFC3339)
	args := []string{"init", "--provider", providerName, "--directory", directory, "--tenant", "tenant-remote", "--repository", "repository-remote", "--checkout", remoteBootstrapCheckout(t), "--base", "refs/heads/base", "--head", "refs/heads/review", "--repository-authority", "example.test", "--repository-namespace", "private/team", "--repository-name", "sample", "--generation-model", "vendor/generator", "--verification-model", "other/verifier", "--generation-credential-environment", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declared-by", "fixture-operator", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "1000000", "--output-micro-usd-per-million-tokens", "2000000", "--max-cost-micro-usd", "1000000", "--declare-remote-route"}
	witness := []string{"--evidence-retrieved-at", reviewed, "--reviewed-at", reviewed, "--valid-from", now.Add(-time.Hour).Format(time.RFC3339), "--valid-until", now.Add(24 * time.Hour).Format(time.RFC3339), "--broker-evidence", "https://evidence.fixture.invalid/broker," + remoteTestDigest, "--account-evidence", "https://evidence.fixture.invalid/account," + remoteTestDigest}
	switch providerName {
	case "openrouter-zdr", "openrouter":
		// Context, output and prices come from the fake OpenRouter API.
		for _, name := range remoteBootstrapOpenRouterDetected {
			index := slices.Index(args, "--"+name)
			args = slices.Delete(args, index, index+2)
		}
		fakeOpenRouter(t, fakeORFinder, fakeORChecker, fakeORNoZDR)
	case "opencode-go":
		args = append(args, witness...)
		args = append(args, "--generation-model-evidence", "https://evidence.fixture.invalid/gen-model,"+remoteTestDigest, "--verification-model-evidence", "https://evidence.fixture.invalid/ver-model,"+remoteTestDigest, "--declare-opencode-go-account")
	case "ollama-cloud":
		args = replaceLocalGitChangeValue(args, "--generation-model", "gemma4:31b")
		args = replaceLocalGitChangeValue(args, "--verification-model", "qwen3.5:397b")
	}
	return args, directory
}

func remoteBootstrapInvoke(t *testing.T, args []string, want int) (remoteBootstrapResult, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"setup", "bootstrap"}, args...), &stdout, &stderr)
	var result remoteBootstrapResult
	if code != want || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Contract != remoteBootstrapResultContract {
		t.Fatalf("remote bootstrap code=%d want=%d out=%s err=%s", code, want, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
		t.Fatal("bootstrap output disclosed a credential value")
	}
	return result, stderr.String()
}

func remoteScannerInstalled(t *testing.T) {
	t.Helper()
	previous := setupBootstrapScannerPrerequisite
	setupBootstrapScannerPrerequisite = func() error { return nil }
	t.Cleanup(func() { setupBootstrapScannerPrerequisite = previous })
}

func remoteModelClient(t *testing.T, transport *remoteModelTransport) {
	t.Helper()
	localReviewModelHTTPClient = &http.Client{Transport: transport, Timeout: time.Minute}
	localReviewModelHTTPClientIdentity = localModelDigest([]byte("offline remote model fixture transport"))
	t.Cleanup(func() { localReviewModelHTTPClient, localReviewModelHTTPClientIdentity = nil, "" })
}

// TestSetupBootstrapRemoteDirectPolicyApprovedReview proves the documented journey:
// bootstrap init/check derive every identity, and the printed review command runs
// `local-git model-review --egress policy-approved` through the production session,
// fixed sanitizer seam and remote adapters to distinct generation and verifier models.
func TestSetupBootstrapRemoteDirectPolicyApprovedReview(t *testing.T) {
	// OpenRouter's allowance is the smallest output a pinned or listed
	// endpoint of the fixture checker allows (16000, under the 16384 target);
	// the other providers keep 4096.
	for _, test := range []struct {
		provider, target, generator, verifier string
		models                                map[string]string
		maxTokens                             uint32
	}{
		{"openrouter-zdr", "https://openrouter.ai/api/v1/chat/completions", "vendor/generator", "other/verifier", map[string]string{"vendor/generator": `["fixture-cloud","fixture-cloud/us"]`, "other/verifier": `["fixture-host/fp8"]`}, 16000},
		{"openrouter", "https://openrouter.ai/api/v1/chat/completions", "vendor/generator", "other/verifier", map[string]string{"vendor/generator": "", "other/verifier": ""}, 16000},
		{"ollama-cloud", "https://ollama.com/v1/chat/completions", "gemma4:31b", "qwen3.5:397b", map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}, 0},
		{"opencode-go", "https://opencode.ai/inference/go/openai/v1/chat/completions", "vendor/generator", "other/verifier", map[string]string{"vendor/generator": "", "other/verifier": ""}, 0},
	} {
		t.Run(test.provider, func(t *testing.T) {
			remoteScannerInstalled(t)
			args, dir := remoteBootstrapArgs(t, test.provider)
			t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
			initial, _ := remoteBootstrapInvoke(t, args, 3)
			if initial.Ready || !slices.Equal(initial.Pending, []string{"credential_environment_present"}) || len(initial.Refused) != 0 || len(initial.ReviewCommand) == 0 {
				t.Fatalf("missing credential did not stay pending: %+v", initial)
			}
			for _, name := range []string{"routes.json", "policy.json", "bootstrap.json"} {
				info, err := os.Stat(filepath.Join(dir, name))
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("remote bootstrap did not protect", name, err)
				}
			}
			// Re-running init with identical declarations is idempotent. An
			// OpenRouter init records when it read the API, so a repeat in a
			// later second is a new observation and is checked elsewhere.
			if !strings.HasPrefix(test.provider, "openrouter") {
				if again, _ := remoteBootstrapInvoke(t, args, 3); again.Policy != initial.Policy || again.Inventory != initial.Inventory {
					t.Fatal("repeated init changed derived identities")
				}
			}
			t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
			ready, _ := remoteBootstrapInvoke(t, []string{"check", "--directory", dir}, 0)
			if !ready.Ready || ready.Status != "ready" || !slices.Equal(ready.ReviewCommand, initial.ReviewCommand) {
				t.Fatalf("check did not become ready: %+v", ready)
			}
			command := ready.ReviewCommand
			if command[0] != "trestle" || !slices.Contains(command, "policy-approved") || slices.Contains(command, "local-only") {
				t.Fatal("review command does not use the direct policy-approved path")
			}
			transport := &remoteModelTransport{t: t, target: test.target, models: test.models, maxTokens: test.maxTokens}
			remoteModelClient(t, transport)
			reviewArgs := replaceLocalGitChangeValue(command[1:], "--format", "json")
			var stdout, stderr bytes.Buffer
			code := run(reviewArgs, &stdout, &stderr)
			var receipt localModelReceipt
			if code != 4 || json.Unmarshal(stdout.Bytes(), &receipt) != nil {
				t.Fatalf("remote review exit=%d out=%s err=%s requests=%v", code, stdout.String(), stderr.String(), transport.requests)
			}
			if receipt.Status != "findings" || receipt.RunStatus != "succeeded" || receipt.Inventory != ready.Inventory || receipt.Policy != ready.Policy || receipt.GenerationRoute == receipt.VerificationRoute || receipt.Independence != "distinct_model" {
				t.Fatalf("remote review did not complete with independent routes: %+v", receipt)
			}
			if !slices.Equal(transport.requests, []string{"candidate_generation:" + test.generator, "candidate_verification:" + test.verifier}) {
				t.Fatalf("remote dispatch did not use distinct generation and verifier models: %v", transport.requests)
			}
			if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
				t.Fatal("review output disclosed the credential value")
			}
		})
	}
}

func TestSetupBootstrapRemoteOpenCodeGoBuildsProfileConfiguration(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	args, dir := remoteBootstrapArgs(t, "opencode-go")
	result, _ := remoteBootstrapInvoke(t, args, 0)
	if !result.Ready || result.Provider != "opencode-go" {
		t.Fatalf("OpenCode Go bootstrap not ready: %+v", result)
	}
	policy := stringMustRead(t, filepath.Join(dir, "policy.json"))
	if !strings.Contains(policy, `"request_profile":"opencode_go_chat_v1"`) || !strings.Contains(policy, "https://opencode.ai/inference/go/openai/v1") || strings.Contains(policy, remoteTestKey) {
		t.Fatal("OpenCode Go policy lost its named profile or stored a credential")
	}
}

func TestSetupBootstrapRemoteScannerPrerequisite(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	args, dir := remoteBootstrapArgs(t, "ollama-cloud")
	// A test binary has no injected scanner digests, so the real probe refuses.
	result, _ := remoteBootstrapInvoke(t, args, 4)
	if result.Ready || !slices.Equal(result.Refused, []string{"sanitized_egress_scanner"}) || !strings.Contains(strings.Join(result.Messages, " "), "package_secret_scanner.py") {
		t.Fatalf("missing scanner digests were not a clear refused prerequisite: %+v", result)
	}
	previous := setupBootstrapScannerPrerequisite
	setupBootstrapScannerPrerequisite = func() error { return secretscan.ErrScannerNotInstalled }
	t.Cleanup(func() { setupBootstrapScannerPrerequisite = previous })
	pending, _ := remoteBootstrapInvoke(t, []string{"inspect", "--directory", dir}, 3)
	if !slices.Equal(pending.Pending, []string{"sanitized_egress_scanner"}) || !strings.Contains(strings.Join(pending.Messages, " "), "install") {
		t.Fatalf("uninstalled scanner was not a clear pending prerequisite: %+v", pending)
	}
}

func TestSetupBootstrapRemoteRefusesInventedOrUnsafeInput(t *testing.T) {
	remoteScannerInstalled(t)
	without := func(args []string, name string) []string {
		index := slices.Index(args, name)
		return slices.Delete(slices.Clone(args), index, index+1)
	}
	for _, test := range []struct {
		name, provider, reason string
		mutate                 func([]string) []string
	}{
		{"missing route declaration", "ollama-cloud", "--declare-remote-route", func(a []string) []string { return without(a, "--declare-remote-route") }},
		{"missing OpenRouter consent", "openrouter-zdr", "refusing to send source to OpenRouter without consent", func(a []string) []string { return without(a, "--declare-remote-route") }},
		{"missing OpenCode Go declaration", "opencode-go", "refusing to claim OpenCode Go privacy", func(a []string) []string { return without(a, "--declare-opencode-go-account") }},
		{"credential value instead of name", "openrouter-zdr", "never a key value", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--generation-credential-environment", "sk-or-v1-"+strings.Repeat("a", 32))
		}},
		{"loopback endpoint", "ollama-cloud", "remote HTTPS base URL", func(a []string) []string { return append(a, "--endpoint", "http://127.0.0.1:11434/v1") }},
		{"endpoint on fixed profile", "openrouter-zdr", "does not apply", func(a []string) []string { return append(a, "--endpoint", "https://example.test/v1") }},
		{"same model", "ollama-cloud", "must differ", func(a []string) []string { return replaceLocalGitChangeValue(a, "--verification-model", "gemma4:31b") }},
		{"retired evidence", "openrouter-zdr", "--generation-slug-evidence is no longer used", func(a []string) []string {
			return append(a, "--generation-slug-evidence", "https://evidence.fixture.invalid/slug,"+remoteTestDigest)
		}},
		{"retired account declaration", "openrouter", "--declare-openrouter-zdr-account is no longer used", func(a []string) []string { return append(a, "--declare-openrouter-zdr-account") }},
		{"slug without zero data retention", "openrouter", "applies only with zero data retention", func(a []string) []string { return append(a, "--generation-provider-slug", "fixture-cloud") }},
		{"model without zero data retention", "openrouter-zdr", "plain/verifier has no zero-data-retention endpoint", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--verification-model", "plain/verifier")
		}},
		{"model not listed", "openrouter", "does not list the model missing/model", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--verification-model", "missing/model")
		}},
		{"evidence without digest", "opencode-go", "SHA-256", func(a []string) []string {
			return replaceLocalGitChangeValue(a, "--broker-evidence", "https://evidence.fixture.invalid/broker,")
		}},
		{"noncanonical time", "opencode-go", "canonical UTC", func(a []string) []string { return replaceLocalGitChangeValue(a, "--valid-until", "tomorrow") }},
		{"retired review window", "openrouter-zdr", "--valid-until is no longer used", func(a []string) []string { return append(a, "--valid-until", "2026-12-01T00:00:00Z") }},
		{"unpayable budget", "ollama-cloud", "cannot cover", func(a []string) []string { return replaceLocalGitChangeValue(a, "--max-cost-micro-usd", "1") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, dir := remoteBootstrapArgs(t, test.provider)
			result, stderr := remoteBootstrapInvoke(t, test.mutate(args), 4)
			if result.Ready || result.Status != "refused" || !strings.Contains(strings.Join(result.Messages, " "), test.reason) || !strings.Contains(stderr, test.reason) {
				t.Fatalf("refusal lacked clear reason %q: %+v %s", test.reason, result, stderr)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatal("refused init wrote configuration")
			}
		})
	}
}
