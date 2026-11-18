package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

func bootstrapInvoke(t *testing.T, args []string, want int) setupBootstrapResult {
	t.Helper()
	var out, err bytes.Buffer
	code := runSetupWithClock(append([]string{"bootstrap"}, args...), &out, &err, fixedSetupClock{setupTimeCLI()})
	var result setupBootstrapResult
	if code != want || err.Len() != 0 || json.Unmarshal(out.Bytes(), &result) != nil {
		t.Fatalf("bootstrap code=%d want=%d out=%s err=%s", code, want, out.String(), err.String())
	}
	return result
}

func bootstrapFixture(t *testing.T) ([]string, string, *localModelFixture, *atomic.Int32) {
	t.Helper()
	f := newLocalModelFixture(t, localModelFixtureOptions{noAuth: true})
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init")
	if err := os.CopyFS(filepath.Join(checkout, ".git", "objects"), os.DirFS(f.objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "update-ref", "refs/heads/base", f.base)
	checkoutGit(t, checkout, "update-ref", "refs/heads/review", f.head)
	if err := os.Chmod(filepath.Join(checkout, ".git", "objects"), 0700); err != nil {
		t.Fatal(err)
	}
	probes := &atomic.Int32{}
	endpoints := []string{}
	for _, endpoint := range []*localModelEndpoint{f.generation, f.verification} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			_ = r.Body.Close()
			if bytes.Contains(body, []byte("func setupProbe()")) {
				probes.Add(1)
				var request struct {
					Model string `json:"model"`
					Max   uint64 `json:"max_output_tokens"`
				}
				if json.Unmarshal(body, &request) != nil || request.Model != endpoint.model || request.Max != 256 || r.Header.Get("Authorization") != "" {
					t.Error("invalid bounded setup request")
				}
				text := `{"schema_version":2,"candidates":[]}`
				if bytes.Contains(body, []byte("candidate_verification")) {
					text = `{"schema_version":1,"verdicts":[]}`
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"id": "bootstrap-probe", "object": "response", "status": "completed", "model": endpoint.model, "output": []any{map[string]any{"id": "message-probe", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": text}}}}, "usage": map[string]any{"input_tokens": 100, "output_tokens": 10, "total_tokens": 110}})
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			endpoint.serve(t, w, r)
		}))
		t.Cleanup(server.Close)
		endpoints = append(endpoints, server.URL+"/v1")
	}
	directory := t.TempDir()
	_ = os.Chmod(directory, 0700)
	args := []string{"init", "--directory", directory, "--tenant", "tenant-local", "--repository", "repository-local", "--recovery-owner", "owner", "--checkout", checkout, "--base", "refs/heads/base", "--head", "refs/heads/review", "--repository-authority", "example.test", "--repository-namespace", "private/team", "--repository-name", "sample", "--generation-endpoint", endpoints[0], "--generation-model", "model-a", "--verification-endpoint", endpoints[1], "--verification-model", "model-b", "--transport", "openai_responses", "--context-tokens", "128000", "--output-tokens", "8192", "--declare-local-capabilities",
		// These tests cover the single general review; specialists by default
		// have their own tests.
		"--specialists", "none"}
	return args, directory, f, probes
}

func TestSetupBootstrapOwnedCheckoutFirstReview(t *testing.T) {
	args, dir, f, probes := bootstrapFixture(t)
	initial := bootstrapInvoke(t, args, 3)
	if initial.Status != "pending" || initial.Ready || probes.Load() != 0 || !slices.Contains(initial.Pending, "local_inference_validated") {
		t.Fatal("initialization claimed readiness or made a model call")
	}
	for _, name := range []string{"routes.json", "policy-template.json", "policy.json", "runs/setup/plan.json", "bootstrap.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("bootstrap did not protect output", name, err)
		}
	}
	for _, path := range []string{filepath.Join(dir, "runs"), filepath.Join(dir, "runs", "setup"), filepath.Join(dir, "runs", "setup", "plan.json.receipts")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("bootstrap did not protect setup ancestor/ledger", path, err)
		}
	}
	for _, name := range []string{"plan.json", "plan.json.lock", "plan.json.receipts", "plan.json.next"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatal("bootstrap duplicated the setup ledger at its old path", name)
		}
	}
	setupIndex := slices.Index(initial.LaunchCommand, "--setup-state")
	if setupIndex < 0 || initial.LaunchCommand[setupIndex+1] != filepath.Join(dir, "runs", "setup", "plan.json") {
		t.Fatal("launch command omitted canonical recovery-compatible setup path")
	}
	// A repeated initialization resumes identical output rather than overwriting it.
	before := stringMustRead(t, filepath.Join(dir, "policy.json"))
	repeated := bootstrapInvoke(t, args, 3)
	if repeated.Plan != initial.Plan || stringMustRead(t, filepath.Join(dir, "policy.json")) != before {
		t.Fatal("resume changed initialized output")
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "operator-"+strings.Repeat("a", 32))
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "observer-"+strings.Repeat("b", 32))
	pending := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner"}, 3)
	if pending.Ready || probes.Load() != 0 || !slices.Contains(pending.Pending, "local_inference_validated") {
		t.Fatal("offline check dispatched or claimed ready")
	}
	backup := t.TempDir()
	_ = os.Chmod(backup, 0700)
	ready := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe", "--backup-directory", backup}, 0)
	if !ready.Ready || ready.Status != "ready" || len(ready.Pending) != 0 || probes.Load() != 2 {
		t.Fatalf("not ready: %+v probes=%d", ready, probes.Load())
	}
	if len(ready.ReviewCommand) != 0 {
		t.Fatal("review intent prepared implicitly")
	}
	ready = bootstrapInvoke(t, []string{"prepare-review", "--directory", dir}, 0)
	inspected := bootstrapInvoke(t, []string{"inspect", "--directory", dir}, 0)
	if !slices.Equal(ready.ReviewCommand, inspected.ReviewCommand) {
		t.Fatal("inspect relabeled review intent")
	}
	var repeatedOut, repeatedErr bytes.Buffer
	if code := runSetupBootstrapWithClock([]string{"inspect", "--directory", dir}, &repeatedOut, &repeatedErr, fixedSetupClock{setupTimeCLI().Add(24 * time.Hour)}); code != 0 {
		t.Fatal("later inspect", code)
	}
	var later setupBootstrapResult
	if json.Unmarshal(repeatedOut.Bytes(), &later) != nil || !slices.Equal(later.ReviewCommand, ready.ReviewCommand) {
		t.Fatal("clock changed persisted submit intent")
	}
	bootstrapInvoke(t, []string{"prepare-review", "--directory", dir}, 0)

	if inspected.Plan != ready.Plan || probes.Load() != 2 {
		t.Fatal("inspect changed setup")
	}
	bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe", "--backup-directory", backup}, 0)
	if probes.Load() != 2 {
		t.Fatal("ready resume repeated probe")
	}
	// Moving source refs cannot relabel the generated first-review command.
	checkout := ready.EphemeralReviewCommand[slices.Index(ready.EphemeralReviewCommand, "--checkout")+1]
	checkoutGit(t, checkout, "update-ref", "refs/heads/review", f.base)
	reviewArgs := append([]string(nil), ready.EphemeralReviewCommand[3:]...)
	reviewArgs = replaceLocalGitChangeValue(reviewArgs, "--format", "json")
	var out, err bytes.Buffer
	code := runLocalGitModelReview(context.Background(), reviewArgs, &out, &err)
	var result localModelReceipt
	if json.Unmarshal(out.Bytes(), &result) != nil || code != 4 || withoutIndexNotice(err.String()) != "" || result.Status != "findings" || result.RunStatus != "succeeded" || result.Independence != "distinct_model" || len(result.Diagnostics.Findings) != 1 || result.Diagnostics.Head != f.head || result.ComprehensiveClearance {
		t.Fatalf("first review code=%d out=%s err=%s", code, out.String(), err.String())
	}
	generation, _ := f.generation.snapshot()
	verification, _ := f.verification.snapshot()
	if generation != 1 || verification != 1 {
		t.Fatal("first review did not use both exact routes")
	}
	if ready.LaunchCommand[0] != "trestled" || !slices.Contains(ready.LaunchCommand, "--local-model-workers") || !slices.Contains(ready.LaunchCommand, filepath.Join(dir, "runs")) {
		t.Fatal("launch command omitted review workers or wrong state root")
	}
	plan, errPlan := setupcore.InspectStateFile(context.Background(), filepath.Join(dir, "runs", "setup", "plan.json"))
	if errPlan != nil || !plan.Ready() {
		t.Fatal("no canonical ready setup", errPlan)
	}
}

func TestSetupBootstrapRefusesChangedAndUnsafeOutputs(t *testing.T) {
	for _, kind := range []string{"changed policy", "symlink policy", "broad manifest", "changed init", "wrong owner"} {
		t.Run(kind, func(t *testing.T) {
			args, dir, _, probes := bootstrapFixture(t)
			bootstrapInvoke(t, args, 3)
			command := []string{"inspect", "--directory", dir}
			switch kind {
			case "changed policy":
				_ = os.WriteFile(filepath.Join(dir, "policy.json"), []byte("{}"), 0600)
			case "symlink policy":
				target := filepath.Join(dir, "policy.json")
				_ = os.Rename(target, target+".saved")
				_ = os.Symlink(target+".saved", target)
			case "broad manifest":
				_ = os.Chmod(filepath.Join(dir, "bootstrap.json"), 0644)
			case "changed init":
				command = append([]string(nil), args...)
				command = replaceLocalGitChangeValue(command, "--generation-model", "changed-model")
			case "wrong owner":
				command = []string{"check", "--directory", dir, "--approved-by", "other", "--allow-local-probe"}
			}
			result := bootstrapInvoke(t, command, 4)
			if result.Ready || result.Status != "refused" || probes.Load() != 0 {
				t.Fatal("unsafe setup admitted")
			}
		})
	}
}

func TestSetupBootstrapPendingCredentialsRecoverWithoutOverwritingConfiguration(t *testing.T) {
	args, dir, _, probes := bootstrapFixture(t)
	bootstrapInvoke(t, args, 3)
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "")
	refused := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner", "--allow-local-probe"}, 4)
	if refused.Ready || probes.Load() != 0 {
		t.Fatal("missing credentials permitted probe or ready")
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "operator-"+strings.Repeat("a", 32))
	t.Setenv("OPEN_TRESTLE_OBSERVER_TOKEN", "observer-"+strings.Repeat("b", 32))
	recovered := bootstrapInvoke(t, []string{"check", "--directory", dir, "--approved-by", "owner"}, 3)
	if recovered.Ready || recovered.Status != "pending" || probes.Load() != 0 {
		t.Fatal("dependency recovery did not remain pending")
	}
}

func TestSetupBootstrapRefusesRemotePackedAndInvalidIntentBeforeWrites(t *testing.T) {
	for _, kind := range []string{"remote", "packed", "public objects", "missing ref", "same model", "missing declaration", "duplicate flag"} {
		t.Run(kind, func(t *testing.T) {
			args, dir, _, probes := bootstrapFixture(t)
			want := 4
			switch kind {
			case "remote":
				args = replaceLocalGitChangeValue(args, "--generation-endpoint", "https://example.invalid/v1")
			case "packed":
				checkout := args[slices.Index(args, "--checkout")+1]
				checkoutGit(t, checkout, "gc", "--prune=now")
			case "public objects":
				checkout := args[slices.Index(args, "--checkout")+1]
				if err := os.Chmod(filepath.Join(checkout, ".git", "objects"), 0755); err != nil {
					t.Fatal(err)
				}
			case "missing ref":
				args = replaceLocalGitChangeValue(args, "--base", "refs/heads/missing")
			case "same model":
				args = replaceLocalGitChangeValue(args, "--verification-model", "model-a")
				want = 2
			case "missing declaration":
				args = args[:len(args)-1]
				want = 2
			case "duplicate flag":
				args = append(args, "--directory", dir)
				want = 2
			}
			var out, err bytes.Buffer
			if code := runSetupBootstrap(args, &out, &err); code != want {
				t.Fatalf("code=%d want=%d %s %s", code, want, out.String(), err.String())
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 || probes.Load() != 0 {
				t.Fatal("invalid initialization wrote output or contacted model")
			}
			if kind == "public objects" {
				checkout := args[slices.Index(args, "--checkout")+1]
				info, statErr := os.Stat(filepath.Join(checkout, ".git", "objects"))
				if statErr != nil || info.Mode().Perm() != 0755 {
					t.Fatal("bootstrap changed source permissions", statErr)
				}
			}
		})
	}
}

func TestSetupBootstrapCanceledContextRemainsNonReady(t *testing.T) {
	args, dir, _, probes := bootstrapFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	var out, err bytes.Buffer
	if code := runSetupBootstrapWithContext(canceled, args, &out, &err, fixedSetupClock{setupTimeCLI()}); code != 4 || probes.Load() != 0 {
		t.Fatal("canceled initialization did work")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("canceled initialization wrote output")
	}
}

func TestSetupBootstrapExplicitCredentialReferencesAndChatTransport(t *testing.T) {
	args, dir, _, probes := bootstrapFixture(t)
	args = replaceLocalGitChangeValue(args, "--transport", "openai_chat_completions")
	args = append(args, "--generation-credential-environment", "OPEN_TRESTLE_PROVIDER_BOOTSTRAP_A", "--verification-credential-environment", "OPEN_TRESTLE_PROVIDER_BOOTSTRAP_B")
	t.Setenv("OPEN_TRESTLE_PROVIDER_BOOTSTRAP_A", "synthetic-not-a-credential")
	bootstrapInvoke(t, args, 3)
	_, _, _, policy, err := loadSetupBootstrap(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range policy.Connections() {
		if connection.CredentialMode() != "bearer" || connection.Implementation() != "openai_chat_completions" || !strings.HasPrefix(connection.CredentialEnvironment(), "OPEN_TRESTLE_PROVIDER_BOOTSTRAP_") {
			t.Fatal("lost explicit credential or transport choice")
		}
	}
	if strings.Contains(stringMustRead(t, filepath.Join(dir, "policy.json")), "synthetic-not-a-credential") || probes.Load() != 0 {
		t.Fatal("initialization read credential value or made model call")
	}
	bootstrapInvoke(t, []string{"prepare-review", "--directory", dir}, 4)
	if _, err := os.Lstat(filepath.Join(dir, "review-intent.json")); !os.IsNotExist(err) {
		t.Fatal("pending setup gained review intent")
	}
}

func TestSetupBootstrapRefusesLegacyLedgerWithoutMutation(t *testing.T) {
	for _, name := range []string{"plan.json", "plan.json.lock", "plan.json.receipts", "plan.json.next"} {
		t.Run(name, func(t *testing.T) {
			args, dir, _, probes := bootstrapFixture(t)
			path := filepath.Join(dir, name)
			if name == "plan.json.receipts" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("retained old setup output"), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, command := range [][]string{args, {"inspect", "--directory", dir}, {"check", "--directory", dir, "--approved-by", "owner"}, {"prepare-review", "--directory", dir}} {
				bootstrapInvoke(t, command, 4)
			}
			after, err := os.Lstat(path)
			entries, readErr := os.ReadDir(dir)
			if err != nil || readErr != nil || len(entries) != 1 || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || probes.Load() != 0 {
				t.Fatal("legacy setup output was changed, migrated or used", err, readErr)
			}
			if !before.IsDir() && stringMustRead(t, path) != "retained old setup output" {
				t.Fatal("legacy setup bytes changed")
			}
		})
	}
}

func TestSetupBootstrapPrivateSetupDirectoriesAndRetry(t *testing.T) {
	for _, kind := range []string{"partial private", "broad runs", "linked runs", "broad setup", "linked setup"} {
		t.Run(kind, func(t *testing.T) {
			args, dir, _, probes := bootstrapFixture(t)
			runs := filepath.Join(dir, "runs")
			setup := filepath.Join(runs, "setup")
			if kind == "linked runs" {
				if err := os.Symlink(t.TempDir(), runs); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(runs, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "broad runs" {
					if err := os.Chmod(runs, 0755); err != nil {
						t.Fatal(err)
					}
				} else if kind == "linked setup" {
					if err := os.Symlink(t.TempDir(), setup); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Mkdir(setup, 0700); err != nil {
						t.Fatal(err)
					}
					if kind == "broad setup" {
						if err := os.Chmod(setup, 0755); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			before, err := os.Lstat(runs)
			if err != nil {
				t.Fatal(err)
			}
			want := 4
			if kind == "partial private" {
				want = 3
			}
			initial := bootstrapInvoke(t, args, want)
			if kind == "partial private" {
				repeated := bootstrapInvoke(t, args, 3)
				if repeated.Plan != initial.Plan {
					t.Fatal("private partial-directory retry changed plan")
				}
			} else {
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 1 {
					t.Fatal("unsafe setup ancestry wrote configuration", err)
				}
			}
			after, err := os.Lstat(runs)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || probes.Load() != 0 {
				t.Fatal("bootstrap replaced directory or changed private prerequisite", err)
			}
		})
	}
}
