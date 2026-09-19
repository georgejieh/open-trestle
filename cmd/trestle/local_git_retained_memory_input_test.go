package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const rmiAdvice = "CLI_AUTHORING_ADVICE_SENTINEL: retain only this bounded operator note."

type rmiReceipt struct {
	Contract                    string `json:"contract"`
	Version                     int    `json:"schema_version"`
	Status                      string `json:"status"`
	RetainedMemoryInputIdentity string `json:"retained_memory_input_identity"`
	ScopeIdentity               string `json:"scope_identity"`
	RepositoryIdentity          string `json:"repository_identity"`
	HeadRevisionIdentity        string `json:"head_revision_identity"`
	RuntimePolicyIdentity       string `json:"runtime_policy_identity"`
	RecordCount                 int    `json:"record_count"`
	PathCount                   int    `json:"path_count"`
	ExpiresAtUnixMilliseconds   int64  `json:"expires_at_unix_ms"`
}

func rmiFeedbackFile(t *testing.T, records map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	items := make([]map[string]string, 0, len(records))
	for path, text := range records {
		items = append(items, map[string]string{"path": path, "text": text})
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "feedback.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func rmiOutputPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "retained-memory-input.json")
}

func rmiArgs(f *localModelFixture, feedback, output string) []string {
	return []string{
		"--repository-authority", "example.test",
		"--repository-namespace", "private/team",
		"--repository-name", "sample",
		"--revision-algorithm", "sha1",
		"--head-revision-digest", f.head,
		"--tenant", "tenant-local",
		"--repository", "repository-local",
		"--route-inventory", f.inventoryPath,
		"--runtime-policy", f.policyPath,
		"--egress", "local-only",
		"--timeout", "5s",
		"--valid-for", "1h",
		"--feedback-input", feedback,
		"--output", output,
	}
}

func rmiRemoveFlag(args []string, flag string) []string {
	result := append([]string(nil), args...)
	for i := 0; i < len(result); i++ {
		if result[i] == flag {
			return append(result[:i], result[i+2:]...)
		}
	}
	panic(flag)
}

func rmiReplaceFlag(args []string, flag, value string) []string {
	result := append([]string(nil), args...)
	for i := 0; i < len(result)-1; i++ {
		if result[i] == flag {
			result[i+1] = value
			return result
		}
	}
	panic(flag)
}

func rmiRun(t *testing.T, ctx context.Context, args []string, wantCode int) (rmiReceipt, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runLocalGitRetainedMemoryInput(ctx, args, &stdout, &stderr)
	if code != wantCode {
		t.Fatalf("retained-memory-input exit=%d want=%d stdout=%q stderr=%q", code, wantCode, stdout.String(), stderr.String())
	}
	var receipt rmiReceipt
	if stdout.Len() != 0 {
		_ = json.Unmarshal(stdout.Bytes(), &receipt)
	}
	return receipt, stdout.String(), stderr.String()
}

func rmiNoLeak(t *testing.T, text string, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(text, value) {
			t.Fatalf("terminal output leaked %q in %q", value, text)
		}
	}
	if strings.Contains(text, "allowed_paths") || strings.Contains(text, "output_path") || strings.Contains(text, "provider-a") || strings.Contains(text, "provider-b") || strings.Contains(text, "model-a") || strings.Contains(text, "model-b") || strings.Contains(text, "OPEN_TRESTLE_PROVIDER") || strings.Contains(text, "Bearer ") {
		t.Fatalf("terminal output leaked content or provider authority: %q", text)
	}
}

func rmiLoadOutput(t *testing.T, f *localModelFixture, path string) (runtimeconfig.RetainedMemoryInput, []byte, runtimeconfig.RuntimePolicy, evidence.RepositoryIdentity, memory.Scope) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, policy, err := runtimeconfig.LoadProtectedConfiguration(context.Background(), f.inventoryPath, f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.head)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := memory.NewScope("tenant-local", "repository-local", "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := runtimeconfig.LoadProtectedRetainedMemoryInput(context.Background(), path, scope, repository, policy, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.MatchesEncoding(encoded) {
		t.Fatal("generated output was not the exact loaded encoding")
	}
	return loaded, encoded, policy, repository, scope
}

func TestRunLocalGitRetainedMemoryInputWritesLoadableContentFreeReceipt(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice, "caller.go": "second bounded note"})
	output := rmiOutputPath(t)
	receipt, stdout, stderr := rmiRun(t, context.Background(), rmiArgs(f, feedback, output), 0)
	if stderr != "" || stdout == "" || !strings.HasSuffix(stdout, "\n") || strings.Count(stdout, "\n") != 1 {
		t.Fatal("successful authoring did not emit one JSON receipt on stdout only")
	}
	rmiNoLeak(t, stdout+stderr, feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
	if receipt.Contract != "open-trestle/retained-memory-authoring-result" || receipt.Version != 1 || receipt.Status != "authored" || receipt.RecordCount != 2 || receipt.PathCount != 2 || receipt.ExpiresAtUnixMilliseconds <= time.Now().UTC().UnixMilli() {
		t.Fatalf("success receipt drift: %+v", receipt)
	}
	loaded, encoded, policy, repository, scope := rmiLoadOutput(t, f, output)
	if receipt.RetainedMemoryInputIdentity != loaded.Identity() || receipt.ScopeIdentity != scope.Identity() || receipt.RepositoryIdentity != repository.Identity() || receipt.RuntimePolicyIdentity != policy.Identity() || receipt.HeadRevisionIdentity != scope.RefSetIdentity() {
		t.Fatal("receipt does not bind the loader-created retained input identity")
	}
	if len(encoded) > 65536 || strings.Contains(string(encoded), "provider-a") || strings.Contains(string(encoded), localModelKey) {
		t.Fatal("retained-memory output exceeded the wire cap or captured provider credentials")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 0 || vc != 0 {
		t.Fatal("authoring command ran model review or called a provider")
	}
	reviewReceipt, reviewOut := localModelExecute(t, f, rmCLIArgs(f, output), 4)
	if reviewReceipt.Status != "findings" || !strings.Contains(reviewOut, "retained_input_read_only") || strings.Contains(reviewOut, rmiAdvice) || strings.Contains(reviewOut, output) {
		t.Fatal("ordinary local-git model-review did not accept the generated protected input without leaking it")
	}
	generatedCount, generated := f.generation.snapshot()
	verifiedCount, verified := f.verification.snapshot()
	if generatedCount != 1 || verifiedCount != 1 {
		t.Fatal("ordinary model-review did not use the loopback external model exactly once per role")
	}
	rmiRequireModelSawGeneratedAdvice(t, generated)
	rmiRequireModelSawGeneratedAdvice(t, verified)
}

func rmiRequireModelSawGeneratedAdvice(t *testing.T, captures []localModelCapture) {
	t.Helper()
	if len(captures) != 1 {
		t.Fatal("ordinary model-review did not capture exactly one model request")
	}
	for _, capture := range captures {
		found := false
		for _, item := range capture.Packet.Memory.Items {
			if item.Path == "a.go" && item.Text == rmiAdvice {
				found = true
			}
		}
		if !found {
			t.Fatal("ordinary model-review did not select generated retained-memory advice")
		}
	}
}

func TestRunLocalGitRetainedMemoryInputArgumentAdmissionIsStrict(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
	output := rmiOutputPath(t)
	valid := rmiArgs(f, feedback, output)
	cases := map[string][]string{
		"empty":                 nil,
		"missing tenant":        rmiRemoveFlag(valid, "--tenant"),
		"duplicate tenant":      append(append([]string(nil), valid...), "--tenant", "tenant-local"),
		"equals syntax":         append(append([]string(nil), rmiRemoveFlag(valid, "--tenant")...), "--tenant=tenant-local"),
		"unknown objects root":  append(append([]string(nil), valid...), "--objects-root", f.objects),
		"unknown provider flag": append(append([]string(nil), valid...), "--provider", "model-a"),
		"investigation refused": append(append([]string(nil), valid...), "--investigation-policy", filepath.Join(t.TempDir(), "investigation.json")),
		"missing flag value":    append(append([]string(nil), valid...), "--format"),
		"bad format":            append(append([]string(nil), valid...), "--format", "xml"),
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, stdout, stderr := rmiRun(t, context.Background(), args, 2)
			if stdout != "" || !strings.Contains(stderr, "usage:") {
				t.Fatalf("usage refusal drift stdout=%q stderr=%q", stdout, stderr)
			}
			rmiNoLeak(t, stdout+stderr, feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
			rmCLINoCalls(t, f)
		})
	}
}

func TestRunLocalGitRetainedMemoryInputPreCreateRefusalsDoNotWriteOrDispatch(t *testing.T) {
	cases := map[string]func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int){
		"canceled": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, args, 3
		},
		"remote egress": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--egress", "policy-approved"), 2
		},
		"remote policy": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			remote := newLocalModelFixture(t, localModelFixtureOptions{remote: true})
			args = rmiReplaceFlag(args, "--route-inventory", remote.inventoryPath)
			args = rmiReplaceFlag(args, "--runtime-policy", remote.policyPath)
			return context.Background(), args, 4
		},
		"missing feedback": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--feedback-input", filepath.Join(filepath.Dir(output), "missing-feedback.json")), 4
		},
		"output exists": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			return context.Background(), args, 4
		},
		"valid-for below timeout": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--valid-for", "5s"), 2
		},
		"timeout below bound": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--timeout", "999ms"), 2
		},
		"timeout above bound": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--timeout", "16m"), 2
		},
		"submillisecond timeout": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--timeout", "1000001ns"), 2
		},
		"valid-for above max": func(t *testing.T, f *localModelFixture, args []string, output string) (context.Context, []string, int) {
			return context.Background(), rmiReplaceFlag(args, "--valid-for", "169h"), 2
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
			output := rmiOutputPath(t)
			args := rmiArgs(f, feedback, output)
			ctx, mutated, wantCode := mutate(t, f, args, output)
			_, stdout, stderr := rmiRun(t, ctx, mutated, wantCode)
			rmiNoLeak(t, stdout+stderr, feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
			if name == "output exists" {
				if got, err := os.ReadFile(output); err != nil || string(got) != "existing" {
					t.Fatal("existing output was overwritten or truncated")
				}
			} else if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("pre-create refusal created an output file")
			}
			rmCLINoCalls(t, f)
		})
	}
}

func TestRunLocalGitRetainedMemoryInputReceiptFailureLeavesLoadableFileAndReportsAmbiguousWrite(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
	output := rmiOutputPath(t)
	var stderr bytes.Buffer
	code := runLocalGitRetainedMemoryInput(context.Background(), rmiArgs(f, feedback, output), shortWriter{}, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "may remain") {
		t.Fatalf("receipt failure did not report ambiguous post-create state: code=%d stderr=%q", code, stderr.String())
	}
	rmiNoLeak(t, stderr.String(), feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
	loaded, encoded, _, _, _ := rmiLoadOutput(t, f, output)
	if loaded.Identity() == "" || !loaded.MatchesEncoding(encoded) {
		t.Fatal("post-create receipt failure did not leave a stable loadable file")
	}
	rmCLINoCalls(t, f)
}

func TestRunLocalGitRetainedMemoryInputMainRouteUsesFrozenHelper(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
	output := rmiOutputPath(t)
	var stdout, stderr bytes.Buffer
	code := runWithContext(context.Background(), append([]string{"local-git", "retained-memory-input"}, rmiArgs(f, feedback, output)...), &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("main route did not dispatch retained-memory-input helper: code=%d stderr=%q", code, stderr.String())
	}
	rmiNoLeak(t, stdout.String()+stderr.String(), feedback, output, f.inventoryPath, f.policyPath, f.objects, rmiAdvice, localModelKey, localModelSecret)
	rmiLoadOutput(t, f, output)
	if stdout.Len() == 0 {
		t.Fatal("main route did not create a loadable retained-memory input")
	}
}

func TestGeneratedRetainedMemoryInputMismatchesRefuseBeforeModelDispatch(t *testing.T) {
	validObserved := func() time.Time {
		return time.UnixMilli(time.Now().UTC().Add(-time.Second).UnixMilli()).UTC()
	}
	cases := map[string]func(t *testing.T, f *localModelFixture) string{
		"wrong head": func(t *testing.T, f *localModelFixture) string {
			return rmiEncodedInputFile(t, f, f.base, validObserved(), time.Hour)
		},
		"wrong policy": func(t *testing.T, f *localModelFixture) string {
			other := newLocalModelFixture(t, localModelFixtureOptions{})
			return rmiEncodedInputFileWithPolicy(t, other, f.head, validObserved(), time.Hour)
		},
		"insufficient lifetime": func(t *testing.T, f *localModelFixture) string {
			feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
			output := rmiOutputPath(t)
			args := rmiArgs(f, feedback, output)
			args = rmiReplaceFlag(args, "--valid-for", "1m")
			rmiRun(t, context.Background(), args, 0)
			return output
		},
		"expired": func(t *testing.T, f *localModelFixture) string {
			return rmiEncodedInputFile(t, f, f.head, time.UnixMilli(time.Now().UTC().Add(-2*time.Hour).UnixMilli()).UTC(), time.Hour)
		},
	}
	for name, makeInput := range cases {
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			path := makeInput(t, f)
			wantCode, wantStatus := 4, "refused"
			reviewArgs := rmCLIArgs(f, path)
			if name == "insufficient lifetime" {
				wantCode, wantStatus = 1, "failed"
				reviewArgs = rmiReplaceFlag(reviewArgs, "--timeout", "2m")
			}
			result, out := localModelExecute(t, f, reviewArgs, wantCode)
			if result.Status != wantStatus || strings.Contains(out, path) || strings.Contains(out, rmiAdvice) {
				t.Fatal("retained input mismatch did not refuse content-free")
			}
			rmCLINoCalls(t, f)
		})
	}
}

func TestRetainedMemoryInputStillRefusesInvestigationMode(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": rmiAdvice})
	output := rmiOutputPath(t)
	rmiRun(t, context.Background(), rmiArgs(f, feedback, output), 0)
	investigation := filepath.Join(t.TempDir(), "investigation.json")
	args := append(rmCLIArgs(f, output), "--investigation-policy", investigation)
	var stdout, stderr bytes.Buffer
	if code := runWithContext(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("retained memory plus investigation policy was not refused as usage: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	rmiNoLeak(t, stdout.String()+stderr.String(), output, investigation, rmiAdvice, localModelKey, localModelSecret)
	rmCLINoCalls(t, f)
}

func rmiEncodedInputFile(t *testing.T, f *localModelFixture, headDigest string, observed time.Time, lifetime time.Duration) string {
	t.Helper()
	return rmiEncodedInputFileWithPolicy(t, f, headDigest, observed, lifetime)
}

func rmiEncodedInputFileWithPolicy(t *testing.T, policyFixture *localModelFixture, headDigest string, observed time.Time, lifetime time.Duration) string {
	t.Helper()
	observed = time.UnixMilli(observed.UTC().UnixMilli()).UTC()
	_, policy, err := runtimeconfig.LoadProtectedConfiguration(context.Background(), policyFixture.inventoryPath, policyFixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, headDigest)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := memory.NewScope("tenant-local", "repository-local", "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := runtimeconfig.EncodeRetainedMemoryInput(context.Background(), scope, repository, head, policy, []runtimeconfig.RetainedMemoryFeedback{{Path: "a.go", Text: rmiAdvice}}, observed.UTC(), observed.UTC().Add(lifetime))
	if err != nil {
		t.Fatal(err)
	}
	path := rmiOutputPath(t)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
