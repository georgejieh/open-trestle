package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

type localModelReceipt struct {
	Contract               string   `json:"contract"`
	Version                int      `json:"schema_version"`
	Status                 string   `json:"status"`
	CI                     string   `json:"ci_disposition"`
	RunStatus              string   `json:"run_status"`
	Failure                string   `json:"failure"`
	Run                    string   `json:"review_run_id"`
	Scope                  string   `json:"scope_identity"`
	Request                string   `json:"request_identity"`
	Plan                   string   `json:"plan_identity"`
	Output                 string   `json:"output_identity"`
	Repository             string   `json:"repository_identity"`
	Base                   string   `json:"base_revision_identity"`
	Head                   string   `json:"head_revision_identity"`
	Inventory              string   `json:"inventory_identity"`
	Policy                 string   `json:"runtime_policy_identity"`
	Context                string   `json:"context_identity"`
	GenerationRequest      string   `json:"generation_request_identity"`
	VerificationRequest    string   `json:"verification_request_identity"`
	VerificationContext    string   `json:"verification_context_identity"`
	CandidateBatch         string   `json:"candidate_batch_identity"`
	CandidateIDs           []string `json:"candidate_ids"`
	Readiness              string   `json:"readiness_identity"`
	GenerationRoute        string   `json:"generation_route_record_identity"`
	VerificationRoute      string   `json:"verification_route_record_identity"`
	Independence           string   `json:"independence"`
	Limitations            []string `json:"limitations"`
	ComprehensiveClearance bool     `json:"comprehensive_clearance"`
	LeaseRenewals          uint64   `json:"lease_renewals"`
	Tasks                  []struct {
		Key         string `json:"key"`
		Status      string `json:"status"`
		Attempts    uint8  `json:"attempts"`
		MaxAttempts uint8  `json:"max_attempts"`
		Output      string `json:"output_identity"`
	} `json:"tasks"`
	Audit []struct {
		Kind    string `json:"kind"`
		Subject string `json:"subject_identity"`
	} `json:"audit"`
	Diagnostics struct {
		Identity string `json:"identity"`
		Head     string `json:"head_revision"`
		Coverage struct {
			CandidateCount    uint16 `json:"candidate_count"`
			VerifiedCount     uint16 `json:"verified_count"`
			InconclusiveCount uint16 `json:"inconclusive_count"`
		} `json:"coverage"`
		SourceCoverage struct {
			Context  string `json:"verification_context_identity"`
			Analyzed uint32 `json:"analyzed_count"`
			Selected uint32 `json:"selected_count"`
			Omitted  uint32 `json:"omitted_count"`
		} `json:"source_coverage"`
		Findings []struct {
			Identity string   `json:"identity"`
			Path     string   `json:"path"`
			Start    uint32   `json:"start_line"`
			End      uint32   `json:"end_line"`
			Severity string   `json:"severity"`
			Evidence []string `json:"evidence_ids"`
		} `json:"findings"`
	} `json:"diagnostics"`
}

func localModelExecute(t *testing.T, f *localModelFixture, args []string, wantCode int) (localModelReceipt, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != wantCode {
		var outcome struct {
			Status    string `json:"status"`
			RunStatus string `json:"run_status"`
		}
		_ = json.Unmarshal(stdout.Bytes(), &outcome)
		generationCalls, _ := f.generation.snapshot()
		verificationCalls, _ := f.verification.snapshot()
		t.Fatalf("model-review exit=%d want=%d status=%s run=%s model_calls=%d/%d stderr=%q", code, wantCode, outcome.Status, outcome.RunStatus, generationCalls, verificationCalls, stderr.String())
	}
	if stdout.Len() == 0 || stdout.Len() > 256<<10 || strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatal("model-review did not emit one bounded terminal JSON result")
	}
	var result localModelReceipt
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Contract != "open-trestle/local-git-model-review-result" || result.Version != 1 || result.ComprehensiveClearance {
		t.Fatal("missing versioned local model receipt or false comprehensive-clearance claim")
	}
	for _, forbidden := range []string{f.objects, f.inventoryPath, f.policyPath, localModelSecret, localModelKey, "return 10 / x", "OPEN_TRESTLE_PROVIDER_LOCAL_TEST", "Bearer "} {
		if strings.Contains(stdout.String()+stderr.String(), forbidden) {
			t.Fatal("terminal output disclosed private source, configuration path, or credentials")
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("JSON result also wrote stderr: %q", stderr.String())
	}
	for _, task := range result.Tasks {
		if task.Key == "publication" {
			t.Fatal("local model run contains a publication task")
		}
	}
	for _, event := range result.Audit {
		if strings.HasPrefix(event.Kind, "publication_") {
			t.Fatal("local model run acquired publication authority")
		}
	}
	return result, stdout.String()
}

func localModelRequireDigest(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || strings.ToLower(value) != value || strings.Trim(value, "0") == "" {
			t.Fatal("terminal receipt omitted an actual lineage identity")
		}
	}
}

func TestRunLocalGitModelReviewCompletesIndependentFinding(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	result, _ := localModelExecute(t, f, f.args, 4)
	generationCalls, generated := f.generation.snapshot()
	verificationCalls, verified := f.verification.snapshot()
	if generationCalls != 1 || verificationCalls != 1 || len(generated) != 1 || len(verified) != 1 {
		t.Fatal("model review did not make exactly one real HTTP attempt per independent route")
	}
	if result.Status != "findings" || result.CI != "blocked" || result.RunStatus != "succeeded" {
		t.Fatal("verified finding did not complete the production worker/finalizer and block CI")
	}
	localModelRequireDigest(t, result.Request, result.Plan, result.Output, result.Readiness, result.Diagnostics.Identity)
	scope, err := audit.NewReviewScope("tenant-local", "repository-local", result.Run)
	if err != nil || result.Scope != scope.Identity() || generated[0].Packet.Scope != scope.Identity() || verified[0].Packet.Scope != scope.Identity() {
		t.Fatal("actual model scopes differ from the requested scope")
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if err != nil {
		t.Fatal(err)
	}
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.base)
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.head)
	if err != nil {
		t.Fatal(err)
	}
	if result.Repository != repository.Identity() || result.Base != base.Identity() || result.Head != head.Identity() || result.Diagnostics.Head != f.head || result.Inventory != f.inventoryID || result.Policy != f.policyID {
		t.Fatal("receipt does not bind the exact local revisions and protected runtime configuration")
	}
	if result.Context != generated[0].ContextID || result.GenerationRequest != generated[0].RequestID || result.VerificationRequest != verified[0].RequestID || result.VerificationContext != verified[0].ContextID || verified[0].Packet.GenerationContext != generated[0].ContextID || result.CandidateBatch != verified[0].Packet.CandidateBatch || result.Diagnostics.SourceCoverage.Context != verified[0].ContextID {
		t.Fatal("terminal/model-visible context, request, or candidate-batch lineage differs")
	}
	if result.GenerationRoute != f.generationRoute || result.VerificationRoute != f.verificationRoute || result.Independence != "distinct_provider" || result.GenerationRoute == result.VerificationRoute {
		t.Fatal("terminal receipt lost route pin or independent provider evidence")
	}
	if len(verified[0].Packet.Candidates) != 1 || len(result.CandidateIDs) != 1 || result.CandidateIDs[0] != verified[0].Packet.Candidates[0].ID {
		t.Fatal("terminal candidate ID was not produced by the actual generation parser")
	}
	if result.Diagnostics.Coverage.CandidateCount != 1 || result.Diagnostics.Coverage.VerifiedCount != 1 || len(result.Diagnostics.Findings) != 1 {
		t.Fatal("actual readiness diagnostics omitted the independently verified finding")
	}
	finding := result.Diagnostics.Findings[0]
	if finding.Path != "a.go" || finding.Start != 2 || finding.End != 2 || finding.Severity != "error" || len(finding.Evidence) != 2 {
		t.Fatal("verified diagnostic lost source location, severity, or evidence")
	}
	for _, source := range verified[0].Packet.Sources {
		if !slices.Contains(finding.Evidence, source.ID) {
			t.Fatal("diagnostic evidence was not copied from actual source context")
		}
	}
	keys := []string{}
	for _, task := range result.Tasks {
		keys = append(keys, task.Key)
		wantAttempts := uint8(3)
		if slices.Contains([]string{"context", "candidates", "verification"}, task.Key) {
			wantAttempts = 1
		}
		if task.Status != "succeeded" || task.Attempts != 1 || task.MaxAttempts != wantAttempts || task.Output == "" {
			t.Fatal("task receipt lost production completion or attempt policy")
		}
	}
	slices.Sort(keys)
	wantKeys := []string{"analysis", "candidates", "change", "context", "memory", "readiness", "source-base", "source-head", "verification"}
	if !slices.Equal(keys, wantKeys) {
		t.Fatal("local review did not execute exactly the nine-stage prepared graph")
	}
	counts := map[string]int{}
	for _, event := range result.Audit {
		counts[event.Kind]++
		localModelRequireDigest(t, event.Subject)
	}
	if len(result.Audit) != 8 || counts["route_selected"] != 2 || counts["route_attempt_claimed"] != 2 || counts["route_dispatch_completed"] != 2 || counts["route_cost_reconciled"] != 2 {
		t.Fatal("model execution bypassed the shared ledger selection/claim/completion/reconciliation path")
	}
	for _, limitation := range []string{"loose_git_objects_only", "empty_memory_index", "bounded_source_context", "no_publication", "ephemeral_state_no_resume"} {
		if !slices.Contains(result.Limitations, limitation) {
			t.Fatal("missing visible execution limitation")
		}
	}
}

func TestRunLocalGitModelReviewNoCandidatesIsNotClearance(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "empty"})
	result, _ := localModelExecute(t, f, f.args, 3)
	gc, _ := f.generation.snapshot()
	vc, packets := f.verification.snapshot()
	if result.Status != "no_candidates" || result.CI != "inconclusive" || result.RunStatus != "succeeded" || gc != 1 || vc != 1 || len(packets) != 1 || len(packets[0].Packet.Candidates) != 0 || result.Diagnostics.Coverage.CandidateCount != 0 || len(result.Diagnostics.Findings) != 0 || result.Readiness == "" || result.Diagnostics.Identity == "" {
		t.Fatal("valid empty candidate batch was confused with comprehensive clearance or skipped independent readiness")
	}
}

func TestRunLocalGitModelReviewInconclusiveAndPartialCoverage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options localModelFixtureOptions
	}{
		{"verifier abstains", localModelFixtureOptions{verificationMode: "inconclusive"}},
		{"removed file", localModelFixtureOptions{generationMode: "empty", partial: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalModelFixture(t, tc.options)
			result, _ := localModelExecute(t, f, f.args, 3)
			if result.Status != "incomplete" || result.CI != "inconclusive" || result.RunStatus != "succeeded" {
				t.Fatal("incomplete evidence was reported as clearance")
			}
			if tc.options.partial && result.Diagnostics.SourceCoverage.Omitted == 0 {
				t.Fatal("unsupported removed file disappeared from coverage")
			}
			if !tc.options.partial && result.Diagnostics.Coverage.InconclusiveCount != 1 {
				t.Fatal("independent abstention disappeared from coverage")
			}
		})
	}
}

func TestRunLocalGitModelReviewFailsClosedAtRuntimeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		options                        localModelFixtureOptions
		code                           int
		status                         string
		maxGeneration, maxVerification int
	}{
		{"no independent approved route", localModelFixtureOptions{verifierPending: true}, 4, "refused", 1, 0},
		{"per-request cost cap", localModelFixtureOptions{expensive: true}, 4, "refused", 0, 0},
		{"full readable payload capacity", localModelFixtureOptions{capacity: true}, 4, "refused", 0, 0},
		{"explicit local egress refusal", localModelFixtureOptions{remote: true}, 4, "refused", 0, 0},
		{"malformed generation", localModelFixtureOptions{generationMode: "malformed"}, 1, "failed", 1, 0},
		{"wrong candidate identity", localModelFixtureOptions{verificationMode: "wrong_candidate"}, 1, "failed", 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLocalModelFixture(t, tc.options)
			result, _ := localModelExecute(t, f, f.args, tc.code)
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.Status != tc.status || result.CI == "pass" || result.RunStatus == "active" || result.Readiness != "" || len(result.Diagnostics.Findings) != 0 || gc > tc.maxGeneration || vc > tc.maxVerification {
				t.Fatal("refusal produced downstream readiness or repeated model effects")
			}
			if strings.Contains(tc.name, "malformed") && gc != 1 || tc.name == "wrong candidate identity" && (gc != 1 || vc != 1) {
				t.Fatal("malformed result test did not reach the actual model adapter")
			}
		})
	}
}

func TestRunLocalGitModelReviewRejectsUnprotectedOrMismatchedConfiguration(t *testing.T) {
	for _, name := range []string{"writable policy", "symlink policy", "inventory mismatch", "unknown field"} {
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			switch name {
			case "writable policy":
				if err := os.Chmod(f.policyPath, 0o666); err != nil {
					t.Fatal(err)
				}
			case "symlink policy":
				link := filepath.Join(filepath.Dir(f.policyPath), "linked.json")
				if err := os.Symlink(f.policyPath, link); err != nil {
					t.Fatal(err)
				}
				f.args = replaceLocalGitChangeValue(f.args, "--runtime-policy", link)
			default:
				encoded, err := os.ReadFile(f.policyPath)
				if err != nil {
					t.Fatal(err)
				}
				var policy map[string]any
				if err := json.Unmarshal(encoded, &policy); err != nil {
					t.Fatal(err)
				}
				if name == "inventory mismatch" {
					policy["inventory_identity"] = strings.Repeat("f", 64)
				} else {
					policy["publish"] = true
				}
				if err := os.WriteFile(f.policyPath, localModelJSON(t, policy), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result, _ := localModelExecute(t, f, f.args, 4)
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.Status != "refused" || gc != 0 || vc != 0 {
				t.Fatal("untrusted configuration reached a model provider")
			}
		})
	}
}

func TestRunLocalGitModelReviewRejectsUnsupportedSourceWithoutFallback(t *testing.T) {
	for _, name := range []string{"missing revision", "packed objects", "worktree pointer"} {
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			switch name {
			case "missing revision":
				f.args = replaceLocalGitChangeValue(f.args, "--head-revision-digest", strings.Repeat("e", 40))
			case "packed objects":
				pack := filepath.Join(f.objects, "pack")
				if err := os.Mkdir(pack, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pack, "pack-unsupported.pack"), []byte("PACK"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "worktree pointer":
				pointer := filepath.Join(t.TempDir(), ".git")
				if err := os.WriteFile(pointer, []byte("gitdir: "+f.objects), 0o600); err != nil {
					t.Fatal(err)
				}
				f.args = replaceLocalGitChangeValue(f.args, "--objects-root", pointer)
			}
			result, _ := localModelExecute(t, f, f.args, 3)
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.Status != "incomplete" || result.CI != "inconclusive" || gc != 0 || vc != 0 {
				t.Fatal("unsupported immutable Git input fell back to model review")
			}
		})
	}
}

func TestRunLocalGitModelReviewDeadlineCancelsActualModelWait(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "wait"})
	args := replaceLocalGitChangeValue(f.args, "--timeout", "2s")
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run(args, &stdout, &stderr) }()
	select {
	case <-f.generation.entered:
	case code := <-done:
		t.Fatalf("entrypoint returned %d before reaching the model wait", code)
	case <-time.After(5 * time.Second):
		t.Fatal("model wait was not reached")
	}
	select {
	case <-f.generation.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("caller deadline did not cancel the actual HTTP request")
	}
	select {
	case code := <-done:
		var result localModelReceipt
		if code != 3 || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Status != "canceled" || result.RunStatus != "canceled" || result.CI != "inconclusive" || stderr.Len() != 0 || stdout.Len() > 256<<10 {
			t.Fatal("deadline did not yield a bounded finalized cancellation receipt")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("foreground model review did not stop after deadline")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 1 || vc != 0 {
		t.Fatal("canceled model attempt was retried or verified")
	}
}

func TestRunLocalGitModelReviewRequiresExplicitCanonicalIntent(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	for name, args := range map[string][]string{
		"malformed scope":    replaceLocalGitChangeValue(f.args, "--tenant", "tenant\ninvalid"),
		"short revision":     replaceLocalGitChangeValue(f.args, "--head-revision-digest", "abc"),
		"duplicate":          append(append([]string(nil), f.args...), "--tenant", "other"),
		"equals grammar":     replaceLocalGitChangeArg(f.args, "--egress", "--egress=local-only"),
		"implicit egress":    replaceLocalGitChangeValue(f.args, "--egress", ""),
		"unsupported egress": replaceLocalGitChangeValue(f.args, "--egress", "unrestricted"),
		"unbounded wait":     replaceLocalGitChangeValue(f.args, "--timeout", "0"),
		"publication":        append(append([]string(nil), f.args...), "--publish", "true"),
		"old run identity":   append(append([]string(nil), f.args...), "--run", "existing-claimed-run"),
		"restart":            append(append([]string(nil), f.args...), "--resume", "true"),
		"persistent state":   append(append([]string(nil), f.args...), "--state", "old-state"),
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage: trestle local-git model-review") {
				t.Fatal("noncanonical intent was not refused by the explicit model-review parser")
			}
		})
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 0 || vc != 0 {
		t.Fatal("invalid intent reached a provider")
	}
}

func TestRunLocalGitModelReviewTextAndOutputFailure(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	var stdout, stderr bytes.Buffer
	args := replaceLocalGitChangeValue(f.args, "--format", "text")
	if code := run(args, &stdout, &stderr); code != 4 || stdout.Len() > 64<<10 || !strings.Contains(stdout.String(), "status: findings") || !strings.Contains(stdout.String(), "ci: blocked") || !strings.Contains(stdout.String(), "a.go:2-2") || !strings.Contains(stdout.String(), "empty_memory_index") || strings.Contains(stdout.String()+stderr.String(), localModelKey) || strings.Contains(stdout.String(), localModelSecret) {
		t.Fatal("text result lost bounded finding, CI status, limitation, or privacy")
	}
	for _, name := range []string{"error", "short"} {
		t.Run(name, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			var stderr bytes.Buffer
			code := 0
			if name == "error" {
				code = run(f.args, errorWriter{}, &stderr)
			} else {
				code = run(f.args, shortWriter{}, &stderr)
			}
			if code != 1 || !strings.Contains(stderr.String(), "write result") {
				t.Fatal("output failure returned a successful CI disposition")
			}
		})
	}
}

func TestRunLocalGitModelReviewNewInvocationIsNotResume(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{generationMode: "empty"})
	first, _ := localModelExecute(t, f, f.args, 3)
	second, _ := localModelExecute(t, f, f.args, 3)
	if first.Run == second.Run || first.Scope == second.Scope || first.Request == second.Request || first.Plan == second.Plan || first.Context == second.Context {
		t.Fatal("new opt-in invocation reused an existing claimed identity")
	}
	gc, generation := f.generation.snapshot()
	vc, verification := f.verification.snapshot()
	if gc != 2 || vc != 2 || len(generation) != 2 || len(verification) != 2 {
		t.Fatal("explicit independent requests did not each perform one bounded model attempt")
	}
	if generation[0].Packet.Scope != first.Scope || generation[1].Packet.Scope != second.Scope || verification[0].Packet.Scope != first.Scope || verification[1].Packet.Scope != second.Scope {
		t.Fatal("new request relabeled prior model work")
	}
	if !slices.Contains(second.Limitations, "ephemeral_state_no_resume") {
		t.Fatal("restart limitation is not visible")
	}
}

func TestRunLocalGitModelReviewDoesNotChangeDeterministicReview(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	args := append([]string{"local-git", "review"}, localGitChangeArgs(f.objects, evidence.RevisionAlgorithmSHA1, f.base, f.head)...)
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	var result localGitReviewResult
	if code != 3 || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Contract != "open-trestle/local-git-review-result" || result.SchemaVersion != 2 || stderr.Len() != 0 {
		t.Fatal("existing deterministic review changed its contract")
	}
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if gc != 0 || vc != 0 {
		t.Fatal("deterministic local-git review silently dispatched models")
	}
}

func localModelUnsupportedStorageCases() []string {
	return []string{"nonempty pack", "pack file", "info file", "pack symlink", "info symlink", "pack socket", "info socket", "alternates file", "http alternates empty", "alternates directory", "alternates symlink", "http alternates symlink", "root alternates", "gitdir", "commondir", "worktree marker"}
}

func localModelMutateUnsupportedStorage(t *testing.T, f *localModelFixture, mutation string) {
	t.Helper()
	write := func(name, value string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(f.objects, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mkdir := func(name string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(f.objects, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	switch mutation {
	case "nonempty pack":
		mkdir("pack")
		write("pack/pack-format-marker", "unsupported")
	case "pack file":
		write("pack", "not a directory")
	case "info file":
		write("info", "not a directory")
	case "pack symlink", "info symlink":
		mkdir("format-target")
		name := strings.TrimSuffix(mutation, " symlink")
		if err := os.Symlink("format-target", filepath.Join(f.objects, name)); err != nil {
			t.Fatal(err)
		}
	case "pack socket", "info socket":
		name := strings.TrimSuffix(mutation, " socket")
		// Bind under a short temporary name, then move the socket node into
		// the owned fixture. Long subtest paths can exceed sockaddr_un limits.
		dir, err := os.MkdirTemp("", "local-model-socket-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		socket := filepath.Join(dir, "node")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Skip("local Unix socket fixture is unavailable")
		}
		t.Cleanup(func() { _ = listener.Close() })
		if err := os.Rename(socket, filepath.Join(f.objects, name)); err != nil {
			t.Fatal(err)
		}
	case "alternates file":
		mkdir("info")
		write("info/alternates", "../other-objects\n")
	case "http alternates empty":
		mkdir("info")
		write("info/http-alternates", "")
	case "alternates directory":
		mkdir("info/alternates")
	case "alternates symlink", "http alternates symlink":
		mkdir("info")
		name := "alternates"
		if mutation == "http alternates symlink" {
			name = "http-alternates"
		}
		if err := os.Symlink("missing-target", filepath.Join(f.objects, "info", name)); err != nil {
			t.Fatal(err)
		}
	case "root alternates":
		write("alternates", "../other-objects\n")
	case "gitdir":
		write("gitdir", "../other-git\n")
	case "commondir":
		write("commondir", "../common-git\n")
	case "worktree marker":
		write(".git", "gitdir: ../other-git\n")
	default:
		t.Fatal("unknown local storage fixture")
	}
}

func TestRunLocalGitModelReviewRefusesStorageIndirectionsBeforeWork(t *testing.T) {
	for _, mutation := range localModelUnsupportedStorageCases() {
		t.Run(mutation, func(t *testing.T) {
			f := newLocalModelFixture(t, localModelFixtureOptions{})
			localModelMutateUnsupportedStorage(t, f, mutation)
			result, _ := localModelExecute(t, f, f.args, 3)
			gc, _ := f.generation.snapshot()
			vc, _ := f.verification.snapshot()
			if result.Status != "incomplete" || result.RunStatus != "not_opened" || result.CI != "inconclusive" || len(result.Tasks) != 0 || len(result.Audit) != 0 || result.Context != "" || result.Output != "" || result.Readiness != "" || gc != 0 || vc != 0 {
				t.Fatal("unsupported storage acquired execution authority")
			}
		})
	}
}

func TestRunLocalGitModelReviewAllowsEmptyNormalPackDirectory(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	for _, name := range []string{"pack", "info"} {
		if err := os.Mkdir(filepath.Join(f.objects, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	result, _ := localModelExecute(t, f, f.args, 4)
	gc, _ := f.generation.snapshot()
	vc, _ := f.verification.snapshot()
	if result.Status != "findings" || result.RunStatus != "succeeded" || gc != 1 || vc != 1 {
		t.Fatal("ordinary loose storage with empty format directories was refused")
	}
}

func TestLocalModelCleanupTimeoutUsesConfiguredBoundWithThreeSecondFloor(t *testing.T) {
	for input, want := range map[time.Duration]time.Duration{
		time.Second:      3 * time.Second,
		3 * time.Second:  3 * time.Second,
		30 * time.Second: 30 * time.Second,
	} {
		if got := localModelCleanupTimeout(input); got != want {
			t.Fatalf("cleanup timeout for %s = %s, want %s", input, got, want)
		}
	}
}
