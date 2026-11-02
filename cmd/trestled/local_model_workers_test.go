//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/worker"
)

func localModelWorkerFixture(t *testing.T) ([]string, func(string) string, *daemonBudgetedModelFixture, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity, runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	args, originalEnv, repository, base, head, basePolicy, _ := localFullDaemonFixture(t)
	fake := newDaemonBudgetedModelFixture(t, basePolicy.ReviewPolicyIdentity())
	inventoryBytes, err := os.ReadFile(fake.inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	var inventoryWire map[string]any
	if err := json.Unmarshal(inventoryBytes, &inventoryWire); err != nil {
		t.Fatal(err)
	}
	for _, entry := range inventoryWire["routes"].([]any) {
		route := entry.(map[string]any)
		if route["adapter_id"] == "daemon-adapter-a" {
			route["input_micro_usd_per_million_tokens"] = float64(0)
			route["output_micro_usd_per_million_tokens"] = float64(0)
		}
	}
	inventoryBytes = daemonBudgetedModelJSON(t, inventoryWire)
	if err := os.WriteFile(fake.inventoryPath, inventoryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	policyBytes, err := os.ReadFile(fake.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policyWire map[string]any
	if err := json.Unmarshal(policyBytes, &policyWire); err != nil {
		t.Fatal(err)
	}
	policyWire["schema_version"] = float64(2)
	policyWire["inventory_identity"] = inventory.Identity()
	policyWire["verification_route_record_identity"] = records["daemon-adapter-b"]
	policyWire["pinned_route_record_identity"] = records["daemon-adapter-a"]
	policyWire["preferred_route_record_identities"] = []string{records["daemon-adapter-b"]}
	policyBytes = daemonBudgetedModelJSON(t, policyWire)
	if err := os.WriteFile(fake.policyPath, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	for i := range args {
		if args[i] == "--runtime-route-inventory" {
			args[i+1] = fake.inventoryPath
		}
		if args[i] == "--runtime-policy" {
			args[i+1] = fake.policyPath
		}
	}
	getenv := func(key string) string {
		switch key {
		case daemonBudgetedModelGenerationKeyEnv:
			return daemonBudgetedModelGenerationKey
		case daemonBudgetedModelVerificationKeyEnv:
			return daemonBudgetedModelVerificationKey
		default:
			return originalEnv(key)
		}
	}
	if _, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory); err != nil {
		t.Fatalf("fixture route pair: %v", err)
	}
	return args, getenv, fake, repository, base, head, policy, inventory
}

func TestDaemonLocalModelWorkersRejectUnboundFlagBeforeCredentials(t *testing.T) {
	t.Parallel()
	calls := 0
	getenv := func(string) string { calls++; return "" }
	for _, args := range [][]string{{"--local-model-workers"}, {"--local-model-workers", "--local-full-review"}} {
		if d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{}); err == nil || d != nil {
			t.Fatalf("unbound opt-in accepted: %v", args)
		}
		if calls != 0 {
			t.Fatalf("credential environment read before opt-in validation: %d", calls)
		}
	}
}

func TestDaemonLocalModelWorkersRejectSingleRouteBeforeDispatch(t *testing.T) {
	t.Parallel()
	args, getenv, fake, _, _, _, _, _ := localModelWorkerFixture(t)
	encoded, err := os.ReadFile(fake.inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	wire["routes"] = wire["routes"].([]any)[:1]
	if err := os.WriteFile(fake.inventoryPath, daemonBudgetedModelJSON(t, wire), 0600); err != nil {
		t.Fatal(err)
	}
	args = append(args, "--local-model-workers")
	if d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{}); err == nil || d != nil {
		t.Fatalf("single-route startup accepted: %v", err)
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 0 {
		t.Fatalf("single-route generation dispatched: %d", calls)
	}
	if calls, _, _, _ := fake.verification.snapshot(); calls != 0 {
		t.Fatalf("single-route verification dispatched: %d", calls)
	}
}

func TestDaemonLocalModelWorkersOptInOnly(t *testing.T) {
	t.Parallel()
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	if len(d.supervisors) != 2 {
		t.Fatalf("default must expose only pre-model workers: %d", len(d.supervisors))
	}
	server := httptest.NewServer(d.server.Handler)
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-default-no-model")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if worked, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("premodel worked=%t err=%v", worked, err)
	}
	pending, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := pending.Task("candidates")
	if candidate.Status() != controlplane.TaskRuntimeAvailable {
		t.Fatalf("candidate not available: %s", candidate.Status())
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 0 {
		t.Fatalf("default dispatched generation: %d", calls)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	args = append(args, "--local-model-workers")
	d, err = buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if len(d.supervisors) != 3 {
		t.Fatalf("enabled model worker missing: %d", len(d.supervisors))
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 0 {
		t.Fatalf("startup dispatched: %d", calls)
	}
	if calls, _, _, _ := fake.verification.snapshot(); calls != 0 {
		t.Fatalf("startup verified: %d", calls)
	}
}

func TestDaemonLocalModelWorkersExecuteAdmittedReview(t *testing.T) {
	t.Parallel()
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-model-worker")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if worked, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("premodel worked=%t err=%v", worked, err)
	}
	if _, err := d.diagnosticStore.GetDiagnosticSet(context.Background(), scope); !errors.Is(err, diagnostics.ErrSetNotFound) {
		t.Fatalf("full-run provisional diagnostic present before verification: %v", err)
	}
	activeProgress, err := api.GetRunProgress(context.Background(), scope)
	if err != nil {
		t.Fatalf("active progress: %v", err)
	}
	if activeProgress.Progress.Change.State != "available" || activeProgress.Progress.Deterministic.State != "available" || activeProgress.Progress.Context.State != "available" || activeProgress.Progress.Context.Selected == nil || activeProgress.Progress.Verification.State != "not_run" || activeProgress.Progress.Verification.Verified != nil {
		t.Fatalf("active context coverage must precede generation: %+v", activeProgress.Progress)
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 0 {
		t.Fatalf("progress dispatched generation: %d", calls)
	}
	cliPath := filepath.Join(t.TempDir(), "trestle")
	build := exec.Command("go", "build", "-o", cliPath, "../trestle")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, output)
	}
	command := func(args []string) []byte {
		t.Helper()
		cmd := exec.Command(cliPath, args...)
		cmd.Env = append(os.Environ(), "OPEN_TRESTLE_API_TOKEN="+getenv("OPEN_TRESTLE_API_TOKEN"))
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI progress: %v %s", err, output)
		}
		return bytes.TrimSpace(output)
	}
	cliArgs := []string{"--server", server.URL}
	packagedAssertProgressParity(t, command, cliArgs, scope, api, nil)
	if worked, err := d.supervisors[2].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("model worked=%t err=%v", worked, err)
	}
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"candidates", "verification", "readiness"} {
		task, found := receipt.Task(key)
		if !found || task.Status() != controlplane.TaskRuntimeSucceeded {
			t.Fatalf("%s not succeeded: status=%s failure=%s output=%s", key, task.Status(), task.Failure(), task.OutputIdentity())
		}
	}
	if calls, _, _, failures := fake.generation.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("generation calls=%d failures=%v", calls, failures)
	}
	if calls, _, _, failures := fake.verification.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("verification calls=%d failures=%v", calls, failures)
	}
	if _, err := d.diagnosticStore.GetDiagnosticSet(context.Background(), scope); !errors.Is(err, diagnostics.ErrSetNotFound) {
		t.Fatalf("diagnostics published before terminal projection: %v", err)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
		t.Fatalf("terminal projection: %v", err)
	}
	final, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || final.SchemaVersion() != 7 || final.Outcome() != diagnostics.FinalOutcomeCompleted || final.AnalysisResultIdentity() == "" || final.VerifiedSetIdentity() == "" || len(final.DeterministicChecks()) != 1 {
		t.Fatalf("final diagnostics invalid: version=%d outcome=%s err=%v", final.SchemaVersion(), final.Outcome(), err)
	}
	finalProgress, err := api.GetRunProgress(context.Background(), scope)
	if err != nil {
		t.Fatalf("final progress: %v", err)
	}
	coverage := finalProgress.Progress
	if finalProgress.Run.Identity() != receipt.Identity() || coverage.Change.State != "available" || coverage.Deterministic.State != "available" || coverage.Context.State != "available" || coverage.Verification.State != "available" {
		t.Fatalf("final progress missing canonical closure: %+v", coverage)
	}
	if coverage.Context.Analyzed == nil || coverage.Context.Selected == nil || coverage.Context.Omitted == nil || *coverage.Context.Analyzed != int(final.SourceAnalyzedCount()) || *coverage.Context.Selected != int(final.SourceSelectedCount()) || *coverage.Context.Omitted != int(final.SourceOmittedCount()) || coverage.Verification.Candidates == nil || coverage.Verification.Verified == nil || coverage.Verification.Rejected == nil || coverage.Verification.Inconclusive == nil || *coverage.Verification.Candidates != int(final.CandidateCount()) || *coverage.Verification.Verified != int(final.VerifiedCount()) || *coverage.Verification.Rejected != int(final.RejectedCount()) || *coverage.Verification.Inconclusive != int(final.InconclusiveCount()) {
		t.Fatalf("progress differs from canonical final evidence: %+v", coverage)
	}
	packagedAssertProgressParity(t, command, cliArgs, scope, api, &final)
	if final.SnapshotIdentity() == "" || final.ReviewSnapshotIdentity() == "" || final.SnapshotIdentity() == final.ReviewSnapshotIdentity() {
		t.Fatalf("source and selected review snapshots not kept distinct")
	}
	analysisTask, _ := receipt.Task("analysis")
	changeTask, _ := receipt.Task("change")
	verificationTask, _ := receipt.Task("verification")
	_, originalVerified, err := publicationhandler.BuildFinalDiagnosticParts(context.Background(), d.artifactStore, scope, analysisTask.OutputIdentity(), changeTask.OutputIdentity(), verificationTask.OutputIdentity(), time.Now().UTC())
	if err != nil {
		t.Fatalf("original verified evidence: %v", err)
	}
	encoded, err := diagnostics.EncodeSet(final)
	if err != nil {
		t.Fatalf("encode terminal result: %v", err)
	}
	var finalParts struct {
		Verified json.RawMessage `json:"verified"`
	}
	if err := json.Unmarshal(encoded, &finalParts); err != nil {
		t.Fatalf("parse terminal parts: %v", err)
	}
	preservedVerified, err := diagnostics.ParseSet(finalParts.Verified)
	if err != nil || preservedVerified.Identity() != originalVerified.Identity() || preservedVerified.SnapshotIdentity() != originalVerified.SnapshotIdentity() {
		t.Fatalf("embedded verification identity changed: %v", err)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
		t.Fatalf("terminal projection replay: %v", err)
	}
	replayed, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || replayed.Identity() != final.Identity() {
		t.Fatalf("final diagnostic identity changed: %v", err)
	}
}

func TestDaemonLocalModelWorkersResumeAfterCandidatesWithoutRedispatch(t *testing.T) {
	t.Parallel()
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-model-restart")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if worked, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("premodel worked=%t err=%v", worked, err)
	}
	dispatchers, err := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, environmentOpenAICredentialResolver{getenv: getenv})
	if err != nil {
		t.Fatal(err)
	}
	var ledger *audit.FileLedger
	for _, closer := range d.closers {
		if file, ok := closer.(*audit.FileLedger); ok {
			ledger = file
		}
	}
	if ledger == nil {
		t.Fatal("daemon audit ledger missing")
	}
	generation, err := modelhandler.NewGenerationHandler(d.artifactStore, dispatchers, ledger, httpapi.SystemClock{}, daemonTestGenerationSanitizer().ExpectedBinaryDigests())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := api.GetRunPlan(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	candidateTask, _ := plan.Task("candidates")
	if generation.HandlerIdentity() != candidateTask.HandlerIdentity() {
		t.Fatal("generation identity changed")
	}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{generation})
	if err != nil {
		t.Fatal(err)
	}
	localControl, err := worker.NewLocalControl(d.journal, httpapi.SystemClock{}, "test-model-candidate")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := worker.New(localControl, catalog, worker.Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 10 * time.Second, ExecutionTimeout: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if worked, _, err := runner.RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("generation worked=%t err=%v", worked, err)
	}
	before, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := before.Task("candidates")
	if candidate.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatalf("candidate %s", candidate.Status())
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 1 {
		t.Fatalf("generation dispatch=%d", calls)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server = httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if worked, err := d.supervisors[2].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("restarted model worked=%t err=%v", worked, err)
	}
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"candidates", "verification", "readiness"} {
		task, found := receipt.Task(key)
		if !found || task.Status() != controlplane.TaskRuntimeSucceeded {
			t.Fatalf("%s not succeeded: status=%s failure=%s output=%s", key, task.Status(), task.Failure(), task.OutputIdentity())
		}
	}
	if calls, _, _, failures := fake.generation.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("generation calls=%d failures=%v", calls, failures)
	}
	if calls, _, _, failures := fake.verification.snapshot(); calls != 1 || len(failures) != 0 {
		t.Fatalf("verification calls=%d failures=%v", calls, failures)
	}
	again, err := api.GetRun(context.Background(), scope)
	if err != nil || again.Identity() != receipt.Identity() {
		t.Fatalf("terminal receipt changed: %v", err)
	}
}
func TestDaemonLocalModelWorkersMissingVerifierDoesNotPromote(t *testing.T) {
	t.Parallel()
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-model-no-verifier")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if worked, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("premodel worked=%t err=%v", worked, err)
	}
	fake.verification.server.Close()
	if worked, err := d.supervisors[2].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil || !worked {
		t.Fatalf("model worked=%t err=%v", worked, err)
	}
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := receipt.Task("candidates")
	verification, _ := receipt.Task("verification")
	readiness, _ := receipt.Task("readiness")
	if candidate.Status() != controlplane.TaskRuntimeSucceeded || verification.Status() != controlplane.TaskRuntimeFailed || verification.Failure() != controlplane.RunFailureTransient || readiness.Status() == controlplane.TaskRuntimeSucceeded || receipt.Status() == controlplane.ReviewRunSucceeded {
		t.Fatalf("missing verifier promoted: candidate=%s verification=%s failure=%s readiness=%s run=%s", candidate.Status(), verification.Status(), verification.Failure(), readiness.Status(), receipt.Status())
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 1 {
		t.Fatalf("generation calls=%d", calls)
	}
	if calls, _, _, _ := fake.verification.snapshot(); calls != 0 {
		t.Fatalf("verifier endpoint calls=%d", calls)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
		t.Fatalf("missing verifier terminal projection: %v", err)
	}
	final, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || final.SchemaVersion() != 7 || final.Outcome() != diagnostics.FinalOutcomeInconclusive || final.VerifiedSetIdentity() != "" || final.AnalysisResultIdentity() == "" {
		t.Fatalf("missing verifier diagnostic promotion: version=%d outcome=%s verified=%q err=%v", final.SchemaVersion(), final.Outcome(), final.VerifiedSetIdentity(), err)
	}
}

func TestDaemonLocalModelWorkersLaterRunAndRestart(t *testing.T) {
	t.Parallel()
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	build := func() *daemon {
		t.Helper()
		d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := build()
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(func() { server.Close() })
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	completed := map[string]string{}
	for _, run := range []string{"run-first", "run-later"} {
		scope, _ := audit.NewReviewScope("tenant-a", "repo-a", run)
		intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
			t.Fatal(err)
		}
		for _, index := range []int{1, 2, 1} {
			if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
				t.Fatalf("run %s supervisor %d: %v", run, index, err)
			}
		}
		receipt, err := api.GetRun(context.Background(), scope)
		if err != nil || receipt.Status() != controlplane.ReviewRunSucceeded {
			t.Fatalf("run %s status=%s err=%v", run, receipt.Status(), err)
		}
		final, err := api.GetDiagnosticSet(context.Background(), scope)
		if err != nil || final.Outcome() != diagnostics.FinalOutcomeCompleted {
			t.Fatalf("run %s final=%s err=%v", run, final.Outcome(), err)
		}
		completed[run] = final.Identity()
	}
	if calls, _, _, failures := fake.generation.snapshot(); calls != 2 || len(failures) != 0 {
		t.Fatalf("generation calls=%d failures=%v", calls, failures)
	}
	if calls, _, _, failures := fake.verification.snapshot(); calls != 2 || len(failures) != 0 {
		t.Fatalf("verification calls=%d failures=%v", calls, failures)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = build()
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatalf("restart supervisor %d: %v", index, err)
		}
	}
	for run, id := range completed {
		scope, _ := audit.NewReviewScope("tenant-a", "repo-a", run)
		final, err := api.GetDiagnosticSet(context.Background(), scope)
		if err != nil || final.Identity() != id {
			t.Fatalf("restart run %s changed final: %v", run, err)
		}
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 2 {
		t.Fatalf("restart redispatched generation: %d", calls)
	}
	if calls, _, _, _ := fake.verification.snapshot(); calls != 2 {
		t.Fatalf("restart redispatched verification: %d", calls)
	}
}

func TestDaemonLocalModelWorkersVerificationOutcomes(t *testing.T) {
	t.Parallel()
	for _, outcome := range []string{"rejected", "inconclusive"} {
		t.Run(outcome, func(t *testing.T) {
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			fake.verification.verificationOutcome = outcome
			args = append(args, "--local-model-workers")
			d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			server := httptest.NewServer(d.server.Handler)
			defer server.Close()
			api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-"+outcome)
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			admitted, err := api.SubmitLocalFullReview(context.Background(), intent)
			if err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{1, 2, 1} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			final, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil || final.VerifiedCount() != 0 || len(final.Findings()) != 0 || final.CandidateCount() != 1 || final.VerifiedSetIdentity() == "" {
				t.Fatalf("verdict outcome=%s candidates=%d verified=%d err=%v", final.Outcome(), final.CandidateCount(), final.VerifiedCount(), err)
			}
			if outcome == "rejected" && (final.RejectedCount() != 1 || final.InconclusiveCount() != 0) || outcome == "inconclusive" && (final.InconclusiveCount() != 1 || final.RejectedCount() != 0) {
				t.Fatal("verdict counts changed")
			}
			progress, err := api.GetRunProgress(context.Background(), scope)
			if err != nil || progress.Progress.Verification.Verified == nil || *progress.Progress.Verification.Verified != 0 {
				t.Fatalf("verified zero missing: %v", err)
			}
			for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
				if calls, _, _, failures := endpoint.snapshot(); calls != 1 || len(failures) != 0 {
					t.Fatalf("dispatch calls=%d failures=%v", calls, failures)
				}
			}
			canonical, err := diagnostics.EncodeSet(final)
			if err != nil {
				t.Fatal(err)
			}
			beforeProgress, err := json.Marshal(progress)
			if err != nil {
				t.Fatal(err)
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			d, err = buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			server = httptest.NewServer(d.server.Handler)
			defer server.Close()
			api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			replay, err := api.SubmitLocalFullReview(context.Background(), intent)
			if err != nil || replay.PlanIdentity() != admitted.PlanIdentity() {
				t.Fatalf("verdict replay changed plan: %v", err)
			}
			for _, index := range []int{1, 2} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatalf("verdict restart supervisor %d: %v", index, err)
				}
			}
			reopened, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			reencoded, err := diagnostics.EncodeSet(reopened)
			if err != nil || !bytes.Equal(canonical, reencoded) {
				t.Fatalf("verdict changed after restart: %v", err)
			}
			reopenedProgress, err := api.GetRunProgress(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			afterProgress, err := json.Marshal(reopenedProgress)
			if err != nil || !bytes.Equal(beforeProgress, afterProgress) {
				t.Fatalf("verdict progress changed after restart: %v", err)
			}
			for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
				if calls, _, _, failures := endpoint.snapshot(); calls != 1 || len(failures) != 0 {
					t.Fatalf("verdict restart redispatched: calls=%d failures=%v", calls, failures)
				}
			}
		})
	}
}

func TestDaemonLocalModelWorkersCanceledBeforeGenerationSurvivesRestart(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"unclaimed", "claimed", "route-attempt"} {
		t.Run(mode, func(t *testing.T) {
			testDaemonLocalModelWorkersCanceledRestart(t, mode)
		})
	}
}

func testDaemonLocalModelWorkersCanceledRestart(t *testing.T, mode string) {
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	build := func() *daemon {
		t.Helper()
		d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := build()
	t.Cleanup(func() { d.Close() })
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(func() { server.Close() })
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-cancel-restart")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if mode == "claimed" {
		plan, err := api.GetRunPlan(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		task, _ := plan.Task("candidates")
		control, err := worker.NewLocalControl(d.journal, httpapi.SystemClock{}, "canceled-claim")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := control.ClaimTask(context.Background(), scope, task.Key(), task.HandlerIdentity()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := api.CancelRun(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	final, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || final.Outcome() != diagnostics.FinalOutcomeCanceled || len(final.Findings()) != 0 || final.VerifiedSetIdentity() != "" {
		t.Fatalf("canceled outcome=%s err=%v", final.Outcome(), err)
	}
	before, err := diagnostics.EncodeSet(final)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if mode == "route-attempt" {
		ledger, err := audit.NewFileLedger(filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), "audit"))
		if err != nil {
			t.Fatal(err)
		}
		events, err := ledger.Read(context.Background(), scope, 0, 64)
		if err != nil || len(events) == 0 {
			ledger.Close()
			t.Fatalf("route audit missing: %v", err)
		}
		last := events[len(events)-1]
		event, err := audit.NewEvent(scope, last.Sequence()+1, last.Identity(), audit.EventRouteAttemptClaimed, last.SubjectIdentity(), nil, time.Now().UTC())
		if err != nil {
			ledger.Close()
			t.Fatal(err)
		}
		if err := ledger.Append(context.Background(), last.Identity(), event); err != nil {
			ledger.Close()
			t.Fatal(err)
		}
		if err := ledger.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if mode != "unclaimed" {
		restarted, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
		if restarted != nil || !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
			if restarted != nil {
				restarted.Close()
			}
			t.Fatalf("canceled claimed candidate startup did not refuse: %v", err)
		}
		return
	}
	d = build()
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	after, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := diagnostics.EncodeSet(after)
	if err != nil || !bytes.Equal(before, encoded) {
		t.Fatalf("canceled result changed after restart: %v", err)
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if calls, _, _, failures := endpoint.snapshot(); calls != 0 || len(failures) != 0 {
			t.Fatalf("canceled run dispatched: calls=%d failures=%v", calls, failures)
		}
	}
	laterScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-after-canceled")
	laterIntent, err := runtimecatalog.NewLocalFullReviewIntent(laterScope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), laterIntent); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2, 1} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	laterFinal, err := api.GetDiagnosticSet(context.Background(), laterScope)
	if err != nil || laterFinal.Outcome() != diagnostics.FinalOutcomeCompleted {
		t.Fatalf("later outcome=%s err=%v", laterFinal.Outcome(), err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = build()
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []struct {
		scope    audit.ReviewScope
		identity string
	}{{scope, final.Identity()}, {laterScope, laterFinal.Identity()}} {
		got, err := api.GetDiagnosticSet(context.Background(), expected.scope)
		if err != nil || got.Identity() != expected.identity {
			t.Fatalf("mixed canceled/completed restart changed result: %v", err)
		}
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if calls, _, _, failures := endpoint.snapshot(); calls != 1 || len(failures) != 0 {
			t.Fatalf("later-run dispatch calls=%d failures=%v", calls, failures)
		}
	}
}

func TestDaemonLocalModelWorkersOfflineBackupPreservesOwnerBoundary(t *testing.T) {
	t.Parallel()
	for _, replaceRoot := range []bool{false, true} {
		name := "in-place"
		if replaceRoot {
			name = "replacement-root"
		}
		t.Run(name, func(t *testing.T) {
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			args = append(args, "--local-model-workers")
			deps := daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()}
			d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { d.Close() }()
			server := httptest.NewServer(d.server.Handler)
			defer func() { server.Close() }()
			api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-backup")
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{1, 2, 1} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			before, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil || before.Outcome() != diagnostics.FinalOutcomeCompleted {
				t.Fatalf("backup result=%s err=%v", before.Outcome(), err)
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			statePath := daemonTestFlagValue(t, args, "--state-dir")
			setupPath := daemonTestFlagValue(t, args, "--setup-state")
			backup := t.TempDir()
			if err := os.Chmod(backup, 0700); err != nil {
				t.Fatal(err)
			}
			// The daemon is closed. Copy regular owned bytes and modes, never links.
			saved := map[string]string{}
			err = filepath.WalkDir(filepath.Dir(setupPath), func(path string, entry os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if entry.IsDir() {
					return nil
				}
				info, err := entry.Info()
				if err != nil {
					return err
				}
				if !info.Mode().IsRegular() {
					return errors.New("backup fixture contains a nonregular file")
				}
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				relative, err := filepath.Rel(filepath.Dir(setupPath), path)
				if err != nil {
					return err
				}
				copyPath := filepath.Join(backup, relative)
				if err := os.MkdirAll(filepath.Dir(copyPath), 0700); err != nil {
					return err
				}
				if err := os.WriteFile(copyPath, body, info.Mode().Perm()); err != nil {
					return err
				}
				saved[path] = copyPath
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if replaceRoot {
				if err := os.Rename(statePath, statePath+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(statePath, 0700); err != nil {
					t.Fatal(err)
				}
			}
			// Simulate lost journal bytes only after capturing the closed recovery point.
			journalPath := filepath.Join(statePath, scope.Identity()+".run.jsonl")
			if !replaceRoot {
				if err := os.WriteFile(journalPath, []byte("damaged\n"), 0600); err != nil {
					t.Fatal(err)
				}
				broken, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
				if broken != nil {
					broken.Close()
				}
				if err == nil {
					t.Fatal("damaged recovery point accepted")
				}
			}
			for path, copyPath := range saved {
				body, err := os.ReadFile(copyPath)
				if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(copyPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, info.Mode().Perm()); err != nil {
					t.Fatal(err)
				}
			}
			restored, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
			if replaceRoot {
				if restored != nil {
					restored.Close()
				}
				if !errors.Is(err, ErrLocalSourceOwnerMismatch) {
					t.Fatalf("replacement owner root not refused: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			d = restored
			server = httptest.NewServer(d.server.Handler)
			api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{1, 2} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			after, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil || after.Identity() != before.Identity() {
				t.Fatalf("restored result changed: %v", err)
			}
			for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
				if calls, _, _, failures := endpoint.snapshot(); calls != 1 || len(failures) != 0 {
					t.Fatalf("restore dispatched: calls=%d failures=%v", calls, failures)
				}
			}
		})
	}
}

func TestDaemonLocalModelWorkersExpiredPacketLaterRunAndRestart(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"complete", "expired-route-attempt", "expired-orphan", "expired-marker"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			testDaemonLocalModelWorkersExpiredPacketRestart(t, mode)
		})
	}
}

func testDaemonLocalModelWorkersExpiredPacketRestart(t *testing.T, mode string) {
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
	var d *daemon
	var expiryErr error
	sanitizerCalled := false
	injectedReturnReached := false
	sanitizer := bootPacketExpirySanitizer{GenerationRequestSanitizer: expireOwnerSanitizer{GenerationRequestSanitizer: daemonTestGenerationSanitizer(), expire: func() {
		sanitizerCalled = true
		facts, err := d.journal.(*controlplane.FileRunJournal).InspectHistoricalContextPackets(context.Background())
		if err != nil || len(facts) != 1 {
			expiryErr = fmt.Errorf("packet facts count=%d: %v", len(facts), err)
			return
		}
		clock.mu.Lock()
		clock.at = facts[0].LeaseEvent().LeaseExpiresAt().Add(time.Millisecond)
		clock.mu.Unlock()
	}}, injected: &injectedReturnReached}
	build := func(expire bool) *daemon {
		t.Helper()
		deps := daemonDependencies{openPostgres: postgresstore.Open, clock: clock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()}
		if expire {
			deps.generationSanitizer = sanitizer
		}
		built, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
		if err != nil {
			t.Fatal(err)
		}
		return built
	}
	d = build(true)
	t.Cleanup(func() { d.Close() })
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(func() { server.Close() })
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-expired-packet")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err == nil {
		t.Fatal("expired packet worker unexpectedly succeeded")
	}
	if expiryErr != nil || !sanitizerCalled || !injectedReturnReached {
		t.Fatalf("sanitizer called=%t injected=%t err=%v", sanitizerCalled, injectedReturnReached, expiryErr)
	}
	facts, err := d.journal.(*controlplane.FileRunJournal).InspectHistoricalContextPackets(context.Background())
	if err != nil || len(facts) != 1 || facts[0].FinalHeadIdentity() != facts[0].PreparedEvent().Identity() {
		t.Fatalf("not exact v4: %v", err)
	}
	packetIdentity := facts[0].PreparedEvent().PacketDescriptor().ArtifactIdentity
	marker := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), scope.Identity()+".scope-intent.json")
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("boot fixture has unresolved marker: %v", err)
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if calls, _, _, failures := endpoint.snapshot(); calls != 0 || len(failures) != 0 {
			t.Fatalf("expired packet dispatched: calls=%d failures=%v", calls, failures)
		}
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = build(false)
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	expiredFinal, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || expiredFinal.Outcome() != diagnostics.FinalOutcomeFailed || len(expiredFinal.Findings()) != 0 {
		t.Fatalf("expired final=%s err=%v", expiredFinal.Outcome(), err)
	}
	laterScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-after-expired-packet")
	laterIntent, err := runtimecatalog.NewLocalFullReviewIntent(laterScope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), laterIntent); err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2, 1} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	laterFinal, err := api.GetDiagnosticSet(context.Background(), laterScope)
	if err != nil || laterFinal.Outcome() != diagnostics.FinalOutcomeCompleted {
		t.Fatalf("later final=%s err=%v", laterFinal.Outcome(), err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if mode != "complete" {
		statePath := daemonTestFlagValue(t, args, "--state-dir")
		journalPath := filepath.Join(statePath, scope.Identity()+".run.jsonl")
		before, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "expired-route-attempt" {
			ledger, err := audit.NewFileLedger(filepath.Join(statePath, "audit"))
			if err != nil {
				t.Fatal(err)
			}
			last, present, err := ledger.Head(context.Background(), scope)
			if err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			sequence, previous := uint64(1), ""
			if present {
				sequence, previous = last.Sequence()+1, last.Identity()
			}
			event, err := audit.NewEvent(scope, sequence, previous, audit.EventRouteAttemptClaimed, packetIdentity, nil, clock.Now())
			if err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			if err := ledger.Append(context.Background(), last.Identity(), event); err != nil {
				ledger.Close()
				t.Fatal(err)
			}
			if err := ledger.Close(); err != nil {
				t.Fatal(err)
			}
		} else if mode == "expired-marker" {
			marker := filepath.Join(statePath, scope.Identity()+".scope-intent.json")
			if err := os.WriteFile(marker, []byte("unknown"), 0600); err != nil {
				t.Fatal(err)
			}
		} else {
			orphan := filepath.Join(statePath, "artifacts", scope.Identity()+"-"+strings.Repeat("0", 64)+".artifact.json")
			if err := os.WriteFile(orphan, []byte("unproven"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		restarted, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: clock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
		if restarted != nil {
			restarted.Close()
			t.Fatal("unproven mixed history admitted")
		}
		if err == nil {
			t.Fatal("unproven mixed history returned no refusal")
		}
		after, readErr := os.ReadFile(journalPath)
		if readErr != nil || !bytes.Equal(before, after) {
			t.Fatalf("mixed refusal mutated expired journal: %v", readErr)
		}
		return
	}
	d = build(false)
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []struct {
		scope    audit.ReviewScope
		identity string
	}{{scope, expiredFinal.Identity()}, {laterScope, laterFinal.Identity()}} {
		got, err := api.GetDiagnosticSet(context.Background(), expected.scope)
		if err != nil || got.Identity() != expected.identity {
			t.Fatalf("mixed expired/completed restart changed result: %v", err)
		}
	}
	if _, err := d.artifactStore.Get(context.Background(), scope, packetIdentity, clock.Now()); err != nil {
		t.Fatalf("expired packet evidence lost: %v", err)
	}
	for _, endpoint := range []*daemonBudgetedModelEndpoint{fake.generation, fake.verification} {
		if calls, _, _, failures := endpoint.snapshot(); calls != 1 || len(failures) != 0 {
			t.Fatalf("mixed restart calls=%d failures=%v", calls, failures)
		}
	}
}
