//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/worker"
)

// This reconstructs a valid journal prefix after a real candidate Put; it is
// not a process interrupted at the instruction boundary.
func TestDaemonLocalFullCandidatePutSyntheticRestartPreservesDispatchFence(t *testing.T) {
	runCandidatePutSyntheticRestart(t, 0)
}

// A candidate request the provider rate-limited twice and the handler retried
// on the same route leaves the same exhausted lease after the synthetic crash,
// and the daemon still boots, before and after retention lapses, from the
// journal and the retried attempts' audit.
func TestDaemonLocalFullCandidateRateLimitedRestartBootsAfterLeaseExpiry(t *testing.T) {
	runCandidatePutSyntheticRestart(t, 2)
}

// runCandidatePutSyntheticRestart drives a candidate generation the provider
// first rate-limits rateLimits times, cuts the journal back to its lease, and
// restarts after the lease and after the retention lapse.
func runCandidatePutSyntheticRestart(t *testing.T, rateLimits int) {
	ctx := context.Background()
	model := newDaemonBudgetedModelFixture(t, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	model.generation.rateLimits = rateLimits
	sent := 1 + rateLimits
	args, originalEnv, repository, base, head, _, _ := localFullDaemonFixture(t)
	policyPath := daemonTestFlagValue(t, args, "--runtime-policy")
	inventoryPath := daemonTestFlagValue(t, args, "--runtime-route-inventory")
	inventoryBytes, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	var inventoryWire map[string]any
	if err := json.Unmarshal(inventoryBytes, &inventoryWire); err != nil {
		t.Fatal(err)
	}
	for _, item := range inventoryWire["routes"].([]any) {
		route := item.(map[string]any)
		route["model_version"] = ""
		if strings.HasSuffix(route["adapter_id"].(string), "-a") {
			route["input_micro_usd_per_million_tokens"] = float64(0)
			route["output_micro_usd_per_million_tokens"] = float64(0)
		}
	}
	inventoryBytes = daemonBudgetedModelJSON(t, inventoryWire)
	if err := os.WriteFile(inventoryPath, inventoryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policyWire map[string]any
	if err := json.Unmarshal(encoded, &policyWire); err != nil {
		t.Fatal(err)
	}
	// The shared fake accepts exactly 4096 output tokens. Retain the
	// local schema-v2 nonzero-cost allowance while rebinding inventory IDs.
	policyWire["max_output_tokens"] = float64(4096)
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	policyWire["inventory_identity"] = inventory.Identity()
	policyWire["pinned_route_record_identity"] = records["adapter-a"]
	policyWire["verification_route_record_identity"] = records["adapter-b"]
	policyWire["preferred_route_record_identities"] = []string{records["adapter-b"]}
	connections := policyWire["connections"].([]any)
	for index, endpoint := range []string{model.generation.URL() + "/v1", model.verification.URL() + "/v1"} {
		connection := connections[index].(map[string]any)
		connection["endpoint"] = endpoint
		connection["credential_environment"] = []string{daemonBudgetedModelGenerationKeyEnv, daemonBudgetedModelVerificationKeyEnv}[index]
	}
	encoded = daemonBudgetedModelJSON(t, policyWire)
	if err := os.WriteFile(policyPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(encoded), inventory)
	if err != nil {
		t.Fatal(err)
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
	deps := daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()}
	d, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(d.server.Handler)
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-candidate-restart")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(ctx, intent); err != nil {
		t.Fatal(err)
	}
	if worked, err := d.supervisors[1].(*worker.RepositorySupervisor).RunOnce(ctx); err != nil || !worked {
		t.Fatalf("pre-model worked=%t err=%v", worked, err)
	}
	if calls, _, _, _ := model.generation.snapshot(); calls != 0 {
		t.Fatalf("pre-model dispatched generation: %d", calls)
	}
	if calls, _, _, _ := model.verification.snapshot(); calls != 0 {
		t.Fatalf("pre-model dispatched verification: %d", calls)
	}
	receipt, err := api.GetRun(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, ok := receipt.Task("candidates")
	if !ok || candidate.Status() != controlplane.TaskRuntimeAvailable {
		t.Fatalf("candidate before model=%#v", candidate)
	}
	inputTask, ok := receipt.Task("context")
	if !ok || inputTask.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatalf("context=%#v", inputTask)
	}
	inputArtifact, err := d.artifactStore.Get(ctx, scope, inputTask.OutputIdentity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if err != nil || !input.IsSanitized() {
		t.Fatalf("generation input=%v", err)
	}
	contextArtifact, err := d.artifactStore.Get(ctx, scope, input.ContextArtifactIdentity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	// Construct only the production generation handler. The daemon intentionally
	// exposes no model worker, so a test-scoped one-task runner supplies the hook.
	dispatchers, err := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, environmentOpenAICredentialResolver{getenv: getenv})
	if err != nil {
		t.Fatal(err)
	}
	var ledger *audit.FileLedger
	for _, closer := range d.closers {
		if value, ok := closer.(*audit.FileLedger); ok {
			ledger = value
			break
		}
	}
	if ledger == nil {
		t.Fatal("local daemon did not own a file audit ledger")
	}
	generation, err := modelhandler.NewGenerationHandler(d.artifactStore, dispatchers, ledger, httpapi.SystemClock{}, deps.generationSanitizer.ExpectedBinaryDigests())
	if err != nil {
		t.Fatal(err)
	}
	if generation.HandlerIdentity() != candidate.HandlerIdentity() {
		t.Fatal("test handler identity differs from admitted handler")
	}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{generation})
	if err != nil {
		t.Fatal(err)
	}
	localControl, err := worker.NewLocalControl(d.journal, httpapi.SystemClock{}, "test-candidate-worker")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := worker.New(localControl, catalog, worker.Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 10 * time.Second, ExecutionTimeout: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if worked, _, err := runner.RunOnce(ctx); err != nil || !worked {
		t.Fatalf("candidate worker worked=%t err=%v", worked, err)
	}
	receipt, err = api.GetRun(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ = receipt.Task("candidates")
	if candidate.Status() != controlplane.TaskRuntimeSucceeded {
		calls, _, captures, failures := model.generation.snapshot()
		t.Fatalf("generation not successful: status=%s failure=%s output=%s audit=%v fake=%d captures=%d failures=%v", candidate.Status(), candidate.Failure(), candidate.OutputIdentity(), candidateRestartAuditSummary(t, ctx, ledger, scope), calls, len(captures), failures)
	}
	outputID := candidate.OutputIdentity()
	outputArtifact, err := d.artifactStore.Get(ctx, scope, outputID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	result, err := modelhandler.ParseGenerationResultArtifact(outputArtifact, inputArtifact, contextArtifact)
	if err != nil || len(result.Candidates().Findings()) != 1 {
		t.Fatalf("stored candidate invalid: %v", err)
	}
	auditEvents, err := ledger.Read(ctx, scope, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	assertCandidateRestartAudit(t, auditEvents, rateLimits)
	if calls, _, captures, failures := model.generation.snapshot(); calls != sent || len(captures) != 1 || len(failures) != 0 {
		t.Fatalf("generation calls=%d captures=%d failures=%v", calls, len(captures), failures)
	}
	if calls, _, _, _ := model.verification.snapshot(); calls != 0 {
		t.Fatalf("verification calls=%d", calls)
	}
	events, err := d.journal.Read(ctx, scope, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	leaseIndex := -1
	var leaseExpires time.Time
	for i, event := range events {
		if event.TaskKey() == "candidates" && event.Kind() == controlplane.RunEventTaskLeased {
			leaseIndex = i
			leaseExpires = event.LeaseExpiresAt()
		}
	}
	if leaseIndex < 0 {
		t.Fatal("candidate lease absent")
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	streamPath := filepath.Join(daemonTestFlagValue(t, args, "--state-dir"), scope.Identity()+".run.jsonl")
	original, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(original), []byte("\n"))
	if len(lines) != len(events)+1 || !bytes.Contains(lines[leaseIndex+1], []byte(`"kind":"task_leased"`)) {
		t.Fatalf("invalid candidate lease prefix: events=%d lines=%d lease=%d", len(events), len(lines), leaseIndex)
	}
	stream, err := os.OpenFile(streamPath, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	prefix := append(bytes.Join(lines[:leaseIndex+2], []byte("\n")), '\n')
	if _, err := stream.Write(prefix); err != nil {
		t.Fatal(err)
	}
	if err := stream.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	future := daemonBudgetedRawClock{at: leaseExpires.Add(5 * time.Second).Truncate(time.Millisecond)}
	deps.clock = future
	d, err = buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("restart after candidate Put: %v", err)
	}
	defer d.Close()
	if calls, _, _, _ := model.generation.snapshot(); calls != sent {
		t.Fatalf("restart dispatched generation: %d", calls)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	plan, found, err := d.journal.LoadPlan(ctx, scope)
	if err != nil || !found {
		t.Fatalf("reopened plan found=%t err=%v", found, err)
	}
	state, err := coordinator.Advance(ctx, plan, future.Now())
	if err != nil {
		t.Fatal(err)
	}
	settled, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ = settled.Task("candidates")
	if candidate.Status() != controlplane.TaskRuntimeFailed || candidate.Failure() != controlplane.RunFailureResourceLimit {
		t.Fatalf("candidate not exhausted: %#v", candidate)
	}
	for _, key := range []string{"verification", "readiness"} {
		task, _ := settled.Task(key)
		if task.Status() == controlplane.TaskRuntimeAvailable || task.Status() == controlplane.TaskRuntimeLeased || task.Status() == controlplane.TaskRuntimeSucceeded {
			t.Fatalf("downstream task claimable: %s %s", key, task.Status())
		}
	}
	if _, err := d.artifactStore.Get(ctx, scope, outputID, future.Now()); err != nil {
		t.Fatalf("candidate artifact missing after restart: %v", err)
	}
	events, err = d.journal.Read(ctx, scope, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	leased, failed := 0, 0
	for _, event := range events {
		if event.TaskKey() != "candidates" {
			continue
		}
		switch event.Kind() {
		case controlplane.RunEventTaskLeased:
			leased++
		case controlplane.RunEventTaskFailed:
			if event.Failure() != controlplane.RunFailureResourceLimit {
				t.Fatalf("wrong terminal failure: %s", event.Failure())
			}
			failed++
		case controlplane.RunEventTaskSucceeded:
			t.Fatal("candidate success survived synthetic prefix")
		}
	}
	if leased != 1 || failed != 1 {
		t.Fatalf("candidate lease/failure counts=%d/%d", leased, failed)
	}
	var reopened *audit.FileLedger
	for _, closer := range d.closers {
		if value, ok := closer.(*audit.FileLedger); ok {
			reopened = value
			break
		}
	}
	if reopened == nil {
		t.Fatal("restarted daemon did not own a file audit ledger")
	}
	_, acquired, err := gateway.ClaimRouteAttempt(ctx, reopened, scope, input.Authorization(), future.Now())
	if err != nil || acquired {
		t.Fatalf("duplicate route claim acquired=%t err=%v", acquired, err)
	}
	after, err := reopened.Read(ctx, scope, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(auditEvents) {
		t.Fatalf("audit appended on duplicate claim: before=%d after=%d", len(auditEvents), len(after))
	}
	assertCandidateRestartAudit(t, after, rateLimits)
	genCalls, _, _, genFailures := model.generation.snapshot()
	verCalls, _, _, verFailures := model.verification.snapshot()
	if genCalls != sent || verCalls != 0 || len(genFailures)+len(verFailures) != 0 {
		t.Fatalf("restarted traffic gen=%d verify=%d failures=%v/%v", genCalls, verCalls, genFailures, verFailures)
	}

	terminalState, err := coordinator.Advance(ctx, plan, future.Now())
	if err != nil {
		t.Fatal(err)
	}
	terminalCompletion, ready, err := terminalState.TerminalCompletion()
	if err != nil {
		t.Fatal(err)
	}
	if !ready {
		t.Fatal("candidate fixture has no terminal completion")
	}
	if _, err := coordinator.FailRun(ctx, plan, terminalCompletion.Failure(), future.Now()); err != nil {
		t.Fatal(err)
	}
	testTerminalCandidateExpiryProof(t, ctx, d, args, repository, policy, inventory, candidate.HandlerIdentity(), outputArtifact, future.Now())
	journalBeforeSecond, err := os.ReadFile(streamPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("second startup after exhausted candidate lease: %v", err)
	}
	defer second.Close()
	journalAfterSecond, err := os.ReadFile(streamPath)
	if err != nil || !bytes.Equal(journalBeforeSecond, journalAfterSecond) {
		t.Fatalf("second startup changed terminal journal: %v", err)
	}
	if value, err := second.artifactStore.Get(ctx, scope, outputID, future.Now()); err != nil || value.Identity() != outputArtifact.Identity() {
		t.Fatalf("second startup candidate changed: %v", err)
	}
	if calls, _, _, _ := model.generation.snapshot(); calls != sent {
		t.Fatalf("second startup generation calls=%d", calls)
	}
	if calls, _, _, _ := model.verification.snapshot(); calls != 0 {
		t.Fatalf("second startup verification calls=%d", calls)
	}
	// After the 24-hour retention lapses the exhausted lease is proved from
	// the journal and audit; the expired bytes are not read.
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	deps.clock = daemonBudgetedRawClock{at: future.Now().Add(25 * time.Hour)}
	third, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatalf("startup after retention lapsed on an exhausted candidate lease: %v", err)
	}
	defer third.Close()
	journalAfterThird, err := os.ReadFile(streamPath)
	if err != nil || !bytes.Equal(journalBeforeSecond, journalAfterThird) {
		t.Fatalf("startup after retention changed terminal journal: %v", err)
	}
	if calls, _, _, _ := model.generation.snapshot(); calls != sent {
		t.Fatalf("startup after retention generation calls=%d", calls)
	}
}

// assertCandidateRestartAudit requires the route selection and, for each of
// the rateLimits refused requests and the final one, a claimed, completed and
// settled route attempt.
func assertCandidateRestartAudit(t *testing.T, events []audit.Event, rateLimits int) {
	t.Helper()
	want := []audit.EventKind{audit.EventRouteSelected}
	for range rateLimits + 1 {
		want = append(want, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled)
	}
	if len(events) != len(want) {
		t.Fatalf("route audit event count=%d, want %d", len(events), len(want))
	}
	for i, kind := range want {
		if events[i].Kind() != kind {
			t.Fatalf("route audit event %d=%s, want %s", i, events[i].Kind(), kind)
		}
	}
}

func candidateRestartAuditSummary(t *testing.T, ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope) map[audit.EventKind]int {
	t.Helper()
	events, err := ledger.Read(ctx, scope, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[audit.EventKind]int{}
	for _, event := range events {
		counts[event.Kind()]++
	}
	return counts
}
