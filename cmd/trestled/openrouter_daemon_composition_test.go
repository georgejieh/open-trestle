//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func daemonOpenRouterPolicy(t *testing.T, h *daemonBudgetedPipelineHarness) {
	t.Helper()
	inventoryBytes, err := os.ReadFile(h.model.inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	var inventoryWire map[string]any
	if err = json.Unmarshal(inventoryBytes, &inventoryWire); err != nil {
		t.Fatal(err)
	}
	routes := inventoryWire["routes"].([]any)
	var accountIdentity string
	for i, raw := range routes {
		route := raw.(map[string]any)
		if i == 0 {
			route["zone"], route["provider_id"] = "brokered_remote", "openrouter"
			witness := newBrokeredPrivacyFixture(brokeredPrivacyRouteFixture{"brokered_remote", "openrouter", route["adapter_id"].(string), route["connection_id"].(string), route["model_id"].(string), route["model_version"].(string), ""}, daemonBudgetedModelGenerationKeyEnv, daemonBudgetedTenant, daemonBudgetedRepository, "fixture-upstream/region", h.clock.UTCMS().Add(-time.Minute).Format(time.RFC3339), h.clock.UTCMS().Add(time.Hour).Format(time.RFC3339))
			var manifest []byte
			manifest, accountIdentity = brokeredPrivacyManifest(t, witness)
			route["evidence_manifest_base64"] = base64.StdEncoding.EncodeToString(manifest)
		} else {
			route["zone"], route["provider_id"] = "private_remote", "daemon-direct"
		}
	}
	inventoryBytes = daemonBudgetedModelJSON(t, inventoryWire)
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records, digests := map[string]string{}, map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		id := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()
		records[id], digests[id] = record.Identity(), record.EvidenceManifestDigest()
	}
	policyBytes, err := os.ReadFile(h.model.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policyWire map[string]any
	if err = json.Unmarshal(policyBytes, &policyWire); err != nil {
		t.Fatal(err)
	}
	policyWire["schema_version"], policyWire["inventory_identity"] = 3, inventory.Identity()
	policyWire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
	policyWire["pinned_route_record_identity"], policyWire["preferred_route_record_identities"] = records["daemon-adapter-a"], []string{}
	policyWire["verification_route_record_identity"] = records["daemon-adapter-b"]
	policyWire["connections"] = []any{
		map[string]any{"implementation": "openai_chat_completions", "adapter_id": "daemon-adapter-a", "endpoint": "https://openrouter.ai/api/v1", "credential_environment": daemonBudgetedModelGenerationKeyEnv, "request_profile": "openrouter_zdr_chat_v1", "brokered_route_authority": map[string]any{
			"route_record_identity": records["daemon-adapter-a"], "evidence_manifest_digest": digests["daemon-adapter-a"], "account_policy_identity": accountIdentity, "tenant_id": daemonBudgetedTenant, "repository_id": daemonBudgetedRepository, "provider_slug": "fixture-upstream/region", "valid_from": h.clock.UTCMS().Add(-time.Minute).Format(time.RFC3339), "valid_until": h.clock.UTCMS().Add(time.Hour).Format(time.RFC3339),
		}},
		map[string]any{"implementation": "openai_responses", "adapter_id": "daemon-adapter-b", "endpoint": "https://direct.fixture.invalid/v1", "credential_environment": daemonBudgetedModelVerificationKeyEnv},
	}
	policyBytes = daemonBudgetedModelJSON(t, policyWire)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	h.model.inventoryPath = daemonBudgetedProtectedFile(t, "openrouter-inventory.json", string(inventoryBytes))
	h.model.policyPath = daemonBudgetedProtectedFile(t, "openrouter-policy.json", string(policyBytes))
	h.model.inventoryID, h.model.policyID = inventory.Identity(), configuration.Identity()
	h.model.generationRoute, h.model.verificationRoute = records["daemon-adapter-a"], records["daemon-adapter-b"]
}

type daemonOpenRouterModelTransport struct {
	t       *testing.T
	fixture *daemonBudgetedModelFixture
}

func (r *daemonOpenRouterModelTransport) RoundTrip(request *http.Request) (response *http.Response, err error) {
	defer func() {
		if err != nil {
			r.t.Logf("model transport target=%s error=%v", request.URL.String(), err)
		}
	}()
	if request.Method != http.MethodPost {
		return nil, fmt.Errorf("model fixture refused method")
	}
	switch request.URL.String() {
	case "https://direct.fixture.invalid/v1/responses":
		recorder := httptest.NewRecorder()
		r.fixture.verification.serve(r.t, recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	case "https://openrouter.ai/api/v1/chat/completions":
		return r.chat(request)
	default:
		return nil, fmt.Errorf("model fixture refused non-authorized target")
	}
}

func (r *daemonOpenRouterModelTransport) chat(request *http.Request) (*http.Response, error) {
	endpoint := r.fixture.generation
	endpoint.mu.Lock()
	endpoint.calls++
	call := endpoint.calls
	endpoint.mu.Unlock()
	if call > daemonBudgetedModelMaxRequests || request.Header.Get("Authorization") != "Bearer "+endpoint.key || request.Header.Get("Accept") != "application/json" {
		return nil, fmt.Errorf("invalid Chat target credential or request count")
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, daemonBudgetedModelMaxBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > daemonBudgetedModelMaxBodyBytes {
		return nil, fmt.Errorf("invalid Chat body bound")
	}
	endpoint.mu.Lock()
	endpoint.aggregateBytes += int64(len(body))
	aggregate := endpoint.aggregateBytes
	endpoint.mu.Unlock()
	if aggregate > daemonBudgetedModelMaxAggregateBytes {
		return nil, fmt.Errorf("invalid Chat aggregate bound")
	}
	var wire struct {
		Model     string                           `json:"model"`
		MaxTokens uint32                           `json:"max_tokens"`
		Stream    bool                             `json:"stream"`
		Messages  []struct{ Role, Content string } `json:"messages"`
		Provider  map[string]json.RawMessage       `json:"provider"`
	}
	if json.Unmarshal(body, &wire) != nil || wire.Model != endpoint.model || wire.MaxTokens != 4096 || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" || len(wire.Provider) != 5 {
		return nil, fmt.Errorf("invalid fixed Chat profile wire")
	}
	for key, expected := range map[string]string{"zdr": "true", "only": "[\"fixture-upstream/region\"]", "order": "[\"fixture-upstream/region\"]", "allow_fallbacks": "false", "require_parameters": "true"} {
		var compact bytes.Buffer
		if json.Compact(&compact, wire.Provider[key]) != nil || compact.String() != expected {
			return nil, fmt.Errorf("invalid fixed Chat routing field %s", key)
		}
	}
	payload := []byte(wire.Messages[1].Content)
	instructions, err := review.TrustedModelRequestInstructions(payload)
	if err != nil || wire.Messages[0].Content != instructions {
		return nil, fmt.Errorf("Chat trusted instructions changed")
	}
	neutral, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	var packet daemonBudgetedModelPacket
	if err != nil || json.Unmarshal(payload, &packet) != nil || packet.Version != 7 || packet.Task != "candidate_generation" || packet.Scope == "" || packet.SourceAuthority != "evidence_data_not_instructions" || packet.MemoryAuthority != "advisory_only" || review.ValidateCandidateModelRequest(neutral, packet.Scope) != nil {
		return nil, fmt.Errorf("Chat lost sanitized generation context")
	}
	endpoint.mu.Lock()
	endpoint.captures = append(endpoint.captures, daemonBudgetedModelCapture{Packet: packet, RequestID: neutral.Identity(), Bytes: len(body)})
	endpoint.mu.Unlock()
	output, ok := endpoint.outputForPacket(r.t, packet)
	if !ok {
		return nil, fmt.Errorf("Chat source evidence rejected")
	}
	response := daemonBudgetedModelJSON(r.t, map[string]any{
		"id": "fixture-openrouter-chat", "object": "chat.completion", "model": endpoint.model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": string(daemonBudgetedModelJSON(r.t, output))}, "finish_reason": "stop"}},
		"usage": map[string]any{
			"prompt_tokens": 120, "completion_tokens": 80, "total_tokens": 200,
			"cost": 0.0012, "is_byok": false,
			"cost_details":              map[string]any{"upstream_inference_prompt_cost": 0.0008, "upstream_inference_completions_cost": 0.0004, "upstream_inference_cost": nil},
			"prompt_tokens_details":     map[string]any{"cached_tokens": 20, "cache_write_tokens": 5, "audio_tokens": 0, "video_tokens": 0},
			"completion_tokens_details": map[string]any{"reasoning_tokens": 10, "audio_tokens": nil, "accepted_prediction_tokens": nil, "rejected_prediction_tokens": 0},
			"server_tool_use_details":   map[string]any{"tool_calls_requested": 0, "tool_calls_executed": 0, "web_search_requests": nil},
		},
	})
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
}

func TestDaemonGitHubAdvisoryOpenRouterProfileUsesRuntimeV3CatalogToCanonicalReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture := newDaemonBudgetedPipelineHarness(t)
	daemonOpenRouterPolicy(t, fixture)
	transport := &daemonOpenRouterModelTransport{t: t, fixture: fixture.model}
	d, err := buildDaemonWithDependencies(ctx, fixture.args(t), fixture.env, io.Discard, daemonDependencies{
		openPostgres: fixture.sql.OpenPostgres, clock: fixture.clock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer(),
		modelHTTPClient: &http.Client{Transport: transport, Timeout: 90 * time.Second}, modelHTTPClientIdentity: daemonBudgetedModelDigest([]byte("exact-host synthetic daemon OpenRouter and direct verifier transport")),
	})
	if err != nil {
		t.Fatalf("runtime-v3 OpenRouter advisory daemon build: %v", err)
	}
	defer d.Close()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted artifact providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	if calls, _, _, failures := fixture.model.generation.snapshot(); calls != 0 || len(failures) != 0 {
		t.Fatalf("startup contacted generation model: calls=%d failures=%v", calls, failures)
	}
	if fixture.readCount(daemonBudgetedModelGenerationKeyEnv) != 0 || fixture.readCount(daemonBudgetedModelVerificationKeyEnv) != 0 {
		t.Fatal("startup retrieved model key")
	}
	handlers := daemonBudgetedHandlerIdentities(t, d)
	for _, kind := range []string{"acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
		if handlers[kind] == "" {
			t.Fatalf("runtime status omitted local handler %s: %#v", kind, handlers)
		}
	}
	if handlers["publish_result"] != "" {
		t.Fatalf("advisory pipeline unexpectedly configured publication handler: %#v", handlers)
	}
	if fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("publication credential was read before publication was configured: %d", fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	supervisor := daemonBudgetedLocalSupervisor(t, d)
	scope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-budgeted-pipeline-clock")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil {
		t.Fatal(err)
	}
	created := fixture.clock.UTCMS().Add(-time.Second)
	expires := fixture.clock.UTCMS().Add(time.Hour)
	baseInput := daemonBudgetedSourceInputArtifact(t, scope, repository, adapter, daemonBudgetedGitHubBaseCommit, created, expires)
	headInput := daemonBudgetedSourceInputArtifact(t, scope, repository, adapter, daemonBudgetedGitHubHeadCommit, created, expires)
	for _, value := range []artifact.Artifact{baseInput, headInput} {
		if ok, err := d.artifactStore.Put(ctx, value, fixture.clock.UTCMS()); err != nil || !ok {
			t.Fatalf("persist source input %s: created=%v err=%v", value.Identity(), ok, err)
		}
	}
	plan := daemonBudgetedPipelinePlan(t, scope, handlers, baseInput.Identity(), headInput.Identity())
	if err := d.journal.SavePlan(ctx, plan); err != nil {
		t.Fatalf("SavePlan rejected real model pipeline plan: %v", err)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, fixture.clock.UTCMS()); err != nil {
		t.Fatalf("open saved model pipeline plan: %v", err)
	}
	worked, err := supervisor.RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("local supervisor RunOnce = (%v, %v)", worked, err)
	}
	finalizer, err := controlplane.NewRunFinalizer(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	state, finalized, err := finalizer.ReconcileRun(ctx, scope, time.Now().UTC().Truncate(time.Millisecond))
	if err != nil || !finalized || state.Status() != controlplane.ReviewRunSucceeded {
		t.Logf("run status=%s failure=%s revision=%d", state.Status(), state.Failure(), state.Revision())
		for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"} {
			task, ok := state.Task(key)
			t.Logf("task=%s exists=%t status=%s attempts=%d failure=%s output=%s", key, ok, task.Status(), task.Attempts(), task.Failure(), task.OutputIdentity())
		}
		events, readErr := d.journal.Read(ctx, scope, 0, 100)
		t.Logf("journal read err=%v count=%d", readErr, len(events))
		for _, event := range events {
			t.Logf("journal seq=%d kind=%s task=%s attempt=%d failure=%s output=%s", event.Sequence(), event.Kind(), event.TaskKey(), event.Attempt(), event.Failure(), event.OutputIdentity())
		}
		snapshot := fixture.sql.Snapshot()
		for _, event := range snapshot.AuditEvents[daemonBudgetedScopeKey(daemonBudgetedTenant, daemonBudgetedRepository, scope.ReviewRunID())] {
			t.Logf("audit seq=%d canonical=%s", event.Sequence, event.CanonicalEvent)
		}
		generationCalls, _, generationCaptures, generationFailures := fixture.model.generation.snapshot()
		verificationCalls, _, verificationCaptures, verificationFailures := fixture.model.verification.snapshot()
		t.Logf("model gen=%d captures=%d failures=%v verifier=%d captures=%d failures=%v key_reads=%d/%d", generationCalls, len(generationCaptures), generationFailures, verificationCalls, len(verificationCaptures), verificationFailures, fixture.readCount(daemonBudgetedModelGenerationKeyEnv), fixture.readCount(daemonBudgetedModelVerificationKeyEnv))
		t.Logf("fixture failures sql=%v s3=%v kms=%v", snapshot.Failures, fixture.s3.Failures(), fixture.kms.Failures())
		t.Fatalf("finalize model pipeline run = (%v, %v, %v)", state.Status(), finalized, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TaskCount() != 9 {
		t.Fatalf("task count = %d, want 9", receipt.TaskCount())
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"} {
		task, ok := receipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("task %s did not succeed from actual journal: %#v", key, task)
		}
	}
	readAt := fixture.clock.UTCMS()
	baseSnapshotArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "source-base", readAt)
	headSnapshotArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "source-head", readAt)
	changeArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "change", readAt)
	analysisArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "analysis", readAt)
	memoryArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "memory", readAt)
	generationInputArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "context", readAt)
	generationArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "candidates", readAt)
	verificationArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "verification", readAt)
	readinessArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "readiness", readAt)
	for label, value := range map[string]artifact.Artifact{"base": baseSnapshotArtifact, "head": headSnapshotArtifact, "change": changeArtifact, "analysis": analysisArtifact, "memory": memoryArtifact, "context-input": generationInputArtifact, "candidates": generationArtifact, "verification": verificationArtifact, "readiness": readinessArtifact} {
		daemonBudgetedAssertUTCMS(t, label+" created_at", value.CreatedAt(), fixture.clock.UTCMS())
		if value.Protection() != artifact.ProtectionEnvelopeEncrypted || value.Classification() != artifact.ClassificationRestricted {
			t.Fatalf("%s artifact was not budgeted protected restricted output", label)
		}
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || len(change.Entries()) != 1 || change.HeadRevision().Digest() != daemonBudgetedGitHubHeadCommit {
		t.Fatalf("change result = %#v err=%v", change, err)
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || analysis.ChangeIdentity() != change.Identity() || len(analysis.Items()) == 0 {
		t.Fatalf("analysis result = %#v err=%v", analysis, err)
	}
	memory, err := memoryhandler.ParseResultArtifact(memoryArtifact, changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || memory.ChangeArtifactIdentity() != changeArtifact.Identity() || len(memory.Queries()) != 1 || memory.PolicyIdentity() != daemonBudgetedPipelineReviewPolicyID {
		t.Fatalf("memory result = %#v err=%v", memory, err)
	}
	input, err := modelhandler.ParseGenerationInput(generationInputArtifact.Payload())
	if err != nil || input.ReviewScopeIdentity() != scope.Identity() || input.Authorization().RouteReference().ModelID() != "model-a" || input.Authorization().RouteRecordIdentity() != fixture.model.generationRoute {
		t.Fatalf("generation input route binding lost: %#v err=%v", input, err)
	}
	if input.SanitizedRequestArtifactIdentity() == "" || input.SanitizedEgressReceiptArtifactIdentity() == "" || input.SanitizedEgressReceiptIdentity() == "" || input.Authorization().RouteReference().ProviderID() != "openrouter" {
		t.Fatal("daemon omitted runtime-v3 sanitized OpenRouter authority")
	}
	contextArtifact, err := d.artifactStore.Get(ctx, scope, input.ContextArtifactIdentity(), readAt)
	if err != nil {
		t.Fatal(err)
	}
	if contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.Origin() != artifact.OriginHost || !containsString(contextArtifact.Provenance(), analysisArtifact.Identity()) || !containsString(contextArtifact.Provenance(), memoryArtifact.Identity()) {
		t.Fatalf("context artifact lost host provenance or kind: %#v", contextArtifact)
	}
	generation, err := modelhandler.ParseGenerationResultArtifact(generationArtifact, generationInputArtifact, contextArtifact)
	if err != nil || generation.ContextIdentity() != input.ContextIdentity() || len(generation.Candidates().Findings()) != 1 || generation.RouteExecution().Outcome().Usage().InputTokens() != 120 || generation.RouteExecution().Outcome().Usage().OutputTokens() != 80 {
		t.Fatalf("generation result = %#v err=%v", generation, err)
	}
	verification, err := modelhandler.ParseStoredVerificationResultArtifact(ctx, d.artifactStore, fixture.clock.UTCMS(), verificationArtifact, generationArtifact, generationInputArtifact, contextArtifact)
	if err != nil || verification.GenerationArtifactIdentity() != generationArtifact.Identity() || verification.Verification().Results()[0].Outcome() != review.VerificationVerified || verification.RouteExecution().Authorization().RouteReference().ModelID() != "model-b" || verification.RouteExecution().Authorization().RouteReference().ProviderID() != "daemon-direct" || verification.RouteExecution().Authorization().RouteRecordIdentity() != fixture.model.verificationRoute {
		t.Fatalf("verification result = %#v err=%v", verification, err)
	}
	var readinessWire struct {
		Contract                     string `json:"contract"`
		VerificationArtifactIdentity string `json:"verification_artifact_identity"`
		VerificationResultIdentity   string `json:"verification_result_identity"`
		PublicationPolicyIdentity    string `json:"publication_policy_identity"`
		Status                       string `json:"status"`
		Verified                     uint8  `json:"verified"`
		Inline                       int    `json:"inline"`
	}
	if json.Unmarshal(readinessArtifact.Payload(), &readinessWire) != nil || readinessWire.Contract != "open-trestle/publication-readiness-result" || readinessWire.Status != "advisory_ready" || readinessWire.Verified != 1 || readinessWire.Inline != 1 || readinessWire.VerificationArtifactIdentity != verificationArtifact.Identity() || readinessWire.VerificationResultIdentity != verification.Identity() {
		t.Fatalf("readiness payload lost verified advisory gate: %#v", readinessWire)
	}
	diagnosticsSet, err := d.diagnosticStore.GetDiagnosticSet(ctx, scope)
	if err != nil || diagnosticsSet.VerifiedCount() != 1 || diagnosticsSet.SnapshotIdentity() != verification.VerifiedFindings().SnapshotIdentity() {
		t.Fatalf("diagnostic set = %#v err=%v", diagnosticsSet, err)
	}
	if findings := diagnosticsSet.Findings(); len(findings) != 1 || findings[0].Severity() != diagnostics.SeverityError || findings[0].Path() == "" || len(findings[0].EvidenceIDs()) == 0 {
		t.Fatalf("diagnostic finding lost verified source identity: %#v", findings)
	}
	generationCalls, generationBytes, generationCaptures, generationFailures := fixture.model.generation.snapshot()
	verificationCalls, verificationBytes, verificationCaptures, verificationFailures := fixture.model.verification.snapshot()
	if generationCalls != 1 || verificationCalls != 1 || len(generationCaptures) != 1 || len(verificationCaptures) != 1 || len(generationFailures)+len(verificationFailures) != 0 {
		t.Fatalf("model fixture traffic = gen(%d,%d,%d,%v) verify(%d,%d,%d,%v)", generationCalls, generationBytes, len(generationCaptures), generationFailures, verificationCalls, verificationBytes, len(verificationCaptures), verificationFailures)
	}
	if generationCaptures[0].Packet.Task != "candidate_generation" || verificationCaptures[0].Packet.Task != "candidate_verification" || verificationCaptures[0].Packet.GenerationContext != generation.ContextIdentity() || generationCaptures[0].RequestID == input.Authorization().RequestIdentity() {
		t.Fatalf("model capture lost request identities: gen=%#v verify=%#v", generationCaptures[0], verificationCaptures[0])
	}
	if fixture.readCount(daemonBudgetedModelGenerationKeyEnv) != 1 || fixture.readCount(daemonBudgetedModelVerificationKeyEnv) != 1 || fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("credential reads were not separated: gen=%d verify=%d publication=%d", fixture.readCount(daemonBudgetedModelGenerationKeyEnv), fixture.readCount(daemonBudgetedModelVerificationKeyEnv), fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected pipeline requests: %v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected pipeline requests: %v", failures)
	}
	if got := fixture.s3.RawRequests(); got == 0 || got > 512 {
		t.Fatalf("S3 pipeline profile bound not honored: %d", got)
	}
	if got := fixture.kms.RawRequests(); got == 0 || got > 256 {
		t.Fatalf("KMS pipeline profile bound not honored: %d", got)
	}
	sqlSnapshot := fixture.sql.Snapshot()
	for _, id := range []string{"run_plan_insert", "run_event_insert", "audit_event_insert", "audit_events_read", "audit_event_head", "diagnostic_insert", "metadata_insert", "admission_insert", "confirmation_cas"} {
		if !daemonBudgetedTraceContains(sqlSnapshot.Events, id) {
			t.Fatalf("pipeline SQL did not execute %s", id)
		}
	}
	if len(sqlSnapshot.AuditEvents[daemonBudgetedScopeKey(daemonBudgetedTenant, daemonBudgetedRepository, scope.ReviewRunID())]) == 0 {
		t.Fatal("audit ledger did not retain model/readiness events")
	}
	if len(sqlSnapshot.Failures) != 0 {
		t.Fatalf("SQL fixture rejected model pipeline run: %v", sqlSnapshot.Failures)
	}
	t.Logf("external requests: model_generation=%d/%dB model_verification=%d/%dB S3=%d KMS=%d", generationCalls, generationBytes, verificationCalls, verificationBytes, fixture.s3.RawRequests(), fixture.kms.RawRequests())
}

type brokeredPrivacySourceFixture struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentSHA256 string `json:"content_sha256"`
}

type brokeredPrivacyRouteFixture struct {
	Zone              string `json:"zone"`
	ProviderID        string `json:"provider_id"`
	AdapterID         string `json:"adapter_id"`
	ConnectionID      string `json:"connection_id"`
	ModelID           string `json:"model_id"`
	ModelVersion      string `json:"model_version"`
	EffectiveSelector string `json:"effective_selector"`
}

type brokeredPrivacyAccountFixture struct {
	AuthorityLabel                 string                       `json:"authority_label"`
	CredentialReferenceIdentity    string                       `json:"credential_reference_identity"`
	ContentLogging                 string                       `json:"content_logging"`
	Training                       string                       `json:"training"`
	SafetyRetentionScope           string                       `json:"safety_retention_scope"`
	EffectiveSafetyRetentionGoogle string                       `json:"effective_safety_retention_google"`
	EffectiveSafetyRetentionOther  string                       `json:"effective_safety_retention_other"`
	ReviewEvidence                 brokeredPrivacySourceFixture `json:"review_evidence"`
}

type brokeredPrivacyFixture struct {
	Contract          string                      `json:"contract"`
	SchemaVersion     int                         `json:"schema_version"`
	Route             brokeredPrivacyRouteFixture `json:"route"`
	Endpoint          string                      `json:"endpoint"`
	RequestProfile    string                      `json:"request_profile"`
	Protocol          string                      `json:"protocol"`
	CredentialMode    string                      `json:"credential_mode"`
	ProviderSlug      string                      `json:"provider_slug"`
	ProviderSlugScope string                      `json:"provider_slug_scope"`
	Upstream          struct {
		RetentionContract string                       `json:"retention_contract"`
		Training          string                       `json:"training"`
		Evidence          brokeredPrivacySourceFixture `json:"evidence"`
	} `json:"upstream"`
	Broker struct {
		RetentionContract string                       `json:"retention_contract"`
		Evidence          brokeredPrivacySourceFixture `json:"evidence"`
	} `json:"broker"`
	SlugEvidence              brokeredPrivacySourceFixture  `json:"slug_evidence"`
	Account                   brokeredPrivacyAccountFixture `json:"account"`
	TenantID                  string                        `json:"tenant_id"`
	RepositoryID              string                        `json:"repository_id"`
	AcceptedRetentionContract string                        `json:"accepted_retention_contract"`
	ReviewedAt                string                        `json:"reviewed_at"`
	ValidFrom                 string                        `json:"valid_from"`
	ValidUntil                string                        `json:"valid_until"`
	BYOK                      string                        `json:"byok"`
	PrivateEndpoints          string                        `json:"private_endpoints"`
	Tools                     string                        `json:"tools"`
	Plugins                   string                        `json:"plugins"`
}

func brokeredPrivacyJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func brokeredPrivacyDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func brokeredPrivacyManifest(t *testing.T, witness brokeredPrivacyFixture) ([]byte, string) {
	t.Helper()
	account := brokeredPrivacyJSON(t, struct {
		Contract string                        `json:"contract"`
		Version  int                           `json:"version"`
		Account  brokeredPrivacyAccountFixture `json:"account"`
	}{"open-trestle/openrouter-account-policy", 2, witness.Account})
	manifest := brokeredPrivacyJSON(t, struct {
		OpenRouterPrivacy brokeredPrivacyFixture `json:"openrouter_privacy"`
	}{witness})
	return manifest, brokeredPrivacyDigest(account)
}

// All evidence is synthetic and does not attest to a live provider or account.
func newBrokeredPrivacyFixture(route brokeredPrivacyRouteFixture, environment, tenant, repository, slug, from, until string) brokeredPrivacyFixture {
	if route.ModelVersion != "" {
		route.EffectiveSelector = route.ModelVersion
	} else {
		route.EffectiveSelector = route.ModelID
	}
	var witness brokeredPrivacyFixture
	witness.Contract, witness.SchemaVersion = "open-trestle/openrouter-privacy-witness", 2
	witness.Route = route
	witness.Endpoint, witness.RequestProfile = "https://openrouter.ai/api/v1", "openrouter_zdr_chat_v1"
	witness.Protocol, witness.CredentialMode = "openai_chat_completions", "bearer"
	witness.ProviderSlug, witness.ProviderSlugScope = slug, "all_slug_matches"
	witness.Upstream.RetentionContract, witness.Upstream.Training = "openrouter_zdr_with_documented_exceptions", "disabled"
	witness.Broker.RetentionContract, witness.AcceptedRetentionContract = witness.Upstream.RetentionContract, witness.Upstream.RetentionContract
	witness.Upstream.Evidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/upstream-model-slug-scope", from, brokeredPrivacyDigest([]byte("synthetic upstream model/slug review, not provider evidence"))}
	witness.Broker.Evidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/broker-retention-exceptions", from, brokeredPrivacyDigest([]byte("synthetic broker exceptions review, not provider evidence"))}
	witness.SlugEvidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/all-zdr-eligible-slug-matches", from, brokeredPrivacyDigest([]byte("synthetic slug coverage review, not provider evidence"))}
	witness.Account = brokeredPrivacyAccountFixture{
		AuthorityLabel:              "synthetic account review, not live approval",
		CredentialReferenceIdentity: brokeredPrivacyDigest([]byte("open-trestle/provider-credential-environment/" + environment)),
		ContentLogging:              "disabled", Training: "disabled",
		SafetyRetentionScope:           "effective_account_and_guardrails",
		EffectiveSafetyRetentionGoogle: "denied",
		EffectiveSafetyRetentionOther:  "denied",
		ReviewEvidence:                 brokeredPrivacySourceFixture{"https://account-review.fixture.invalid/reviews/synthetic-account", from, brokeredPrivacyDigest([]byte("synthetic account review, not public privacy policy or live approval"))},
	}
	witness.TenantID, witness.RepositoryID = tenant, repository
	witness.ReviewedAt, witness.ValidFrom, witness.ValidUntil = from, from, until
	witness.BYOK, witness.PrivateEndpoints, witness.Tools, witness.Plugins = "excluded", "excluded", "excluded", "excluded"
	return witness
}
