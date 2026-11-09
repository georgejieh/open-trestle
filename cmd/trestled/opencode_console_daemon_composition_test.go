//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func daemonOpenCodeConsolePolicy(t *testing.T, h *daemonBudgetedPipelineHarness) {
	t.Helper()
	from, until := h.clock.UTCMS().Add(-time.Minute).Format(time.RFC3339Nano), h.clock.UTCMS().Add(time.Hour).Format(time.RFC3339Nano)
	hash := func(value string) string { return daemonBudgetedModelDigest([]byte(value)) }
	type source struct {
		URL           string `json:"url"`
		RetrievedAt   string `json:"retrieved_at"`
		ContentSHA256 string `json:"content_sha256"`
	}
	account := struct {
		AuthorityLabel              string `json:"authority_label"`
		CredentialReferenceIdentity string `json:"credential_reference_identity"`
		BillingMode                 string `json:"billing_mode"`
		KeyKind                     string `json:"key_kind"`
		ModelsRequest               bool   `json:"models_request"`
		WorkspaceMembership         string `json:"workspace_membership"`
		PrivacyTraining             string `json:"privacy_training"`
		AutoRecharge                string `json:"auto_recharge"`
		ReviewEvidence              source `json:"review_evidence"`
	}{"synthetic Console single-member account, not live approval", hash("open-trestle/provider-credential-environment/" + daemonBudgetedModelGenerationKeyEnv), "prepaid_balance", "personal", true, "single_member", "disabled", "disabled", source{"https://account-review.fixture.invalid/console/prepaid-privacy", from, hash("synthetic prepaid account privacy and auto-recharge off review")}}
	accountPreimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Account  any    `json:"account"`
	}{"open-trestle/opencode-console-account-policy", 1, account}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(`{"opencode_console_privacy":{"contract":"open-trestle/opencode-console-privacy-witness","schema_version":1,"route":{"zone":"brokered_remote","provider_id":"opencode-console","adapter_id":"adapter-a","connection_id":"connection-a","model_id":"glm-5.3-flash","model_version":"","effective_selector":"glm-5.3-flash"},"endpoint":"https://opencode.ai/inference/openai/v1","request_profile":"opencode_console_chat_v1","protocol":"openai_chat_completions","credential_mode":"bearer","model_privacy":{"training":"disabled","retention_days":0},"broker_privacy":{"retention_contract":"model_specific_documented_zero_days"},"tenant_id":"tenant-a","repository_id":"repo-a","reviewed_at":"2026-10-29T00:00:00Z","valid_from":"2026-10-29T00:00:00Z","valid_until":"2026-11-01T00:00:00Z","byok":"excluded","tools":"excluded","plugins":"excluded","streaming":"excluded","client":{"user_agent":"open-trestle/1","session_derivation":"authorized_review_scope_sha256_v1"}}}`), &manifest); err != nil {
		t.Fatal(err)
	}
	witness := manifest["opencode_console_privacy"].(map[string]any)
	witness["account"] = account
	witness["model_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/console/glm-5.3-flash-privacy", from, hash("synthetic documented exact model zero-day no-training review")}
	witness["broker_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/console/broker-privacy-scope", from, hash("synthetic broker privacy scope review")}

	witness["tenant_id"], witness["repository_id"] = daemonBudgetedTenant, daemonBudgetedRepository
	witness["reviewed_at"], witness["valid_from"], witness["valid_until"] = from, from, until
	inventoryBytes, err := os.ReadFile(h.model.inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	var inventoryWire map[string]any
	if err = json.Unmarshal(inventoryBytes, &inventoryWire); err != nil {
		t.Fatal(err)
	}
	routes := inventoryWire["routes"].([]any)
	for i, raw := range routes {
		route := raw.(map[string]any)
		route["input_micro_usd_per_million_tokens"], route["output_micro_usd_per_million_tokens"] = 1000, 2000
		if i == 0 {
			route["zone"], route["provider_id"], route["model_id"], route["model_version"] = "brokered_remote", "opencode-console", "glm-5.3-flash", ""
			witness["route"] = map[string]any{"zone": "brokered_remote", "provider_id": "opencode-console", "adapter_id": route["adapter_id"], "connection_id": route["connection_id"], "model_id": "glm-5.3-flash", "model_version": "", "effective_selector": "glm-5.3-flash"}
			route["evidence_manifest_base64"] = base64.StdEncoding.EncodeToString(daemonBudgetedModelJSON(t, manifest))
		} else {
			route["zone"], route["provider_id"] = "private_remote", "daemon-direct"
		}
	}
	inventoryBytes = daemonBudgetedModelJSON(t, inventoryWire)
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal("Console daemon inventory", err)
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
	policyWire["schema_version"], policyWire["inventory_identity"] = 5, inventory.Identity()
	policyWire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
	policyWire["max_cost_micro_usd"] = 100000
	policyWire["pinned_route_record_identity"], policyWire["preferred_route_record_identities"] = records["daemon-adapter-a"], []string{}
	policyWire["verification_route_record_identity"] = records["daemon-adapter-b"]
	policyWire["connections"] = []any{
		map[string]any{"implementation": "openai_chat_completions", "adapter_id": "daemon-adapter-a", "endpoint": "https://opencode.ai/inference/openai/v1", "credential_environment": daemonBudgetedModelGenerationKeyEnv, "request_profile": "opencode_console_chat_v1", "opencode_console_authority": map[string]any{
			"route_record_identity": records["daemon-adapter-a"], "evidence_manifest_digest": digests["daemon-adapter-a"], "account_policy_identity": hash(string(daemonBudgetedModelJSON(t, accountPreimage))), "tenant_id": daemonBudgetedTenant, "repository_id": daemonBudgetedRepository, "valid_from": from, "valid_until": until,
		}},
		map[string]any{"implementation": "openai_responses", "adapter_id": "daemon-adapter-b", "endpoint": "https://direct.fixture.invalid/v1", "credential_environment": daemonBudgetedModelVerificationKeyEnv},
	}
	policyBytes = daemonBudgetedModelJSON(t, policyWire)
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal("Console daemon policy", err)
	}
	h.model.inventoryPath = daemonBudgetedProtectedFile(t, "opencode-console-inventory.json", string(inventoryBytes))
	h.model.policyPath = daemonBudgetedProtectedFile(t, "opencode-console-policy.json", string(policyBytes))
	h.model.inventoryID, h.model.policyID = inventory.Identity(), policy.Identity()
	h.model.generationRoute, h.model.verificationRoute = records["daemon-adapter-a"], records["daemon-adapter-b"]
}

type daemonOpenCodeConsoleTransport struct {
	t       *testing.T
	fixture *daemonBudgetedModelFixture
	scope   audit.ReviewScope
}

func (r *daemonOpenCodeConsoleTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost {
		return nil, fmt.Errorf("Console fixture refused method")
	}
	if request.URL.String() == "https://direct.fixture.invalid/v1/responses" {
		if request.Header.Get("x-opencode-session") != "" {
			return nil, fmt.Errorf("Console session leaked to direct verifier")
		}
		recorder := httptest.NewRecorder()
		r.fixture.verification.serve(r.t, recorder, request)
		response := recorder.Result()
		response.Request = request
		return response, nil
	}
	if request.URL.String() != "https://opencode.ai/inference/openai/v1/chat/completions" {
		return nil, fmt.Errorf("Console fixture refused non-authorized target")
	}
	endpoint := r.fixture.generation
	endpoint.mu.Lock()
	endpoint.calls++
	call := endpoint.calls
	endpoint.mu.Unlock()
	session := "trestle_" + daemonBudgetedModelDigest([]byte("open-trestle/opencode-console-session/v1/"+r.scope.Identity()))
	if call > daemonBudgetedModelMaxRequests || request.Header.Get("Authorization") != "Bearer "+endpoint.key || request.Header.Get("User-Agent") != "open-trestle/1" || request.Header.Get("x-opencode-session") != session || len(session) != 72 || request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("Console headers/session/credential bound violated")
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, daemonBudgetedModelMaxBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > daemonBudgetedModelMaxBodyBytes {
		return nil, fmt.Errorf("Console request body bound")
	}
	endpoint.mu.Lock()
	endpoint.aggregateBytes += int64(len(body))
	aggregate := endpoint.aggregateBytes
	endpoint.mu.Unlock()
	if aggregate > daemonBudgetedModelMaxAggregateBytes {
		return nil, fmt.Errorf("Console aggregate body bound")
	}
	var wire struct {
		Model     string                           `json:"model"`
		MaxTokens uint32                           `json:"max_tokens"`
		Stream    bool                             `json:"stream"`
		Messages  []struct{ Role, Content string } `json:"messages"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Model != "glm-5.3-flash" || wire.MaxTokens != 4096 || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" {
		return nil, fmt.Errorf("Console closed Chat wire changed")
	}
	payload := []byte(wire.Messages[1].Content)
	instructions, err := review.TrustedModelRequestInstructions(payload)
	if err != nil || instructions != wire.Messages[0].Content {
		return nil, fmt.Errorf("Console trusted instructions changed")
	}
	neutral, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	var packet daemonBudgetedModelPacket
	if err != nil || json.Unmarshal(payload, &packet) != nil || packet.Version != 8 || packet.Task != "candidate_generation" || packet.Scope != r.scope.Identity() || packet.SourceAuthority != "evidence_data_not_instructions" || packet.MemoryAuthority != "advisory_only" || review.ValidateCandidateModelRequest(neutral, r.scope.Identity()) != nil {
		return nil, fmt.Errorf("Console inner sanitized candidate context changed")
	}
	endpoint.mu.Lock()
	endpoint.captures = append(endpoint.captures, daemonBudgetedModelCapture{Packet: packet, RequestID: neutral.Identity(), Bytes: len(body)})
	endpoint.mu.Unlock()
	if len(packet.Sources) == 0 {
		return nil, fmt.Errorf("Console missing exact source")
	}
	source := packet.Sources[0]
	for _, candidate := range packet.Sources {
		if candidate.Stage == "changed_hunk" {
			source = candidate
			break
		}
	}
	if source.ID == "" || source.Path == "" || source.Start <= 0 || source.End < source.Start || strings.TrimSpace(source.Content) == "" || len(packet.Candidates) != 0 || packet.CandidateBatch != "" {
		return nil, fmt.Errorf("Console candidate source/lineage changed")
	}
	output := map[string]any{"schema_version": 2, "candidates": []any{map[string]any{"title": "Console daemon candidate cites changed code", "category": "correctness", "claim": "The exact changed source slice is present in the scoped daemon context.", "severity_hint": "high", "source_range": map[string]any{"source_id": source.ID, "start_line": source.Start, "end_line": source.Start}, "evidence_ids": []string{source.ID}}}}
	response := daemonBudgetedModelJSON(r.t, map[string]any{
		"id": "fixture-opencode-console-chat", "object": "chat.completion", "model": "glm-5.3-flash",
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": string(daemonBudgetedModelJSON(r.t, output)), "reasoning_content": "GO_DAEMON_REASONING_NOT_CONTENT"}, "finish_reason": "stop"}},
		"usage":   map[string]any{"prompt_tokens": 1200, "completion_tokens": 300, "cost": 0.001, "opencode": map[string]any{"billing_source": "balance", "list_cost": 0.001, "tokens": map[string]any{"input": 1200, "output": 300, "reasoning": 120, "cache_read": 8000, "cache_write_5m": 0, "cache_write_1h": 0}}},
	})
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(response)), Request: request}, nil
}

func TestDaemonGitHubAdvisoryOpenCodeConsoleProfileUsesRuntimeV5CatalogToCanonicalReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	h := newDaemonBudgetedPipelineHarness(t)
	daemonOpenCodeConsolePolicy(t, h)
	scope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-opencode-console-daemon")
	if err != nil {
		t.Fatal(err)
	}
	transport := &daemonOpenCodeConsoleTransport{t: t, fixture: h.model, scope: scope}
	d, err := buildDaemonWithDependencies(ctx, h.args(t), h.env, io.Discard, daemonDependencies{
		openPostgres: h.sql.OpenPostgres, clock: h.clock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer(),
		modelHTTPClient: &http.Client{Transport: transport, Timeout: 90 * time.Second}, modelHTTPClientIdentity: daemonBudgetedModelDigest([]byte("exact-host synthetic Console daemon generation and direct Responses verifier")),
	})
	if err != nil {
		t.Fatalf("Console v5 advisory daemon composition: %v", err)
	}
	defer d.Close()
	if h.s3.RawRequests() != 0 || h.kms.RawRequests() != 0 || h.readCount(daemonBudgetedModelGenerationKeyEnv) != 0 || h.readCount(daemonBudgetedModelVerificationKeyEnv) != 0 {
		t.Fatal("startup contacted providers or retrieved model credential")
	}
	if calls, _, _, _ := h.model.generation.snapshot(); calls != 0 {
		t.Fatal("startup contacted Go")
	}
	if calls, _, _, _ := h.model.verification.snapshot(); calls != 0 {
		t.Fatal("startup contacted verifier")
	}
	handlers := daemonBudgetedHandlerIdentities(t, d)
	for _, kind := range []string{"acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
		if handlers[kind] == "" {
			t.Fatalf("missing actual handler %s", kind)
		}
	}
	if handlers["publish_result"] != "" || h.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatal("advisory run configured publication")
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	sourceAdapter, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil {
		t.Fatal(err)
	}
	created, expires := h.clock.UTCMS().Add(-time.Second), h.clock.UTCMS().Add(time.Hour)
	baseInput := daemonBudgetedSourceInputArtifact(t, scope, repository, sourceAdapter, daemonBudgetedGitHubBaseCommit, created, expires)
	headInput := daemonBudgetedSourceInputArtifact(t, scope, repository, sourceAdapter, daemonBudgetedGitHubHeadCommit, created, expires)
	for _, value := range []artifact.Artifact{baseInput, headInput} {
		if ok, err := d.artifactStore.Put(ctx, value, h.clock.UTCMS()); err != nil || !ok {
			t.Fatalf("put source input=%v/%v", ok, err)
		}
	}
	plan := daemonBudgetedPipelinePlan(t, scope, handlers, baseInput.Identity(), headInput.Identity())
	if err = d.journal.SavePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Open(ctx, plan, h.clock.UTCMS()); err != nil {
		t.Fatal(err)
	}
	if worked, err := daemonBudgetedLocalSupervisor(t, d).RunOnce(ctx); err != nil || !worked {
		t.Fatalf("actual supervisor=%v/%v", worked, err)
	}
	finalizer, err := controlplane.NewRunFinalizer(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	state, finalized, err := finalizer.ReconcileRun(ctx, scope, time.Now().UTC().Truncate(time.Millisecond))
	if err != nil || !finalized || state.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("Console daemon run status=%s failure=%s finalized=%v err=%v", state.Status(), state.Failure(), finalized, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TaskCount() != 9 {
		t.Fatalf("actual task count=%d", receipt.TaskCount())
	}
	outputs := map[string]artifact.Artifact{}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"} {
		task, ok := receipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("actual task %s not succeeded", key)
		}
		value := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, key, h.clock.UTCMS())
		outputs[key] = value
		daemonBudgetedAssertUTCMS(t, key+" created_at", value.CreatedAt(), h.clock.UTCMS())
		if value.Protection() != artifact.ProtectionEnvelopeEncrypted || value.Classification() != artifact.ClassificationRestricted || bytes.Contains(value.Payload(), []byte("GO_DAEMON_REASONING_NOT_CONTENT")) {
			t.Fatalf("%s lost protection or retained reasoning", key)
		}
	}
	input, err := modelhandler.ParseGenerationInput(outputs["context"].Payload())
	if err != nil {
		t.Fatal(err)
	}
	route := input.Authorization().RouteReference()
	if input.ReviewScopeIdentity() != scope.Identity() || route.ProviderID() != "opencode-console" || route.ModelID() != "glm-5.3-flash" || route.ModelVersion() != "" || input.Authorization().RouteRecordIdentity() != h.model.generationRoute || input.SanitizedRequestArtifactIdentity() == "" || input.SanitizedEgressReceiptArtifactIdentity() == "" || input.SanitizedEgressReceiptIdentity() == "" {
		t.Fatal("actual Console generation authority/proof lineage changed")
	}
	packet, err := d.artifactStore.Get(ctx, scope, input.ContextArtifactIdentity(), h.clock.UTCMS())
	if err != nil {
		t.Fatal(err)
	}
	if packet.Kind() != artifact.KindContextPacket || packet.Origin() != artifact.OriginHost || !containsString(packet.Provenance(), outputs["analysis"].Identity()) || !containsString(packet.Provenance(), outputs["memory"].Identity()) {
		t.Fatal("host context provenance changed")
	}
	generation, err := modelhandler.ParseGenerationResultArtifact(outputs["candidates"], outputs["context"], packet)
	if err != nil {
		t.Fatal(err)
	}
	usage := generation.RouteExecution().Outcome().Usage()
	if generation.ContextIdentity() != input.ContextIdentity() || len(generation.Candidates().Findings()) != 1 || usage.IsKnown() || generation.RouteExecution().Reconciliation().ActualCost().IsKnown() || generation.RouteExecution().Reconciliation().Status() != gateway.RouteCostUsageUnknown {
		t.Fatal("Console generation unknown accounting/source candidate changed")
	}
	verification, err := modelhandler.ParseStoredVerificationResultArtifact(ctx, d.artifactStore, h.clock.UTCMS(), outputs["verification"], outputs["candidates"], outputs["context"], packet)
	if err != nil {
		t.Fatal(err)
	}
	verifierRoute := verification.RouteExecution().Authorization().RouteReference()
	if verification.GenerationArtifactIdentity() != outputs["candidates"].Identity() || len(verification.Verification().Results()) != 1 || verification.Verification().Results()[0].Outcome() != review.VerificationVerified || verifierRoute.ProviderID() != "daemon-direct" || verifierRoute.ModelID() != "model-b" || verification.RouteExecution().Authorization().RouteRecordIdentity() != h.model.verificationRoute {
		t.Fatal("independent direct verifier lineage changed")
	}
	var readiness struct {
		Contract             string `json:"contract"`
		Status               string `json:"status"`
		Verified             uint8  `json:"verified"`
		Inline               int    `json:"inline"`
		VerificationArtifact string `json:"verification_artifact_identity"`
		VerificationResult   string `json:"verification_result_identity"`
	}
	if json.Unmarshal(outputs["readiness"].Payload(), &readiness) != nil || readiness.Contract != "open-trestle/publication-readiness-result" || readiness.Status != "advisory_ready" || readiness.Verified != 1 || readiness.Inline != 1 || readiness.VerificationArtifact != outputs["verification"].Identity() || readiness.VerificationResult != verification.Identity() {
		t.Fatalf("canonical advisory readiness=%#v", readiness)
	}
	diagnosticSet, err := d.diagnosticStore.GetDiagnosticSet(ctx, scope)
	if err != nil || diagnosticSet.VerifiedCount() != 1 || diagnosticSet.SnapshotIdentity() != verification.VerifiedFindings().SnapshotIdentity() {
		t.Fatalf("canonical diagnostic set=%v", err)
	}
	findings := diagnosticSet.Findings()
	if len(findings) != 1 || findings[0].Severity() != diagnostics.SeverityError || findings[0].Path() == "" || len(findings[0].EvidenceIDs()) == 0 {
		t.Fatal("canonical diagnostic lost exact verified source")
	}
	genCalls, _, genCaptures, genFailures := h.model.generation.snapshot()
	verCalls, _, verCaptures, verFailures := h.model.verification.snapshot()
	if genCalls != 1 || verCalls != 1 || len(genCaptures) != 1 || len(verCaptures) != 1 || len(genFailures)+len(verFailures) != 0 {
		t.Fatalf("actual Go/direct captures=%d/%d failures=%v/%v", genCalls, verCalls, genFailures, verFailures)
	}
	if genCaptures[0].Packet.Scope != scope.Identity() || genCaptures[0].Packet.Task != "candidate_generation" || verCaptures[0].Packet.Task != "candidate_verification" || verCaptures[0].Packet.GenerationContext != generation.ContextIdentity() || genCaptures[0].RequestID == input.Authorization().RequestIdentity() {
		t.Fatal("inner/outer request lineage changed")
	}
	if h.readCount(daemonBudgetedModelGenerationKeyEnv) != 1 || h.readCount(daemonBudgetedModelVerificationKeyEnv) != 1 || h.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatal("model/publication credential separation changed")
	}
	snapshot := h.sql.Snapshot()
	for _, id := range []string{"run_plan_insert", "run_event_insert", "audit_event_insert", "audit_events_read", "audit_event_head", "diagnostic_insert", "metadata_insert", "admission_insert", "confirmation_cas"} {
		if !daemonBudgetedTraceContains(snapshot.Events, id) {
			t.Fatalf("actual SQL omitted %s", id)
		}
	}
	if len(snapshot.AuditEvents[daemonBudgetedScopeKey(daemonBudgetedTenant, daemonBudgetedRepository, scope.ReviewRunID())]) == 0 || len(snapshot.Failures) != 0 {
		t.Fatalf("audit ledger missing or SQL rejected: %v", snapshot.Failures)
	}
	if len(h.s3.Failures()) != 0 || len(h.kms.Failures()) != 0 || h.s3.RawRequests() == 0 || h.s3.RawRequests() > 512 || h.kms.RawRequests() == 0 || h.kms.RawRequests() > 256 {
		t.Fatal("artifact fixture contract/request bounds changed")
	}
}
