package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/artifactvalidation"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type recordingDispatcher struct {
	adapterID       string
	result          gateway.RouteDispatchResult
	calls           int
	requestIdentity string
	requestPayload  []byte
	receiptIdentity string
}

func (d *recordingDispatcher) AdapterID() string             { return d.adapterID }
func (d *recordingDispatcher) ConfigurationIdentity() string { return strings.Repeat("a", 64) }
func (d *recordingDispatcher) DispatchRoute(_ context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	return d.record(request, "")
}
func (d *recordingDispatcher) DispatchSanitizedRoute(_ context.Context, request gateway.RouteDispatchRequest, proof SanitizedDispatchProof) gateway.RouteDispatchResult {
	return d.record(request, proof.ReceiptIdentity())
}
func (d *recordingDispatcher) record(request gateway.RouteDispatchRequest, receiptIdentity string) gateway.RouteDispatchResult {
	d.calls++
	d.requestIdentity = request.Request().Identity()
	d.requestPayload = request.Request().Payload()
	d.receiptIdentity = receiptIdentity
	return d.result
}

func generationContextFixture(t *testing.T) (audit.ReviewScope, review.ReviewSnapshot, review.ContextPacket, artifact.Artifact, provider.Request) {
	return generationContextFixtureWithContent(t, []byte("line one\nline two\n"))
}

func generationContextFixtureWithContent(t *testing.T, content []byte) (audit.ReviewScope, review.ReviewSnapshot, review.ContextPacket, artifact.Artifact, provider.Request) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	memoryScope, _ := memory.NewScope("tenant-a", "repo-a", "actor-a", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	sourceRange, _ := evidence.NewSourceRange("src/main.go", 1, 2)
	snapshot, _ := review.NewReviewSnapshot("workspace", strings.Repeat("b", 64), []evidence.SourceRange{sourceRange})
	digest := sha256.Sum256(content)
	item, _ := evidence.NewEvidenceItem("source-1", evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), sourceRange)
	source, err := review.NewContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, content)
	if err != nil {
		t.Fatal(err)
	}
	index := memory.NewLexicalIndex()
	query, _ := memory.NewLexicalQuery(memoryScope, "src/main.go", nil, nil, time.UnixMilli(100), 5)
	retrieval, err := index.Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := review.NewContextLimits(1<<20, 0)
	packet, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := packet.ProviderRequest()
	contextArtifact, err := artifact.New(
		scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential,
		artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)},
		request.Payload(), time.UnixMilli(50), time.UnixMilli(10000),
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope, snapshot, packet, contextArtifact, request
}

type authorizationEncoding struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	Identity                     string `json:"identity"`
	Kind                         string `json:"kind"`
	ReviewScopeIdentity          string `json:"review_scope_identity"`
	RequestIdentity              string `json:"request_identity"`
	SelectionReceiptIdentity     string `json:"selection_receipt_identity"`
	RegistryRevision             uint64 `json:"registry_revision"`
	RouteRecordIdentity          string `json:"route_record_identity"`
	AttemptOrdinal               uint8  `json:"attempt_ordinal"`
	RouteAttemptOrdinal          uint8  `json:"route_attempt_ordinal"`
	PreviousOutcomeIdentity      string `json:"previous_outcome_identity"`
	ContinuationDecisionIdentity string `json:"continuation_decision_identity"`
	Zone                         string `json:"zone"`
	ProviderID                   string `json:"provider_id"`
	AdapterID                    string `json:"adapter_id"`
	ConnectionID                 string `json:"connection_id"`
	ModelID                      string `json:"model_id"`
	ModelVersion                 string `json:"model_version"`
	ContentLogging               string `json:"content_logging"`
	InputPrice                   uint64 `json:"input_price_micro_usd_per_million_tokens"`
	OutputPrice                  uint64 `json:"output_price_micro_usd_per_million_tokens"`
	EstimatedInputTokens         uint32 `json:"estimated_input_tokens"`
	MaxOutputTokens              uint32 `json:"max_output_tokens"`
	CostCap                      uint64 `json:"cost_cap_micro_usd"`
	MaximumCost                  uint64 `json:"maximum_cost_micro_usd"`
	RemainingBefore              uint64 `json:"remaining_before_micro_usd"`
	Reserved                     uint64 `json:"reserved_micro_usd"`
	RemainingAfter               uint64 `json:"remaining_after_micro_usd"`
}

func routeAuthorization(
	t *testing.T,
	scope audit.ReviewScope,
	request provider.Request,
	providerID, adapterID, connectionID, modelID, modelVersion, selectionIdentity, recordIdentity string,
) gateway.RouteAttemptAuthorization {
	t.Helper()
	wire := authorizationEncoding{
		Contract: "open-trestle/route-attempt-authorization", SchemaVersion: 1,
		Kind: "initial", ReviewScopeIdentity: scope.Identity(), RequestIdentity: request.Identity(),
		SelectionReceiptIdentity: selectionIdentity, RegistryRevision: 1, RouteRecordIdentity: recordIdentity,
		AttemptOrdinal: 1, RouteAttemptOrdinal: 1, Zone: "local", ProviderID: providerID,
		AdapterID: adapterID, ConnectionID: connectionID, ModelID: modelID, ModelVersion: modelVersion,
		ContentLogging: "disabled", EstimatedInputTokens: 1, MaxOutputTokens: 100,
	}
	preimage := struct {
		Contract                     string `json:"contract"`
		Version                      int    `json:"version"`
		Kind                         string `json:"kind"`
		ReviewScopeIdentity          string `json:"review_scope_identity"`
		RequestIdentity              string `json:"request_identity"`
		SelectionReceiptIdentity     string `json:"selection_receipt_identity"`
		RegistryRevision             uint64 `json:"registry_revision"`
		RouteRecordIdentity          string `json:"route_record_identity"`
		AttemptOrdinal               uint8  `json:"attempt_ordinal"`
		RouteAttemptOrdinal          uint8  `json:"route_attempt_ordinal"`
		PreviousOutcomeIdentity      string `json:"previous_outcome_identity"`
		ContinuationDecisionIdentity string `json:"continuation_decision_identity"`
		Zone                         string `json:"zone"`
		ProviderID                   string `json:"provider_id"`
		AdapterID                    string `json:"adapter_id"`
		ConnectionID                 string `json:"connection_id"`
		ModelID                      string `json:"model_id"`
		ModelVersion                 string `json:"model_version"`
		ContentLogging               string `json:"content_logging"`
		InputPrice                   uint64 `json:"input_price"`
		OutputPrice                  uint64 `json:"output_price"`
		EstimatedInputTokens         uint32 `json:"estimated_input_tokens"`
		MaxOutputTokens              uint32 `json:"max_output_tokens"`
		CostCap                      uint64 `json:"cost_cap"`
		MaximumCost                  uint64 `json:"maximum_cost"`
		RemainingBefore              uint64 `json:"remaining_before"`
		Reserved                     uint64 `json:"reserved"`
		RemainingAfter               uint64 `json:"remaining_after"`
	}{"open-trestle/route-attempt-authorization", 1, wire.Kind, wire.ReviewScopeIdentity, wire.RequestIdentity, wire.SelectionReceiptIdentity, wire.RegistryRevision, wire.RouteRecordIdentity, wire.AttemptOrdinal, wire.RouteAttemptOrdinal, "", "", wire.Zone, wire.ProviderID, wire.AdapterID, wire.ConnectionID, wire.ModelID, wire.ModelVersion, wire.ContentLogging, 0, 0, wire.EstimatedInputTokens, wire.MaxOutputTokens, 0, 0, 0, 0, 0}
	encodedPreimage, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encodedPreimage)
	wire.Identity = hex.EncodeToString(digest[:])
	encoded, _ := json.Marshal(wire)
	authorization, err := gateway.ParseRouteAttemptAuthorization(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func generationAuthorization(t *testing.T, scope audit.ReviewScope, request provider.Request) gateway.RouteAttemptAuthorization {
	return routeAuthorization(
		t, scope, request, "test-provider", "test-model", "primary/test", "test-model", "1",
		strings.Repeat("c", 64), strings.Repeat("d", 64),
	)
}

func sanitizedGenerationFixture(t *testing.T, scope audit.ReviewScope, rawArtifact artifact.Artifact, raw provider.Request, secret string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, artifact.Artifact, artifact.Artifact, review.ScannerBinaryDigests) {
	t.Helper()
	type item struct {
		Path    string   `json:"path"`
		Symbols []string `json:"symbols"`
		Text    string   `json:"text"`
	}
	type memoryWire struct {
		Items []item `json:"items"`
	}
	var wire struct {
		Sources []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"sources"`
		SourceOmissions []struct {
			Path string `json:"path"`
		} `json:"source_omissions"`
		Memory           memoryWire   `json:"memory"`
		AdditionalMemory []memoryWire `json:"additional_memory"`
	}
	if err := json.Unmarshal(raw.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	fields := make([]review.SanitizedField, 0)
	appendField := func(role review.FieldRole, text string) {
		ordinal := len(fields)
		matches := []secretscan.Match{}
		redacted := 0
		if secret != "" {
			start := strings.Index(text, secret)
			if start >= 0 {
				match := secretscan.Match{SourceOrdinal: ordinal, RuleID: "generic-api-key", StartByte: start, EndByteExclusive: start + len(secret)}
				match.OccurrenceID = secretscan.OccurrenceID(match)
				matches = append(matches, match)
				redacted = len(secret)
			}
		}
		fields = append(fields, review.SanitizedField{Role: role, Ordinal: ordinal, ScannedByteCount: len(text), RedactedByteCount: redacted, Matches: matches})
	}
	appendMemory := func(value memoryWire) {
		for _, item := range value.Items {
			appendField(review.FieldRoleMemoryPath, item.Path)
			for _, symbol := range item.Symbols {
				appendField(review.FieldRoleMemorySymbol, symbol)
			}
			appendField(review.FieldRoleMemoryText, item.Text)
		}
	}
	for _, source := range wire.Sources {
		appendField(review.FieldRoleSourcePath, source.Path)
		appendField(review.FieldRoleSourceContent, source.Content)
	}
	for _, omission := range wire.SourceOmissions {
		appendField(review.FieldRoleSourceOmissionPath, omission.Path)
	}
	appendMemory(wire.Memory)
	for _, value := range wire.AdditionalMemory {
		appendMemory(value)
	}
	sanitizedPayload := raw.Payload()
	if secret != "" {
		sanitizedPayload = bytes.ReplaceAll(sanitizedPayload, []byte(secret), bytes.Repeat([]byte{'*'}, len(secret)))
	}
	inner, err := provider.NewRequest(raw.Capability(), raw.MediaType(), sanitizedPayload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := review.NewSanitizedModelRequest(scope.Identity(), raw, inner)
	if err != nil {
		t.Fatal(err)
	}
	total, redacted, matches := 0, 0, 0
	for _, field := range fields {
		total += field.ScannedByteCount
		redacted += field.RedactedByteCount
		matches += len(field.Matches)
	}
	expected := review.ScannerBinaryDigests{LauncherSHA256: strings.Repeat("b", 64), WorkerSHA256: strings.Repeat("c", 64)}
	receipt, err := review.NewSanitizedEgressReceipt(review.SanitizedEgressReceiptInput{
		ReviewScopeIdentity: scope.Identity(), RawRequestIdentity: raw.Identity(), SanitizedRequestIdentity: request.SanitizedRequestIdentity(),
		Scanner: review.ScannerProfile{WorkerProtocol: 1, Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: secretscan.BuildProfile, LauncherSHA256: expected.LauncherSHA256, WorkerSHA256: expected.WorkerSHA256},
		Initial: review.ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: total, MatchCount: matches}, Residual: review.ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: total}, RedactedByteCount: redacted, Fields: fields,
	})
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, receiptArtifact, err := review.NewSanitizedEgressArtifacts(rawArtifact, request, receipt, expected, time.UnixMilli(60))
	if err != nil {
		t.Fatal(err)
	}
	return request, receipt, requestArtifact, receiptArtifact, expected
}

// successfulProviderResult answers a version 7 generation context with candidate batch v2.
func successfulProviderResult(t *testing.T) gateway.RouteDispatchResult {
	t.Helper()
	return providerDocumentResult(t, `{"schema_version":2,"candidates":[{"title":"Issue","claim":"The value is not checked.","category":"correctness","fix":"Check the value before use.","severity_hint":"high","source_range":{"source_id":"source-1","start_line":1,"end_line":1},"evidence_ids":["source-1"]}]}`)
}

// legacyProviderResult answers a recorded pre-version-7 context with candidate batch v1.
func legacyProviderResult(t *testing.T) gateway.RouteDispatchResult {
	t.Helper()
	return providerDocumentResult(t, `{"schema_version":1,"candidates":[{"title":"Issue","claim":"The value is not checked.","severity_hint":"high","source_range":{"source_id":"source-1","start_line":1,"end_line":1},"evidence_ids":["source-1"]}]}`)
}

func providerDocumentResult(t *testing.T, document string) gateway.RouteDispatchResult {
	t.Helper()
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	usage, _ := provider.NewRouteTokenUsage(10, 5, 0)
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	result, _ := gateway.NewSuccessfulRouteDispatchResult(response)
	return result
}

func generationTaskRequest(t *testing.T, scope audit.ReviewScope, inputIdentity, handlerIdentity string, maxAttempts uint8) controlplane.TaskExecutionRequest {
	t.Helper()
	specs := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{
		{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
	}
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for _, spec := range specs {
		attempts := uint8(1)
		identity := strings.Repeat(string('a'+rune(len(tasks))), 64)
		handler := strings.Repeat(string('f'-rune(len(tasks))), 64)
		if spec.key == "candidates" {
			identity = strings.Repeat("6", 64)
			handler = handlerIdentity
			attempts = maxAttempts
		}
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, identity, handler, spec.deps, attempts, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("8", 64), strings.Repeat("9", 64), controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	at := int64(100)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(at))
	for _, task := range tasks[:len(tasks)-1] {
		at++
		_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
		at++
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker-a", time.UnixMilli(at))
		if err != nil {
			t.Fatal(err)
		}
		outputIdentity := strings.Repeat("7", 64)
		if task.Key() == "context" {
			outputIdentity = inputIdentity
		}
		completion, _ := controlplane.NewTaskSuccess(outputIdentity)
		at++
		if _, err = coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
	}
	at++
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
	at++
	candidate := tasks[len(tasks)-1]
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, candidate.Key(), candidate.HandlerIdentity(), "worker-a", time.UnixMilli(at))
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, candidate)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, candidate, lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func seedRouteSelection(t *testing.T, ledger audit.Ledger, scope audit.ReviewScope, authorization gateway.RouteAttemptAuthorization) {
	t.Helper()
	// This legacy model-handler fixture has no typed selection receipt. Bind the
	// attempted record structurally, without claiming exact routing/ranking proof.
	event, err := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, authorization.SelectionReceiptIdentity(), []string{strings.Repeat("1", 64), authorization.RouteRecordIdentity(), strings.Repeat("3", 64)}, time.UnixMilli(90))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), "", event); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationHandlerDispatchesAuditsAndPersistsAdmittedCandidates(t *testing.T) {
	secret := "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixtureWithContent(t, []byte(secret+"\nline two\n"))
	sanitized, receipt, requestArtifact, receiptArtifact, expected := sanitizedGenerationFixture(t, scope, contextArtifact, providerRequest, secret)
	dispatchRequest, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	authorization := generationAuthorization(t, scope, dispatchRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	_, _ = store.Put(context.Background(), requestArtifact, time.UnixMilli(60))
	_, _ = store.Put(context.Background(), receiptArtifact, time.UnixMilli(60))
	handler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)}, expected)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewSanitizedGenerationInput(contextArtifact, packet, snapshot, requestArtifact, receiptArtifact, expected, authorization)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	if err != nil {
		t.Fatal(err)
	}
	var inputHeader struct {
		SchemaVersion                          int    `json:"schema_version"`
		SanitizedRequestArtifactIdentity       string `json:"sanitized_request_artifact_identity"`
		SanitizedEgressReceiptArtifactIdentity string `json:"sanitized_egress_receipt_artifact_identity"`
		SanitizedEgressReceiptIdentity         string `json:"sanitized_egress_receipt_identity"`
	}
	if json.Unmarshal(inputArtifact.Payload(), &inputHeader) != nil || inputHeader.SchemaVersion != 3 || inputHeader.SanitizedRequestArtifactIdentity != requestArtifact.Identity() || inputHeader.SanitizedEgressReceiptArtifactIdentity != receiptArtifact.Identity() || inputHeader.SanitizedEgressReceiptIdentity != receipt.Identity() {
		t.Fatal("generation input omitted sanitized authority identities")
	}
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	request := generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1)
	validated, err := artifactvalidation.NewValidatedTaskHandler(
		handler, store, fixedClock{at: time.UnixMilli(201)},
		[]artifact.Kind{artifact.KindTaskInput}, []artifact.Kind{artifact.KindCandidateBatch},
	)
	if err != nil {
		t.Fatal(err)
	}
	completion := validated.Execute(context.Background(), request)
	if completion.Status() != controlplane.TaskCompletionSucceeded || completion.Validate() != nil || dispatcher.calls != 1 {
		t.Fatalf("completion=%#v calls=%d", completion, dispatcher.calls)
	}
	if dispatcher.requestIdentity != authorization.RequestIdentity() || !bytes.Equal(dispatcher.requestPayload, dispatchRequest.Payload()) || bytes.Contains(dispatcher.requestPayload, []byte(secret)) || bytes.Contains(dispatcher.requestPayload, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) || receipt.SanitizedRequestIdentity() != dispatcher.requestIdentity || dispatcher.receiptIdentity != receipt.Identity() {
		t.Fatal("dispatcher received bytes outside sanitized authority")
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(contextArtifact.Payload(), []byte(secret)) {
		t.Fatal("authorized raw context lost secret canary")
	}
	for name, payload := range map[string][]byte{
		"sanitized request": requestArtifact.Payload(), "receipt": receiptArtifact.Payload(), "generation input": inputArtifact.Payload(), "generation output": output.Payload(),
	} {
		if bytes.Contains(payload, []byte(secret)) || bytes.Contains(payload, []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) {
			t.Fatalf("%s leaked secret canary", name)
		}
	}
	result, err := ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.Candidates().Findings()[0].Title() != "Issue" || result.RouteExecution().Output().ArtifactIdentity() != result.Candidates().Identity() || result.RouteExecution().Output().ContextIdentity() != packet.Identity() {
		t.Fatalf("result=%#v", result)
	}
	events, err := ledger.Read(context.Background(), scope, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[1].Kind() != audit.EventRouteAttemptClaimed || events[2].Kind() != audit.EventRouteDispatchCompleted || events[3].Kind() != audit.EventRouteCostReconciled {
		t.Fatalf("events=%#v", events)
	}
	replayed := validated.Execute(context.Background(), request)
	if replayed.Status() != controlplane.TaskCompletionFailed || dispatcher.calls != 1 {
		t.Fatalf("existing route claim redispatched: status=%s calls=%d", replayed.Status(), dispatcher.calls)
	}
	if handler.Validate() != nil || fmt.Sprint(handler) != "model generation task handler" || fmt.Sprintf("%#v", handler) != "model.GenerationHandler{<redacted>}" {
		t.Fatalf("handler formatting leaked: %v / %#v", handler, handler)
	}
}

func TestGenerationInputSchemaDeclaresSanitizedAuthorityVersion(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "artifact", "model-generation-input-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"schema_version": {
      "const": 3`, `"sanitized_request_artifact_identity"`, `"sanitized_egress_receipt_artifact_identity"`, `"sanitized_egress_receipt_identity"`} {
		if !bytes.Contains(encoded, []byte(required)) {
			t.Fatalf("generation input schema missing %s", required)
		}
	}
}

func TestGenerationHandlerRejectsIncompleteOrCrossWiredSanitizedAuthorityBeforeClaim(t *testing.T) {
	secret := "sk-proj-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	scope, snapshot, packet, contextArtifact, raw := generationContextFixtureWithContent(t, []byte(secret+"\nline two\n"))
	sanitized, _, requestArtifact, receiptArtifact, expected := sanitizedGenerationFixture(t, scope, contextArtifact, raw, secret)
	dispatchRequest, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	authorization := generationAuthorization(t, scope, dispatchRequest)
	input, err := NewSanitizedGenerationInput(contextArtifact, packet, snapshot, requestArtifact, receiptArtifact, expected, authorization)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		putReceipt bool
		expected   review.ScannerBinaryDigests
	}{
		{"missing receipt", false, expected},
		{"wrong trusted launcher", true, review.ScannerBinaryDigests{LauncherSHA256: strings.Repeat("d", 64), WorkerSHA256: expected.WorkerSHA256}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
			catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
			ledger := audit.NewMemoryLedger()
			seedRouteSelection(t, ledger, scope, authorization)
			store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
			for _, value := range []artifact.Artifact{contextArtifact, requestArtifact, inputArtifact} {
				_, _ = store.Put(context.Background(), value, time.UnixMilli(80))
			}
			if test.putReceipt {
				_, _ = store.Put(context.Background(), receiptArtifact, time.UnixMilli(80))
			}
			handler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)}, test.expected)
			if err != nil {
				t.Fatal(err)
			}
			completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
			if completion.Status() != controlplane.TaskCompletionFailed || dispatcher.calls != 0 {
				t.Fatalf("completion=%#v calls=%d", completion, dispatcher.calls)
			}
			events, err := ledger.Read(context.Background(), scope, 0, 10)
			if err != nil || len(events) != 1 || events[0].Kind() != audit.EventRouteSelected {
				t.Fatalf("route claim occurred: events=%#v err=%v", events, err)
			}
		})
	}
}

func TestGenerationHandlerRejectsControlPlaneRetryAuthority(t *testing.T) {
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := newLegacyGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 2))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailurePolicy || dispatcher.calls != 0 {
		t.Fatalf("completion=%#v calls=%d", completion, dispatcher.calls)
	}
}

func TestGenerationHandlerAuditsTypedProviderFailureWithoutOutput(t *testing.T) {
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	// A server error is not retried, so the one attempt is audited alone.
	failedResult, _ := gateway.NewFailedRouteDispatchResult(
		gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown,
		provider.NewUnknownRouteTokenUsage(), 0,
	)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: failedResult}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := newLegacyGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureTransient || completion.OutputIdentity() != "" || dispatcher.calls != 1 {
		t.Fatalf("completion=%#v failure=%s calls=%d", completion, completion.Failure(), dispatcher.calls)
	}
	events, err := ledger.Read(context.Background(), scope, 0, 10)
	if err != nil || len(events) != 4 || events[2].SubjectIdentity() == "" || events[3].SubjectIdentity() == "" {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
}

// A provider that refuses for billing, or does not serve or has retired the
// model, fails the task once as a policy refusal that the control plane does
// not retry, as an authentication refusal does. The completion names the
// refusal with its content-free reason; a rate limit also carries the
// provider's Retry-After; a reply the adapter refused keeps its internal
// failure and names provider_response_invalid; a credential that was never
// sent, or a request that was never built, names none.
func TestGenerationHandlerRefusesProviderRefusalAsPolicy(t *testing.T) {
	for _, test := range []struct {
		failure    gateway.RouteFailureClass
		safety     gateway.RouteReplaySafety
		retryAfter uint32
		run        controlplane.RunFailure
		reason     controlplane.TaskFailureReason
	}{
		{gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderPaymentRequired},
		{gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderModelUnavailable},
		{gateway.RouteFailureModelRetired, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderModelRetired},
		{gateway.RouteFailureAuthentication, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderAuthenticationFailed},
		{gateway.RouteFailureAuthorization, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderAuthorizationDenied},
		{gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 7_000, controlplane.RunFailureTransient, controlplane.TaskFailureReasonProviderRateLimited},
		{gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailureTransient, controlplane.TaskFailureReasonProviderRateLimited},
		{gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown, 0, controlplane.RunFailureInternal, controlplane.TaskFailureReasonProviderResponseInvalid},
		{gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0, controlplane.RunFailureInternal, controlplane.TaskFailureReasonProviderResponseInvalid},
		{gateway.RouteFailureAuthentication, gateway.RouteReplayNotDispatched, 0, controlplane.RunFailurePolicy, 0},
		{gateway.RouteFailureInvalidResponse, gateway.RouteReplayNotDispatched, 0, controlplane.RunFailureInternal, 0},
		{gateway.RouteFailureOutputExhausted, gateway.RouteReplayOutcomeUnknown, 0, controlplane.RunFailureInternal, 0},
		{gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0, controlplane.RunFailureTransient, 0},
	} {
		failure := test.failure
		t.Run(failure.String()+"/"+test.safety.String(), func(t *testing.T) {
			scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
			authorization := generationAuthorization(t, scope, providerRequest)
			failedResult, _ := gateway.NewFailedRouteDispatchResult(failure, test.safety, provider.NewUnknownRouteTokenUsage(), test.retryAfter)
			dispatcher := &recordingDispatcher{adapterID: "test-model", result: failedResult}
			catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
			ledger := audit.NewMemoryLedger()
			seedRouteSelection(t, ledger, scope, authorization)
			store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
			_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
			handler, _ := newLegacyGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
			handler.wait = func(context.Context, time.Duration) error { return nil }
			input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
			inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
			_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
			completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
			// A rate limit the provider refused before processing is retried
			// twice on the same route; every other refusal is sent once.
			calls := 1
			if failure == gateway.RouteFailureRateLimited && test.safety == gateway.RouteReplayNoSideEffect {
				calls = 1 + gateway.MaxRateLimitRetries
			}
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil || completion.Failure() != test.run || completion.FailureReason() != test.reason || completion.OutputIdentity() != "" || dispatcher.calls != calls {
				t.Fatalf("completion failure=%s reason=%s calls=%d", completion.Failure(), completion.FailureReason(), dispatcher.calls)
			}
			if test.run == controlplane.RunFailurePolicy && completion.Failure().Retryable() {
				t.Fatal("a provider refusal is retryable")
			}
		})
	}
}

// Every route failure class maps to one run failure; a refusal an operator
// must act on is never a retryable internal failure.
func TestMapRouteFailureCoversEveryClass(t *testing.T) {
	want := map[gateway.RouteFailureClass]controlplane.RunFailure{
		gateway.RouteFailureTransport:        controlplane.RunFailureTransient,
		gateway.RouteFailureRateLimited:      controlplane.RunFailureTransient,
		gateway.RouteFailureProviderServer:   controlplane.RunFailureTransient,
		gateway.RouteFailureTimeout:          controlplane.RunFailureTransient,
		gateway.RouteFailureConnection:       controlplane.RunFailureTransient,
		gateway.RouteFailureInvalidResponse:  controlplane.RunFailureInternal,
		gateway.RouteFailureAuthentication:   controlplane.RunFailurePolicy,
		gateway.RouteFailureAuthorization:    controlplane.RunFailurePolicy,
		gateway.RouteFailurePolicyDenied:     controlplane.RunFailurePolicy,
		gateway.RouteFailureBudgetExhausted:  controlplane.RunFailurePolicy,
		gateway.RouteFailureCancelled:        controlplane.RunFailureCanceled,
		gateway.RouteFailureOutputExhausted:  controlplane.RunFailureInternal,
		gateway.RouteFailurePaymentRequired:  controlplane.RunFailurePolicy,
		gateway.RouteFailureModelUnavailable: controlplane.RunFailurePolicy,
		gateway.RouteFailureModelRetired:     controlplane.RunFailurePolicy,
		gateway.RouteFailureRequestRejected:  controlplane.RunFailurePolicy,
	}
	for class := gateway.RouteFailureTransport; class.Validate() == nil; class++ {
		expected, ok := want[class]
		if !ok {
			t.Fatalf("route failure %s has no expected run failure", class)
		}
		if got := mapRouteFailure(class); got != expected {
			t.Fatalf("route failure %s maps to %s, want %s", class, got, expected)
		}
		delete(want, class)
	}
	if len(want) != 0 {
		t.Fatalf("classes outside the closed set: %v", want)
	}
}

func TestGenerationInputEncodingIsCanonicalAndDefensive(t *testing.T) {
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	input, err := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeGenerationInput(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGenerationInput(encoded)
	if err != nil || parsed.Identity() != input.Identity() || parsed.Authorization().Identity() != authorization.Identity() || parsed.Snapshot().Identity() != snapshot.Identity() {
		t.Fatalf("parsed input=(%#v,%v)", parsed, err)
	}
	reencoded, _ := EncodeGenerationInput(parsed)
	if string(reencoded) != string(encoded) {
		t.Fatal("input encoding was not canonical")
	}
	if parsed, err := ParseGenerationInput(append(append([]byte(nil), encoded...), '\n')); err == nil || parsed.Identity() != "" {
		t.Fatalf("noncanonical input=(%#v,%v)", parsed, err)
	}
	items := parsed.EvidenceItems()
	items[0] = evidence.EvidenceItem{}
	if parsed.EvidenceItems()[0].ID() != "source-1" {
		t.Fatal("input evidence was mutable")
	}
	if fmt.Sprint(input) != "model generation input" || fmt.Sprintf("%#v", input) != "model.GenerationInput{<redacted>}" {
		t.Fatalf("input formatting leaked: %v / %#v", input, input)
	}
}

func TestGenerationHandlerRequiresAuditedSelectionBeforeDispatch(t *testing.T) {
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := newLegacyGenerationHandler(store, catalog, audit.NewMemoryLedger(), fixedClock{at: time.UnixMilli(200)})
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureInternal || dispatcher.calls != 0 {
		t.Fatalf("completion=%#v calls=%d", completion, dispatcher.calls)
	}
}
