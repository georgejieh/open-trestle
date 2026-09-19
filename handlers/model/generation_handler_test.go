package model

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type recordingDispatcher struct {
	adapterID string
	result    gateway.RouteDispatchResult
	calls     int
}

func (d *recordingDispatcher) AdapterID() string             { return d.adapterID }
func (d *recordingDispatcher) ConfigurationIdentity() string { return strings.Repeat("a", 64) }
func (d *recordingDispatcher) DispatchRoute(_ context.Context, _ gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	d.calls++
	return d.result
}

func generationContextFixture(t *testing.T) (audit.ReviewScope, review.ReviewSnapshot, review.ContextPacket, artifact.Artifact, provider.Request) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	memoryScope, _ := memory.NewScope("tenant-a", "repo-a", "actor-a", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	content := []byte("line one\nline two\n")
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
		AttemptOrdinal: 1, RouteAttemptOrdinal: 1, Zone: "private_remote", ProviderID: providerID,
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

func successfulProviderResult(t *testing.T) gateway.RouteDispatchResult {
	t.Helper()
	document := `{"schema_version":1,"candidates":[{"title":"Issue","claim":"The value is not checked.","severity_hint":"high","source_range":{"source_id":"source-1","start_line":1,"end_line":1},"evidence_ids":["source-1"]}]}`
	document = strings.ReplaceAll(document, `\"`, `"`)
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
	event, err := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, authorization.SelectionReceiptIdentity(), []string{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)}, time.UnixMilli(90))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), "", event); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationHandlerDispatchesAuditsAndPersistsAdmittedCandidates(t *testing.T) {
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	request := generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1)
	validated, err := artifact.NewValidatedTaskHandler(
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
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
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

func TestGenerationHandlerRejectsControlPlaneRetryAuthority(t *testing.T) {
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
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
	failedResult, _ := gateway.NewFailedRouteDispatchResult(
		gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect,
		provider.NewUnknownRouteTokenUsage(), 2000,
	)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: failedResult}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
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
	handler, _ := NewGenerationHandler(store, catalog, audit.NewMemoryLedger(), fixedClock{at: time.UnixMilli(200)})
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureInternal || dispatcher.calls != 0 {
		t.Fatalf("completion=%#v calls=%d", completion, dispatcher.calls)
	}
}
