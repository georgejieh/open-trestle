package context

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/scm"
	"strings"
	"testing"
	"time"
)

type contextTestClock struct{ at time.Time }

func (c contextTestClock) Now() time.Time { return c.at }

type contextTestSource struct {
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
}

func (a *contextTestSource) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a *contextTestSource) Acquire(_ context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	return a.results[r.Revision().Identity()]
}
func makeSourceResult(t *testing.T, contents map[string][]byte) scm.SourceAdapterResult {
	t.Helper()
	files := make([]evidence.RepositoryFile, 0, len(contents))
	for path, content := range contents {
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
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
	scope audit.ReviewScope,
	request provider.Request,
	providerID, adapterID, connectionID, modelID, modelVersion, selectionIdentity, recordIdentity string,
) (gateway.RouteAttemptAuthorization, error) {
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
	return gateway.ParseRouteAttemptAuthorization(encoded)
}

type contextTestAuthorizer struct{ identity string }

func (a contextTestAuthorizer) Identity() string { return a.identity }
func (a contextTestAuthorizer) Authorize(_ context.Context, scope audit.ReviewScope, request provider.Request, policy string, _ time.Time) (gateway.RouteAttemptAuthorization, error) {
	if policy != strings.Repeat("f", 64) {
		return gateway.RouteAttemptAuthorization{}, errors.New("wrong policy")
	}
	return routeAuthorization(scope, request, "test-provider", "test-model", "primary/test", "test-model", "1", strings.Repeat("c", 64), strings.Repeat("d", 64))
}

func TestHandlerBuildsBoundGenerationAuthority(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &contextTestSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{baseRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.go": []byte("package p\nfunc Changed() int{return 1}\n"), "a_test.go": []byte("package p\nfunc TestChanged(){_=Changed()}\n")}), headRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.go": []byte("package p\nfunc Changed() int{return 2}\n"), "a_test.go": []byte("package p\nfunc TestChanged(){_=Changed()}\n")})}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceTaskHandler, _ := sourcehandler.NewHandler(store, adapter, contextTestClock{time.UnixMilli(200)})
	changeTaskHandler, _ := changehandler.NewHandler(store, contextTestClock{time.UnixMilli(210)})
	analysisTaskHandler, _ := analysishandler.NewHandler(store, contextTestClock{time.UnixMilli(215)})
	index := memorycore.NewLexicalIndex()
	memoryScope, scopeErr := memorycore.NewScope("tenant", "repository", "reviewer", memorycore.RefVisibilityExact, headRevision.Identity(), []string{"."})
	if scopeErr != nil {
		t.Fatal(scopeErr)
	}
	record, recordErr := memorycore.NewRecord(memoryScope, memorycore.RecordInput{Kind: memorycore.RecordCanonicalFact, Taint: memorycore.TaintTrusted, Path: "a.txt", Text: "this path has a parser invariant", EvidenceIDs: []string{strings.Repeat("9", 64)}, ProducerIdentity: strings.Repeat("7", 64), ObservedAt: time.UnixMilli(10), ValidFrom: time.UnixMilli(10)})
	if recordErr != nil {
		t.Fatal(recordErr)
	}
	if _, _, err := index.Add(context.Background(), memoryScope, record); err != nil {
		t.Fatal(err)
	}
	policyIdentity := strings.Repeat("f", 64)
	memoryTaskHandler, _ := memoryhandler.NewHandler(store, contextTestClock{time.UnixMilli(220)}, index, strings.Repeat("6", 64), policyIdentity, "reviewer", []string{"."}, 10, 20)
	authorizer := contextTestAuthorizer{identity: strings.Repeat("5", 64)}
	contextTaskHandler, _ := NewHandler(store, contextTestClock{time.UnixMilli(230)}, authorizer)
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeTaskHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	analysisTask, _ := controlplane.NewTaskDefinition("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("3", 64), analysisTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	memoryTask, _ := controlplane.NewTaskDefinition("memory", controlplane.TaskRetrieveContext, strings.Repeat("d", 64), memoryTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	contextTask, _ := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("4", 64), contextTaskHandler.HandlerIdentity(), []string{"analysis", "memory"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), policyIdentity, controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, analysisTask, memoryTask, contextTask})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	execute := func(task controlplane.TaskDefinition, handler controlplane.TaskHandler, at time.Time) {
		state, err := coordinator.Advance(context.Background(), plan, at)
		if err != nil {
			t.Fatal(err)
		}
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		if err != nil {
			t.Fatal(err)
		}
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("%s completion=%#v", task.Key(), completion)
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	execute(baseTask, sourceTaskHandler, time.UnixMilli(101))
	execute(headTask, sourceTaskHandler, time.UnixMilli(103))
	execute(changeTask, changeTaskHandler, time.UnixMilli(105))
	execute(analysisTask, analysisTaskHandler, time.UnixMilli(107))
	execute(memoryTask, memoryTaskHandler, time.UnixMilli(109))
	execute(contextTask, contextTaskHandler, time.UnixMilli(111))
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(113))
	if err != nil {
		t.Fatal(err)
	}
	contextState, _ := state.Task("context")
	output, err := store.Get(context.Background(), scope, contextState.OutputIdentity(), time.UnixMilli(231))
	if err != nil {
		t.Fatal(err)
	}
	input, err := modelhandler.ParseGenerationInput(output.Payload())
	if err != nil || input.ReviewScopeIdentity() != scope.Identity() || input.Authorization().RequestIdentity() == "" {
		t.Fatalf("input=(%#v,%v)", input, err)
	}
	contextArtifact, err := store.Get(context.Background(), scope, input.ContextArtifactIdentity(), time.UnixMilli(231))
	if err != nil {
		t.Fatal(err)
	}
	if contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.Origin() != artifact.OriginHost || len(input.EvidenceItems()) != 2 {
		t.Fatalf("context artifact or evidence mismatch: %d", len(input.EvidenceItems()))
	}
	sawTest := false
	for _, item := range input.EvidenceItems() {
		if item.SourceRange().Path() == "a_test.go" {
			sawTest = true
		}
	}
	if !sawTest {
		t.Fatal("semantic affected-test context omitted")
	}
}
