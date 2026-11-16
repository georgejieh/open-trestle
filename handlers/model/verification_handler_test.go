package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/artifactvalidation"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

type failingVerificationSanitizer struct{}

func (failingVerificationSanitizer) Identity() string { return strings.Repeat("8", 64) }
func (failingVerificationSanitizer) ExpectedBinaryDigests() review.ScannerBinaryDigests {
	return review.ScannerBinaryDigests{LauncherSHA256: strings.Repeat("b", 64), WorkerSHA256: strings.Repeat("c", 64)}
}
func (failingVerificationSanitizer) SanitizeVerification(context.Context, provider.Request, string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	return review.SanitizedModelRequest{}, review.SanitizedEgressReceipt{}, review.ErrSanitizedEgressUnavailable
}

type fixedVerificationSanitizer struct {
	request  review.SanitizedModelRequest
	receipt  review.SanitizedEgressReceipt
	expected review.ScannerBinaryDigests
}

func (fixedVerificationSanitizer) Identity() string { return strings.Repeat("8", 64) }
func (value fixedVerificationSanitizer) ExpectedBinaryDigests() review.ScannerBinaryDigests {
	return value.expected
}
func (value fixedVerificationSanitizer) SanitizeVerification(context.Context, provider.Request, string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	return value.request, value.receipt, nil
}

type fixedVerificationAuthorizer struct {
	identity        string
	authority       VerificationAuthority
	calls           int
	requestIdentity string
}

func (a *fixedVerificationAuthorizer) Identity() string { return a.identity }
func (a *fixedVerificationAuthorizer) Authorize(_ context.Context, _ audit.ReviewScope, request provider.Request, _ gateway.RouteExecutionRecord) (VerificationAuthority, error) {
	a.calls++
	a.requestIdentity = request.Identity()
	return a.authority, nil
}

func appendSelectionEvent(t *testing.T, ledger audit.Ledger, scope audit.ReviewScope, authorization gateway.RouteAttemptAuthorization, at time.Time) {
	t.Helper()
	head, found, err := ledger.Head(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	sequence := uint64(1)
	previous := ""
	if found {
		sequence = head.Sequence() + 1
		previous = head.Identity()
	}
	// This legacy verifier fixture has no typed selection receipt. Bind the
	// attempted record structurally, without claiming exact routing/ranking proof.
	event, err := audit.NewEvent(scope, sequence, previous, audit.EventRouteSelected, authorization.SelectionReceiptIdentity(), []string{strings.Repeat("1", 64), authorization.RouteRecordIdentity(), strings.Repeat("3", 64)}, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), previous, event); err != nil {
		t.Fatal(err)
	}
}

func completedGenerationFixture(t *testing.T) (audit.ReviewScope, *artifact.MemoryStore, audit.Ledger, artifact.Artifact, artifact.Artifact, artifact.Artifact, GenerationResult) {
	t.Helper()
	return completedGenerationFixtureWithDispatch(t, successfulProviderResult(t))
}

func completedGenerationFixtureWithDispatch(t *testing.T, dispatch gateway.RouteDispatchResult) (audit.ReviewScope, *artifact.MemoryStore, audit.Ledger, artifact.Artifact, artifact.Artifact, artifact.Artifact, GenerationResult) {
	t.Helper()
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: dispatch}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 30)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := newLegacyGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	if completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("generation=%#v", completion)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	return scope, store, ledger, contextArtifact, inputArtifact, output, result
}

func verificationProviderResult(t *testing.T, candidates review.CandidateBatch) gateway.RouteDispatchResult {
	t.Helper()
	candidateID := candidates.Findings()[0].Identity()
	document := `{"schema_version":1,"verdicts":[{"candidate_id":"` + candidateID + `","outcome":"verified","severity":"high","rationale":"The cited source confirms the issue.","evidence_ids":["source-1"]}]}`
	document = strings.ReplaceAll(document, `\"`, `"`)
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	usage, _ := provider.NewRouteTokenUsage(12, 6, 0)
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	result, _ := gateway.NewSuccessfulRouteDispatchResult(response)
	return result
}

func verificationTaskRequest(t *testing.T, scope audit.ReviewScope, candidateOutput, handlerIdentity string) controlplane.TaskExecutionRequest {
	t.Helper()
	specs := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{
		{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
	}
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for index, spec := range specs {
		handler := strings.Repeat(string('a'+rune(index)), 64)
		if spec.key == "verification" {
			handler = handlerIdentity
		}
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, strings.Repeat(string('1'+rune(index)), 64), handler, spec.deps, 1, 1000, 30000, true)
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
	at := int64(300)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(at))
	for _, task := range tasks[:len(tasks)-1] {
		at++
		_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
		at++
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker-v", time.UnixMilli(at))
		if err != nil {
			t.Fatal(err)
		}
		output := strings.Repeat("7", 64)
		if task.Key() == "candidates" {
			output = candidateOutput
		}
		completion, _ := controlplane.NewTaskSuccess(output)
		at++
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
	}
	at++
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
	verification := tasks[len(tasks)-1]
	at++
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, verification.Key(), verification.HandlerIdentity(), "worker-v", time.UnixMilli(at))
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, verification)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, verification, lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestVerificationHandlerUsesIndependentRouteAndPersistsPromotedFindings(t *testing.T) {
	scope, store, ledger, contextArtifact, inputArtifact, generationArtifact, generation := completedGenerationFixture(t)
	verificationContext := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	rawVerificationRequest, _ := verificationContext.ProviderRequest()
	sanitizer := testsupport.NewCleanVerificationSanitizer()
	sanitizedVerification, _, err := sanitizer.SanitizeVerification(context.Background(), rawVerificationRequest, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	verificationRequest, err := sanitizedVerification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	verificationAuthorization := routeAuthorization(t, scope, verificationRequest, "verifier-provider", "test-verifier", "primary/verifier", "verifier-model", "1", strings.Repeat("e", 64), strings.Repeat("f", 64))
	policy, _ := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	authority, err := NewVerificationAuthority(verificationRequest, generation.RouteExecution(), verificationAuthorization, policy)
	if err != nil {
		t.Fatal(err)
	}
	appendSelectionEvent(t, ledger, scope, verificationAuthorization, time.UnixMilli(210))
	authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64), authority: authority}
	dispatcher := &recordingDispatcher{adapterID: "test-verifier", result: verificationProviderResult(t, generation.Candidates())}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	handler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(220)}, sanitizer)
	if err != nil {
		t.Fatal(err)
	}
	request := verificationTaskRequest(t, scope, generationArtifact.Identity(), handler.HandlerIdentity())
	validated, err := artifactvalidation.NewValidatedTaskHandler(
		handler, store, fixedClock{at: time.UnixMilli(221)},
		[]artifact.Kind{artifact.KindCandidateBatch}, []artifact.Kind{artifact.KindVerifiedFindingSet},
	)
	if err != nil {
		t.Fatal(err)
	}
	completion := validated.Execute(context.Background(), request)
	if completion.Status() != controlplane.TaskCompletionSucceeded || dispatcher.calls != 1 || authorizer.calls != 1 {
		t.Fatalf("completion=%#v calls=(%d,%d)", completion, dispatcher.calls, authorizer.calls)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(221))
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseStoredVerificationResultArtifact(context.Background(), store, time.UnixMilli(221), output, generationArtifact, inputArtifact, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if result.egress.empty() || !result.egress.valid() || result.egress.sanitizedRequestIdentity != dispatcher.requestIdentity || authorizer.requestIdentity != dispatcher.requestIdentity || result.RouteExecution().Authorization().RequestIdentity() != dispatcher.requestIdentity {
		t.Fatal("verifier authority, dispatch, and sanitized result identities diverged")
	}
	requestArtifact, err := store.Get(context.Background(), scope, result.egress.sanitizedRequestArtifactIdentity, time.UnixMilli(221))
	if err != nil {
		t.Fatal(err)
	}
	receiptArtifact, err := store.Get(context.Background(), scope, result.egress.receiptArtifactIdentity, time.UnixMilli(221))
	if err != nil {
		t.Fatal(err)
	}
	rawVerificationRequest, err = result.VerificationContext().ProviderRequest()
	if err != nil || review.ValidateSanitizedVerificationEgressArtifacts(rawVerificationRequest, generation.ContextIdentity(), generation.Candidates().Identity(), generationArtifact, inputArtifact, contextArtifact, requestArtifact, receiptArtifact, sanitizer.ExpectedBinaryDigests()) != nil {
		t.Fatal("stored verifier egress artifacts did not reload as one authority")
	}
	if _, err := ParseVerificationResultArtifact(output, generationArtifact, inputArtifact, contextArtifact); err == nil {
		t.Fatal("v2 result parsed without reloading its sanitizer authority")
	}
	if _, err := ParseVerificationResultArtifact(output, generationArtifact, inputArtifact, contextArtifact, VerificationEgressArtifacts{SanitizedRequest: requestArtifact, Receipt: requestArtifact}); err == nil {
		t.Fatal("v2 result parsed with cross-wired sanitizer artifacts")
	}
	if result.Verification().Results()[0].Outcome() != review.VerificationVerified || len(result.VerifiedFindings().Findings()) != 1 || result.RouteIndependence().Level() != gateway.RouteIndependenceDistinctProvider || result.IndependentReceipt().VerifiedCount() != 1 {
		t.Fatalf("result=%#v", result)
	}
	if handler.Validate() != nil || fmt.Sprint(handler) != "model verification task handler" || fmt.Sprintf("%#v", handler) != "model.VerificationHandler{<redacted>}" || fmt.Sprint(result) != "model verification result" {
		t.Fatalf("formatting leaked: %v / %#v / %v", handler, handler, result)
	}
	events, err := ledger.Read(context.Background(), scope, 0, 20)
	if err != nil || len(events) != 8 || events[6].Kind() != audit.EventRouteDispatchCompleted || events[7].Kind() != audit.EventRouteCostReconciled {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
	replayed := validated.Execute(context.Background(), request)
	if replayed.Status() != controlplane.TaskCompletionFailed || dispatcher.calls != 1 {
		t.Fatalf("existing verifier claim redispatched: status=%s calls=%d", replayed.Status(), dispatcher.calls)
	}
}

func generationContextForResult(t *testing.T, contextArtifact, inputArtifact artifact.Artifact, generation GenerationResult) review.VerificationRequestContext {
	t.Helper()
	input, err := ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	context, err := review.NewVerificationRequestContext(contextArtifact.Payload(), generation.ContextIdentity(), contextArtifact.Scope().Identity(), input.MemoryScopeIdentity(), input.MemoryIdentity(), input.Snapshot(), input.EvidenceItems(), generation.Candidates())
	if err != nil {
		t.Fatal(err)
	}
	return context
}

type modelRouteRegistryReader struct{ record provider.RouteRegistryRecord }

func (r modelRouteRegistryReader) LookupRouteRegistryRecord(context.Context, string) (provider.RouteRegistryRecord, error) {
	return r.record, nil
}

type modelRouteManifestReader struct{ content []byte }

func (r modelRouteManifestReader) OpenRouteEvidenceManifest(context.Context, string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(string(r.content))), nil
}

type modelRouteInventory struct {
	identity string
	snapshot VerificationRouteSnapshot
	calls    int
}

func (i *modelRouteInventory) Identity() string { return i.identity }
func (i *modelRouteInventory) Snapshot(context.Context, audit.ReviewScope) (VerificationRouteSnapshot, error) {
	i.calls++
	return i.snapshot, nil
}

func verifierObservedRoute(t *testing.T) (gateway.ObservedRouteCandidate, provider.RoutePerformanceObservation) {
	t.Helper()
	reference, _ := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "verifier-provider", "test-verifier", "primary/verifier", "verifier-model", "1")
	capabilities, _ := provider.NewModelCapabilities(128000, 16000, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	declaration, _ := provider.NewRouteCapabilityDeclaration(reference, capabilities)
	pricing, _ := provider.NewRoutePricing(0, 0)
	candidate, _ := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier4)
	manifest := []byte("verifier route evidence")
	digest := sha256.Sum256(manifest)
	record, _ := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	resolved, err := gateway.ResolveRouteRegistryRecord(context.Background(), record.Identity(), modelRouteRegistryReader{record}, modelRouteManifestReader{manifest})
	if err != nil {
		t.Fatal(err)
	}
	operational, _ := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	observed, _ := gateway.NewObservedRouteCandidate(resolved, operational)
	performance, _ := provider.NewUnknownRoutePerformanceObservation(record.Identity(), 1)
	return observed, performance
}

func TestPolicyVerificationAuthorizerFiltersAndAuditsIndependentRoute(t *testing.T) {
	scope, _, ledger, contextArtifact, inputArtifact, _, generation := completedGenerationFixture(t)
	verificationContext := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	rawRequest, _ := verificationContext.ProviderRequest()
	sanitized, _, err := testsupport.NewCleanVerificationSanitizer().SanitizeVerification(context.Background(), rawRequest, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	request, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	route, observation := verifierObservedRoute(t)
	snapshot, err := NewVerificationRouteSnapshot(1, 1, []gateway.ObservedRouteCandidate{route}, []provider.RoutePerformanceObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	inventory := &modelRouteInventory{identity: strings.Repeat("a", 64), snapshot: snapshot}
	requirements, _ := provider.NewModelRequirements(1, 1, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZonePrivateRemote)
	constraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	budget, _ := provider.NewModelCostBudget(1, 100, 0)
	ranking, _ := gateway.NewRouteRankingPolicy(nil)
	independence, _ := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	authorizer, err := NewPolicyVerificationAuthorizer(inventory, requirements, constraints, budget, ranking, independence, ledger, fixedClock{at: time.UnixMilli(210)})
	if err != nil {
		t.Fatal(err)
	}
	if rawAuthority, rawErr := authorizer.Authorize(context.Background(), scope, rawRequest, generation.RouteExecution()); rawErr == nil || rawAuthority.Identity() != "" || inventory.calls != 0 {
		t.Fatal("verifier authorizer accepted raw unscanned authority")
	}
	authority, err := authorizer.Authorize(context.Background(), scope, request, generation.RouteExecution())
	if err != nil {
		t.Fatal(err)
	}
	if authority.Authorization().RouteReference().ProviderID() != "verifier-provider" || !authority.MatchesGeneration(request, generation.RouteExecution()) || inventory.calls != 1 || authorizer.Validate() != nil {
		t.Fatalf("authority=%#v calls=%d", authority, inventory.calls)
	}
	if localInvestigationVerificationAuthorization(authority.Authorization()) {
		t.Fatal("selected remote verifier authorization passed the local investigation recheck")
	}
	events, err := ledger.Read(context.Background(), scope, 0, 10)
	if err != nil || len(events) != 5 || events[4].Kind() != audit.EventRouteSelected || events[4].SubjectIdentity() != authority.Authorization().SelectionReceiptIdentity() {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
}

func TestVerificationHandlerFailsBeforeAuthorizerClaimAndDispatchOnSanitizerFailure(t *testing.T) {
	scope, store, ledger, _, _, generationArtifact, _ := completedGenerationFixture(t)
	authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64)}
	dispatcher := &recordingDispatcher{adapterID: "test-verifier", result: gateway.RouteDispatchResult{}}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	handler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(220)}, failingVerificationSanitizer{})
	if err != nil {
		t.Fatal(err)
	}
	completion := handler.Execute(context.Background(), verificationTaskRequest(t, scope, generationArtifact.Identity(), handler.HandlerIdentity()))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailurePolicy || authorizer.calls != 0 || dispatcher.calls != 0 {
		t.Fatalf("sanitizer failure reached authority or dispatch: completion=%#v calls=(%d,%d)", completion, authorizer.calls, dispatcher.calls)
	}
	events, err := ledger.Read(context.Background(), scope, 0, 20)
	if err != nil || len(events) != 4 {
		t.Fatalf("sanitizer failure changed route ledger: events=%d err=%v", len(events), err)
	}
}

func TestVerificationHandlerRejectsGenerationReceiptReuseBeforeAuthorizer(t *testing.T) {
	scope, store, ledger, contextArtifact, _, generationArtifact, _ := completedGenerationFixture(t)
	rawGeneration, err := provider.NewRequest(provider.CapabilityReviewV1, contextArtifact.MediaType(), contextArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	generationSanitizer := testsupport.NewCleanGenerationSanitizer()
	request, receipt, err := generationSanitizer.SanitizeGeneration(context.Background(), rawGeneration, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	sanitizer := fixedVerificationSanitizer{request: request, receipt: receipt, expected: generationSanitizer.ExpectedBinaryDigests()}
	authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64)}
	dispatcher := &recordingDispatcher{adapterID: "test-verifier", result: gateway.RouteDispatchResult{}}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	handler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(220)}, sanitizer)
	if err != nil {
		t.Fatal(err)
	}
	completion := handler.Execute(context.Background(), verificationTaskRequest(t, scope, generationArtifact.Identity(), handler.HandlerIdentity()))
	if completion.Status() != controlplane.TaskCompletionFailed || authorizer.calls != 0 || dispatcher.calls != 0 {
		t.Fatalf("generation receipt reached verifier authority: completion=%#v calls=(%d,%d)", completion, authorizer.calls, dispatcher.calls)
	}
	events, err := ledger.Read(context.Background(), scope, 0, 20)
	if err != nil || len(events) != 4 {
		t.Fatalf("cross-wired receipt changed route ledger: events=%d err=%v", len(events), err)
	}
}

func TestVerificationResultSchemaClosesVersionedEgressFields(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "artifact", "model-verification-result-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			SchemaVersion struct {
				Enum []int `json:"enum"`
			} `json:"schema_version"`
		} `json:"properties"`
		AllOf []struct {
			Then struct {
				Required []string `json:"required"`
			} `json:"then"`
			Else struct {
				Not struct {
					AnyOf []struct {
						Required []string `json:"required"`
					} `json:"anyOf"`
				} `json:"not"`
			} `json:"else"`
		} `json:"allOf"`
	}
	if json.Unmarshal(encoded, &schema) != nil || len(schema.Properties.SchemaVersion.Enum) != 2 || len(schema.AllOf) != 1 || len(schema.AllOf[0].Then.Required) != 8 || len(schema.AllOf[0].Else.Not.AnyOf) != 8 {
		t.Fatal("verification result schema does not close v1 and v2 egress fields")
	}
	for index, field := range schema.AllOf[0].Then.Required {
		if len(schema.AllOf[0].Else.Not.AnyOf[index].Required) != 1 || schema.AllOf[0].Else.Not.AnyOf[index].Required[0] != field {
			t.Fatal("v1 schema accepts a v2 egress field")
		}
	}
}

func TestVerificationEgressArtifactsRejectSameScopeCrossGenerationRequest(t *testing.T) {
	_, _, _, contextArtifact, inputArtifact, generationArtifact, generation := completedGenerationFixture(t)
	raw := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	rawRequest, err := raw.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	crossedPayload := bytes.Replace(rawRequest.Payload(), []byte(generation.Candidates().Identity()), []byte(strings.Repeat("d", 64)), 1)
	if bytes.Equal(crossedPayload, rawRequest.Payload()) {
		t.Fatal("candidate batch identity was not present")
	}
	crossed, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", crossedPayload)
	if err != nil || review.ValidateVerificationModelRequest(crossed, generationArtifact.Scope().Identity()) != nil {
		t.Fatal("same-scope cross-generation fixture is not a valid verifier request")
	}
	sanitizer := testsupport.NewCleanVerificationSanitizer()
	request, receipt, err := sanitizer.SanitizeVerification(context.Background(), crossed, generationArtifact.Scope().Identity())
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, receiptArtifact, err := review.NewSanitizedVerificationEgressArtifacts(crossed, generation.ContextIdentity(), generation.Candidates().Identity(), generationArtifact, inputArtifact, contextArtifact, request, receipt, sanitizer.ExpectedBinaryDigests(), time.UnixMilli(220))
	if err == nil || requestArtifact.Identity() != "" || receiptArtifact.Identity() != "" {
		t.Fatal("same-scope verifier request was rebound to another generation")
	}
}

func TestInvestigationSelectedRemoteVerifierStopsBeforeClaimCostOrDispatch(t *testing.T) {
	scope, _, ledger, contextArtifact, inputArtifact, _, generation := completedGenerationFixture(t)
	verificationContext := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	raw, err := verificationContext.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	sanitized, _, err := testsupport.NewCleanVerificationSanitizer().SanitizeVerification(context.Background(), raw, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	request, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	route, observation := verifierObservedRoute(t)
	snapshot, err := NewVerificationRouteSnapshot(1, 1, []gateway.ObservedRouteCandidate{route}, []provider.RoutePerformanceObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	inventory := &modelRouteInventory{identity: strings.Repeat("a", 64), snapshot: snapshot}
	requirements, _ := provider.NewModelRequirements(1, 1, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZonePrivateRemote)
	constraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	budget, _ := provider.NewModelCostBudget(1, 100, 0)
	ranking, _ := gateway.NewRouteRankingPolicy(nil)
	independence, _ := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	authorizer, err := NewPolicyVerificationAuthorizer(inventory, requirements, constraints, budget, ranking, independence, ledger, fixedClock{at: time.UnixMilli(210)})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorizer.Authorize(context.Background(), scope, request, generation.RouteExecution())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &recordingDispatcher{adapterID: "test-verifier"}
	if localInvestigationVerificationAuthorization(authority.Authorization()) || dispatcher.calls != 0 {
		t.Fatal("selected remote verifier passed the pre-claim local recheck")
	}
	events, err := ledger.Read(context.Background(), scope, 0, 20)
	if err != nil || len(events) != 5 || events[4].Kind() != audit.EventRouteSelected {
		t.Fatalf("selected remote verifier created claim, cost, or dispatch evidence: events=%#v err=%v", events, err)
	}
}
