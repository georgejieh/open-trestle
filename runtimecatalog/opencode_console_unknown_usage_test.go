package runtimecatalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

type consoleUnknownUsageTransport struct {
	delegate *consoleCallerTransport
}

func (r consoleUnknownUsageTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.delegate.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var wire map[string]json.RawMessage
	requiredCheck(r.delegate.t, json.NewDecoder(response.Body).Decode(&wire))
	if _, present := wire["usage"]; !present {
		r.delegate.t.Fatal("delegate fixture lost known usage")
	}
	delete(wire, "usage")
	body, err := json.Marshal(wire)
	requiredCheck(r.delegate.t, err)
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

func TestCommonRuntimePolicyCatalogOpenCodeConsoleUnknownUsageRetainsReservation(t *testing.T) {
	ctx := context.Background()
	clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 1, 0, time.UTC)}
	configuration, inventory := consoleCallerRuntimePolicy(t)
	key, err := openai.NewAPIKey([]byte("synthetic-console-key"))
	requiredCheck(t, err)
	credentials := &brokeredCountingCredentials{key: key}
	transport := &consoleCallerTransport{t: t}
	catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, brokeredResolver{credentials}, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Transport: consoleUnknownUsageTransport{delegate: transport}, Timeout: 2 * time.Minute}, HTTPClientIdentity: requiredDigest("console-unknown-usage-http")})
	requiredCheck(t, err)
	memoryStore, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	requiredCheck(t, err)
	store := consoleCallerStore{Store: memoryStore, t: t}
	ledger := audit.NewMemoryLedger()
	transport.ledger = ledger
	sanitizer := testsupport.NewCleanGenerationSanitizer()
	handler, err := modelhandler.NewGenerationHandler(store, catalog, ledger, clock, sanitizer.ExpectedBinaryDigests())
	requiredCheck(t, err)
	scope, err := audit.NewReviewScope("tenant-a", "repository-a", "console-unknown-usage")
	requiredCheck(t, err)
	request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
	dependency, ok := request.DependencyOutput("context")
	if !ok || !dependency.Available() {
		t.Fatal("generation task lost actual input dependency")
	}
	inputArtifact, err := store.Get(ctx, scope, dependency.OutputIdentity(), clock.Now())
	requiredCheck(t, err)
	input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	requiredCheck(t, err)
	authorization := input.Authorization()
	if authorization.Validate() != nil || authorization.ReservedCostMicroUSD() == 0 || authorization.RemainingCostBeforeMicroUSD() <= authorization.RemainingCostAfterMicroUSD() || authorization.RemainingCostBeforeMicroUSD()-authorization.RemainingCostAfterMicroUSD() != authorization.ReservedCostMicroUSD() {
		t.Fatal("unknown-usage oracle did not reserve a nonzero budget")
	}
	transport.scope, transport.authorization = scope, authorization
	completion := handler.Execute(ctx, request)
	if completion.Validate() != nil || completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("Console unknown-usage generation failed: %#v", completion)
	}
	output, err := store.Get(ctx, scope, completion.OutputIdentity(), clock.Now())
	requiredCheck(t, err)
	contextArtifact, err := store.Get(ctx, scope, input.ContextArtifactIdentity(), clock.Now())
	requiredCheck(t, err)
	result, err := modelhandler.ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
	requiredCheck(t, err)
	if result.Validate() != nil || len(result.Candidates().Findings()) != 0 {
		t.Fatal("unknown-usage caller did not admit typed empty candidates")
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(consoleCallerCandidateContent))
	requiredCheck(t, err)
	expectedResponse, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	requiredCheck(t, err)
	execution := result.RouteExecution()
	outcome := execution.Outcome()
	reconciliation := execution.Reconciliation()
	if execution.Validate() != nil || execution.Authorization().Identity() != authorization.Identity() || outcome.Validate() != nil || outcome.AuthorizationIdentity() != authorization.Identity() || outcome.ResponseIdentity() != expectedResponse.Identity() || result.Candidates().ResponseIdentity() != expectedResponse.Identity() {
		t.Fatal("unknown-usage actual execution/candidate response lineage changed")
	}
	if outcome.Usage().Validate() != nil || outcome.Usage().IsKnown() {
		t.Fatal("absent whole usage became known or free")
	}
	if reconciliation.Validate() != nil || reconciliation.Status() != gateway.RouteCostUsageUnknown || reconciliation.ActualCost().IsKnown() || reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() || reconciliation.ReservedCostMicroUSD() != authorization.ReservedCostMicroUSD() || reconciliation.RemainingAfterReservationMicroUSD() != authorization.RemainingCostAfterMicroUSD() || reconciliation.RemainingCostMicroUSD() != reconciliation.RemainingAfterReservationMicroUSD() || reconciliation.BudgetOverrunMicroUSD() != 0 {
		t.Fatal("unknown usage refunded reservation or invented actual cost")
	}
	if bytes.Contains(output.Payload(), []byte(consoleCallerReasoningSentinel)) {
		t.Fatal("reasoning persisted in unknown-usage result")
	}
	events, err := ledger.Read(ctx, scope, 0, 20)
	requiredCheck(t, err)
	if len(events) != 4 {
		t.Fatal("unknown usage added a hidden retry/fallback or lost audit events")
	}
	for index, kind := range []audit.EventKind{audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled} {
		event := events[index]
		if event.Validate() != nil || event.Kind() != kind {
			t.Fatal("unknown-usage audit lineage missing")
		}
		encoded, err := audit.EncodeEvent(event)
		requiredCheck(t, err)
		if bytes.Contains(encoded, []byte(consoleCallerReasoningSentinel)) {
			t.Fatal("reasoning persisted in unknown-usage audit")
		}
	}
	if events[1].SubjectIdentity() != authorization.Identity() || events[2].SubjectIdentity() != outcome.Identity() || events[3].SubjectIdentity() != reconciliation.Identity() {
		t.Fatal("unknown-usage audit subjects not linked to actual execution")
	}
	if transport.calls != 1 || credentials.calls != 1 {
		t.Fatal("unknown-usage oracle did not execute exactly one authorized attempt")
	}
}
