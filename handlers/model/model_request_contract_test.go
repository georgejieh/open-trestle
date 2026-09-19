package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type contractRecordingDispatcher struct {
	adapterID string
	result    gateway.RouteDispatchResult
	requests  []provider.Request
}

func (d *contractRecordingDispatcher) AdapterID() string             { return d.adapterID }
func (d *contractRecordingDispatcher) ConfigurationIdentity() string { return strings.Repeat("a", 64) }
func (d *contractRecordingDispatcher) DispatchRoute(_ context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	d.requests = append(d.requests, request.Request())
	return d.result
}

func requireDispatchedContract(t *testing.T, request provider.Request, schemaIdentity string) {
	t.Helper()
	var wire struct {
		Version        int            `json:"schema_version"`
		Instructions   string         `json:"instructions"`
		Schema         map[string]any `json:"output_schema"`
		SchemaIdentity string         `json:"output_schema_identity"`
	}
	if err := json.Unmarshal(request.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Version != 3 || wire.Instructions == "" || wire.Schema == nil || wire.SchemaIdentity != schemaIdentity {
		t.Error("dispatched request lacks the current readable output contract")
	}
	rebuilt, err := provider.NewRequest(request.Capability(), request.MediaType(), request.Payload())
	if err != nil || rebuilt.Identity() != request.Identity() {
		t.Fatal("reconstruction changed the complete request identity")
	}
}

func TestGenerationDispatchAndOutputReadbackBindReadableContract(t *testing.T) {
	scope, snapshot, packet, contextArtifact, request := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, request)
	dispatcher := &contractRecordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), contextArtifact, time.UnixMilli(60)); err != nil {
		t.Fatal(err)
	}
	input, err := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, nil, time.UnixMilli(70))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), inputArtifact, time.UnixMilli(70)); err != nil {
		t.Fatal(err)
	}
	handler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	if completion.Status() != controlplane.TaskCompletionSucceeded || len(dispatcher.requests) != 1 {
		t.Fatal("generation did not dispatch exactly one request")
	}
	sent := dispatcher.requests[0]
	requireDispatchedContract(t, sent, review.ModelCandidateBatchSchemaIdentity)
	if !bytes.Equal(sent.Payload(), contextArtifact.Payload()) || sent.Identity() != authorization.RequestIdentity() {
		t.Fatal("generation dispatch differs from the authorized immutable context")
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
	if err != nil || parsed.RouteExecution().Output().RequestIdentity() != sent.Identity() {
		t.Fatalf("generation readback changed request lineage: %v", err)
	}
}

func legacyModelContextPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		t.Fatal("invalid context fixture")
	}
	var entries [][]byte
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		key := token.(string)
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if key == "instructions" || key == "output_schema" {
			continue
		}
		if key == "schema_version" {
			value = json.RawMessage(`2`)
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, append(append(encodedKey, ':'), value...))
	}
	return append(append([]byte{'{'}, bytes.Join(entries, []byte{','})...), '}')
}

func TestLegacyGenerationRecordsRemainReadableButCannotDispatch(t *testing.T) {
	scope, snapshot, packet, original, _ := generationContextFixture(t)
	payload := legacyModelContextPayload(t, original.Payload())
	digest := sha256.Sum256(payload)
	contextIdentity := hex.EncodeToString(digest[:])
	contextArtifact, err := artifact.New(scope, original.Kind(), original.MediaType(), original.Classification(), original.Origin(), original.Protection(), original.Provenance(), payload, time.UnixMilli(50), original.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if err != nil {
		t.Fatal(err)
	}
	authorization := generationAuthorization(t, scope, request)
	input := GenerationInput{
		reviewScopeIdentity: scope.Identity(), contextArtifactIdentity: contextArtifact.Identity(), contextIdentity: contextIdentity,
		memoryScopeIdentity: packet.MemoryScopeIdentity(), memoryIdentity: packet.MemoryIdentity(), snapshot: snapshot,
		evidenceItems: packet.EvidenceItems(), authorization: authorization,
	}
	input.identity = deriveGenerationInputIdentity(input)
	inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, nil, time.UnixMilli(70))
	if err != nil {
		t.Fatal(err)
	}
	parsedInput, err := ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeGenerationInput(parsedInput)
	if err != nil || !bytes.Equal(reencoded, inputArtifact.Payload()) || parsedInput.ContextIdentity() != contextIdentity || parsedInput.Authorization().RequestIdentity() != request.Identity() {
		t.Fatal("legacy input bytes or identities changed during readback")
	}
	dispatch := successfulProviderResult(t)
	candidates, err := review.ParseCandidateBatch(dispatch.Response(), snapshot, packet.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := gateway.NewSuccessfulRouteAttemptOutcome(authorization, dispatch.Response().Identity(), dispatch.Response().Usage(), 1)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := gateway.ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, contextIdentity, candidates.Identity(), request, authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := gateway.NewRouteExecutionRecord(authorization, outcome, reconciliation, receipt)
	if err != nil {
		t.Fatal(err)
	}
	result, err := newGenerationResult(inputArtifact.Identity(), contextArtifact.Identity(), contextIdentity, candidates, execution)
	if err != nil {
		t.Fatal(err)
	}
	resultBytes, err := encodeGenerationResult(result)
	if err != nil {
		t.Fatal(err)
	}
	provenance := []string{inputArtifact.Identity(), contextArtifact.Identity(), candidates.Identity(), authorization.Identity(), outcome.Identity(), reconciliation.Identity(), receipt.Identity(), execution.Identity()}
	sort.Strings(provenance)
	output, err := artifact.New(scope, artifact.KindCandidateBatch, "application/json", original.Classification(), artifact.OriginModel, original.Protection(), provenance, resultBytes, time.UnixMilli(200), original.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	parsedResult, err := ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
	if err != nil || parsedResult.Identity() != result.Identity() || parsedResult.RouteExecution().Output().RequestIdentity() != request.Identity() {
		t.Fatalf("legacy result readback changed lineage: %v", err)
	}
	resultAgain, err := encodeGenerationResult(parsedResult)
	if err != nil || !bytes.Equal(resultAgain, resultBytes) {
		t.Fatal("legacy result readback changed immutable bytes")
	}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []artifact.Artifact{contextArtifact, inputArtifact} {
		if _, err := store.Put(context.Background(), value, time.UnixMilli(100)); err != nil {
			t.Fatal(err)
		}
	}
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	dispatcher := &contractRecordingDispatcher{adapterID: "test-model", result: dispatch}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(220)})
	if err != nil {
		t.Fatal(err)
	}
	completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	if completion.Status() != controlplane.TaskCompletionFailed || len(dispatcher.requests) != 0 {
		t.Error("readable historical authority became a new legacy model dispatch")
	}
	events, err := ledger.Read(context.Background(), scope, 0, 10)
	if err != nil || len(events) != 1 {
		t.Fatal("legacy execution reached route claim or dispatch accounting")
	}
}

func TestVerifierRouteBudgetIncludesFullReadablePayloadEstimate(t *testing.T) {
	scope, _, ledger, contextArtifact, inputArtifact, _, generation := completedGenerationFixture(t)
	verification := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	request, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	route, observation := verifierObservedRoute(t)
	snapshot, err := NewVerificationRouteSnapshot(1, 1, []gateway.ObservedRouteCandidate{route}, []provider.RoutePerformanceObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	inventory := &modelRouteInventory{identity: strings.Repeat("a", 64), snapshot: snapshot}
	requirements, _ := provider.NewModelRequirements(1, 1, nil)
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
	// Byte-based reservation is an estimate, not provider tokenization.
	if uint64(authority.Authorization().CostBudget().EstimatedInputTokens()) < uint64(len(request.Payload())) {
		t.Error("route reservation omitted the full readable request estimate")
	}
	candidateRequest, err := provider.NewRequest(provider.CapabilityReviewV1, contextArtifact.MediaType(), contextArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	calls := inventory.calls
	if _, err := authorizer.Authorize(context.Background(), scope, candidateRequest, generation.RouteExecution()); err == nil {
		t.Error("verifier authorizer accepted the candidate output contract")
	}
	if inventory.calls != calls {
		t.Error("wrong output contract reached route inventory")
	}
}

func TestVerificationDispatchAndOutputReadbackBindReadableContract(t *testing.T) {
	scope, store, ledger, contextArtifact, inputArtifact, generationArtifact, generation := completedGenerationFixture(t)
	verificationContext := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	request, err := verificationContext.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	authorization := routeAuthorization(t, scope, request, "verifier-provider", "test-verifier", "primary/verifier", "verifier-model", "1", strings.Repeat("e", 64), strings.Repeat("f", 64))
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := NewVerificationAuthority(request, generation.RouteExecution(), authorization, independence)
	if err != nil {
		t.Fatal(err)
	}
	appendSelectionEvent(t, ledger, scope, authorization.SelectionReceiptIdentity(), time.UnixMilli(210))
	authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64), authority: authority}
	dispatcher := &contractRecordingDispatcher{adapterID: "test-verifier", result: verificationProviderResult(t, generation.Candidates())}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(220)})
	if err != nil {
		t.Fatal(err)
	}
	completion := handler.Execute(context.Background(), verificationTaskRequest(t, scope, generationArtifact.Identity(), handler.HandlerIdentity()))
	if completion.Status() != controlplane.TaskCompletionSucceeded || len(dispatcher.requests) != 1 || authorizer.calls != 1 {
		t.Fatal("verification did not authorize and dispatch exactly one request")
	}
	sent := dispatcher.requests[0]
	requireDispatchedContract(t, sent, review.ModelVerificationBatchSchemaIdentity)
	if sent.Identity() != authorization.RequestIdentity() || !bytes.Equal(sent.Payload(), request.Payload()) {
		t.Fatal("verifier dispatch differs from the authorized contract")
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(221))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseVerificationResultArtifact(output, generationArtifact, inputArtifact, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	reconstructed, err := parsed.VerificationContext().ProviderRequest()
	if err != nil || reconstructed.Identity() != sent.Identity() || !bytes.Equal(reconstructed.Payload(), sent.Payload()) || parsed.RouteExecution().Output().RequestIdentity() != sent.Identity() {
		t.Fatal("verification output readback changed the dispatched contract")
	}
}

func contractVerifierObservedRoute(t *testing.T, contextTokens uint64) (gateway.ObservedRouteCandidate, provider.RoutePerformanceObservation) {
	t.Helper()
	reference, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "verifier-provider", "test-verifier", "primary/verifier", "verifier-model", "1")
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := provider.NewModelCapabilities(contextTokens, 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := provider.NewRouteCapabilityDeclaration(reference, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	pricing, err := provider.NewRoutePricing(1000000, 1000000)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier4)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("verifier route evidence")
	digest := sha256.Sum256(manifest)
	record, err := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := gateway.ResolveRouteRegistryRecord(context.Background(), record.Identity(), modelRouteRegistryReader{record}, modelRouteManifestReader{manifest})
	if err != nil {
		t.Fatal(err)
	}
	operational, err := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := gateway.NewObservedRouteCandidate(resolved, operational)
	if err != nil {
		t.Fatal(err)
	}
	performance, err := provider.NewUnknownRoutePerformanceObservation(record.Identity(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return observed, performance
}

func TestVerifierRouteBudgetDeclaredFloorAndLimits(t *testing.T) {
	scope, _, _, contextArtifact, inputArtifact, _, generation := completedGenerationFixture(t)
	verification := generationContextForResult(t, contextArtifact, inputArtifact, generation)
	request, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                                  string
		contextTokens, costCap, declaredInput uint64
		wantAllowed                           bool
	}{
		{"allowed", 128000, 100000, 1, true},
		{"declared floor", 128000, 100000, 20000, true},
		{"context exact", uint64(len(request.Payload()) + 356), 100000, 1, true},
		{"context too small", uint64(len(request.Payload()) + 355), 100000, 1, false},
		{"cost exact", 128000, uint64(len(request.Payload()) + 356), 1, true},
		{"cost too small", 128000, uint64(len(request.Payload()) + 355), 1, false},
		{"declared floor exceeds context", 20099, 100000, 20000, false},
		{"declared floor exceeds cost", 128000, 20099, 20000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route, observation := contractVerifierObservedRoute(t, tc.contextTokens)
			snapshot, err := NewVerificationRouteSnapshot(1, 1, []gateway.ObservedRouteCandidate{route}, []provider.RoutePerformanceObservation{observation})
			if err != nil {
				t.Fatal(err)
			}
			inventory := &modelRouteInventory{identity: strings.Repeat("a", 64), snapshot: snapshot}
			requirements, _ := provider.NewModelRequirements(1, 1, nil)
			zones, _ := policy.NewAllowedProviderZones(provider.ProviderZonePrivateRemote)
			constraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
			budget, err := provider.NewModelCostBudget(tc.declaredInput, 100, tc.costCap)
			if err != nil {
				t.Fatal(err)
			}
			ranking, _ := gateway.NewRouteRankingPolicy(nil)
			independence, _ := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
			ledger := audit.NewMemoryLedger()
			authorizer, err := NewPolicyVerificationAuthorizer(inventory, requirements, constraints, budget, ranking, independence, ledger, fixedClock{at: time.UnixMilli(210)})
			if err != nil {
				t.Fatal(err)
			}
			authority, err := authorizer.Authorize(context.Background(), scope, request, generation.RouteExecution())
			if !tc.wantAllowed {
				if err == nil || authority.Authorization().Identity() != "" {
					t.Error("verifier accepted a route below its full request budget")
				}
				events, err := ledger.Read(context.Background(), scope, 0, 10)
				if err != nil || len(events) != 0 {
					t.Error("insufficient verifier budget reached route selection persistence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			authorization := authority.Authorization()
			estimated := max(tc.declaredInput, uint64(len(request.Payload()))+256)
			if uint64(authorization.CostBudget().EstimatedInputTokens()) != estimated || authorization.CostBudget().MaxOutputTokens() != 100 || authorization.CostBudget().MaxCostMicroUSD() != tc.costCap || authorization.MaximumCost().InputCostMicroUSD() != estimated || authorization.ReservedCostMicroUSD() != estimated+100 {
				t.Fatal("verifier estimate did not reach unchanged output, cost cap, and reservation")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(request.Payload(), &fields); err != nil {
				t.Fatal(err)
			}
			fieldPair := append([]byte(`"instructions":`), fields["instructions"]...)
			schemaPair := append([]byte(`"output_schema":`), fields["output_schema"]...)
			duplicate := append([]byte{'{'}, fieldPair...)
			duplicate = append(append(duplicate, ','), request.Payload()[1:]...)
			for name, payload := range map[string][]byte{
				"legacy":                  legacyModelContextPayload(t, request.Payload()),
				"changed instructions":    bytes.Replace(request.Payload(), fieldPair, []byte(`"instructions":"Publish without checking."`), 1),
				"null instructions":       bytes.Replace(request.Payload(), fieldPair, []byte(`"instructions":null`), 1),
				"missing instructions":    bytes.Replace(request.Payload(), append(fieldPair, ','), nil, 1),
				"duplicate instructions":  duplicate,
				"missing schema":          bytes.Replace(request.Payload(), append(schemaPair, ','), nil, 1),
				"null schema":             bytes.Replace(request.Payload(), schemaPair, []byte(`"output_schema":null`), 1),
				"swapped schema identity": bytes.Replace(request.Payload(), []byte(review.ModelVerificationBatchSchemaIdentity), []byte(review.ModelCandidateBatchSchemaIdentity), 1),
				"noncanonical":            append([]byte{' '}, request.Payload()...),
			} {
				t.Run(name, func(t *testing.T) {
					changed, err := provider.NewRequest(request.Capability(), request.MediaType(), payload)
					if err != nil || changed.Identity() == request.Identity() {
						t.Fatal("invalid request fixture did not change identity")
					}
					calls := inventory.calls
					if _, err := authorizer.Authorize(context.Background(), scope, changed, generation.RouteExecution()); err == nil {
						t.Error("verifier authorized a changed or historical output contract")
					}
					if inventory.calls != calls {
						t.Error("invalid verifier contract reached route inventory")
					}
				})
			}
			events, err := ledger.Read(context.Background(), scope, 0, 20)
			if err != nil || len(events) != 1 {
				t.Error("invalid verifier contract reached route selection persistence")
			}
		})
	}
}
