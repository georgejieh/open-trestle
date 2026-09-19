package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func artifactsCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func artifactsHash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func artifactsJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	artifactsCheck(t, err)
	return b
}
func artifactsID(s string) string { return artifactsHash([]byte(s)) }
func artifactsKind(t *testing.T, token string) artifact.Kind {
	t.Helper()
	for n := 1; n <= 255; n++ {
		kind := artifact.Kind(n)
		if kind.String() == token {
			return kind
		}
	}
	t.Fatalf("existing artifact token API refuses %q; token implementation remains a separate prerequisite", token)
	return 0
}

type artifactsSource struct {
	id     evidence.SourceAdapterIdentity
	result scm.SourceAdapterResult
	calls  int
}

func (s *artifactsSource) Identity() evidence.SourceAdapterIdentity { return s.id }
func (s *artifactsSource) Acquire(ctx context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.calls++
	return s.result
}

type artifactsRegistry struct{ record provider.RouteRegistryRecord }

func (r artifactsRegistry) LookupRouteRegistryRecord(ctx context.Context, id string) (provider.RouteRegistryRecord, error) {
	return r.record, nil
}

type artifactsManifest []byte

func (m artifactsManifest) OpenRouteEvidenceManifest(ctx context.Context, id string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m)), nil
}

type artifactsModel struct {
	t        *testing.T
	scope    audit.ReviewScope
	ledger   audit.Ledger
	adapter  string
	foreign  bool
	calls    []gateway.RouteDispatchRequest
	response provider.Response
}

func (m *artifactsModel) AdapterID() string             { return m.adapter }
func (m *artifactsModel) ConfigurationIdentity() string { return artifactsID(m.adapter) }
func (m *artifactsModel) DispatchRoute(ctx context.Context, r gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	artifactsCheck(m.t, r.Validate())
	events, err := m.ledger.Read(ctx, m.scope, 0, 100)
	artifactsCheck(m.t, err)
	claimed := false
	for _, e := range events {
		if e.Kind() == audit.EventRouteAttemptClaimed && e.SubjectIdentity() == r.Authorization().Identity() {
			claimed = true
		}
	}
	if !claimed {
		m.t.Fatal("external model preceded actual route claim")
	}
	m.calls = append(m.calls, r)
	var packet struct {
		Sources []struct {
			ID    string `json:"source_id"`
			Start int    `json:"start_line"`
		} `json:"sources"`
	}
	artifactsCheck(m.t, json.Unmarshal(r.Request().Payload(), &packet))
	if len(packet.Sources) == 0 {
		m.t.Fatal("actual request lacked evidence")
	}
	id := packet.Sources[0].ID
	if m.foreign {
		id = "foreign-source"
	}
	line := packet.Sources[0].Start
	payload := artifactsJSON(m.t, map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Zero input divides by zero", "claim": "The supplied division does not guard zero input.", "severity_hint": "high", "source_range": map[string]any{"source_id": id, "start_line": line, "end_line": line}, "evidence_ids": []string{id}}}})
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", payload)
	artifactsCheck(m.t, err)
	usage, err := provider.NewRouteTokenUsage(100, 100, 0)
	artifactsCheck(m.t, err)
	m.response, err = provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	artifactsCheck(m.t, err)
	result, err := gateway.NewSuccessfulRouteDispatchResult(m.response)
	artifactsCheck(m.t, err)
	return result
}
func artifactsRoute(t *testing.T, name string) (gateway.ObservedRouteCandidate, provider.RoutePerformanceObservation, review.InvestigationRouteContextClaim) {
	t.Helper()
	ref, err := provider.NewRouteReference(provider.ProviderZoneLocal, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, "1")
	artifactsCheck(t, err)
	caps, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	artifactsCheck(t, err)
	declaration, err := provider.NewRouteCapabilityDeclaration(ref, caps)
	artifactsCheck(t, err)
	pricing, err := provider.NewRoutePricing(1000000, 1000000)
	artifactsCheck(t, err)
	candidate, err := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier3)
	artifactsCheck(t, err)
	manifest := artifactsManifest("fixture route manifest bytes")
	record, err := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, artifactsHash(manifest))
	artifactsCheck(t, err)
	resolved, err := gateway.ResolveRouteRegistryRecord(context.Background(), record.Identity(), artifactsRegistry{record}, manifest)
	artifactsCheck(t, err)
	operational, err := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	artifactsCheck(t, err)
	observed, err := gateway.NewObservedRouteCandidate(resolved, operational)
	artifactsCheck(t, err)
	performance, err := provider.NewKnownRoutePerformanceObservation(record.Identity(), 1, 10, 20)
	artifactsCheck(t, err)
	return observed, performance, review.InvestigationRouteContextClaim{Record: record, Operational: operational, ManifestSizeBytes: uint32(len(manifest))}
}

type artifactsFixture struct {
	context  InvestigationArtifactContext
	binding  review.InvestigationContextBinding
	expected InvestigationArtifactExpectations
	owner    *gateway.InvestigationRouteOwner
	options  gateway.InvestigationRouteOwnerOptions
	model    *artifactsModel
	store    artifact.Store
	ledger   audit.Ledger
	packet   review.ContextPacket
	clock    fixedClock
}

func artifactsOwnerID(o gateway.InvestigationRouteOwnerOptions) string {
	features := []string{}
	for _, f := range o.Requirements.RequiredFeatures() {
		features = append(features, f.String())
	}
	zones := []string{}
	for z := provider.ProviderZoneLocal; z <= provider.ProviderZoneSubscriptionOAuth; z++ {
		if o.Constraints.AllowedProviderZones().Allows(z) {
			zones = append(zones, z.String())
		}
	}
	b, _ := json.Marshal([]any{"open-trestle/investigation-route-owner", 1, o.Scope.Identity(), o.SessionIdentity, o.PolicyIdentity, o.Deadline.UnixMilli(), o.MaxTurns, 1, o.Budget.EstimatedInputTokens(), o.Budget.MaxOutputTokens(), o.Budget.MaxCostMicroUSD(), o.Requirements.MinContextTokens(), o.Requirements.MinOutputTokens(), features, string(o.Constraints.Classification()), zones, o.Constraints.ContentLoggingAllowed(), o.Generation.Identity(), o.Verification.Identity(), o.Catalog.Identity()})
	return artifactsHash(b)
}
func newArtifactsFixture(t *testing.T, runLabels ...string) artifactsFixture {
	t.Helper()
	ctx := context.Background()
	clock := fixedClock{at: time.UnixMilli(1000)}
	runLabel := "artifact-run"
	if len(runLabels) == 1 {
		runLabel = runLabels[0]
	}
	scope, err := audit.NewReviewScope("artifact-tenant", "artifact-repo", runLabel)
	artifactsCheck(t, err)
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	artifactsCheck(t, err)
	ledger := audit.NewMemoryLedger()
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "repo")
	artifactsCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	artifactsCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "artifact-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	artifactsCheck(t, err)
	content := []byte("package p\nfunc Changed(x int) int { return 10 / x }\n")
	file, err := evidence.NewRepositoryFile("a.go", content)
	artifactsCheck(t, err)
	manifest, err := evidence.NewRepositoryManifest([]evidence.RepositoryFile{file})
	artifactsCheck(t, err)
	external := &artifactsSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: map[string][]byte{"a.go": content}}}
	handler, err := source.NewHandler(store, external, clock)
	artifactsCheck(t, err)
	sourceInput, err := source.NewInput(repository, revision, adapter)
	artifactsCheck(t, err)
	inputArtifact, err := source.NewInputArtifact(scope, sourceInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{artifactsID("source-intent")}, time.UnixMilli(100), time.UnixMilli(100000))
	artifactsCheck(t, err)
	_, err = store.Put(ctx, inputArtifact, time.UnixMilli(100))
	artifactsCheck(t, err)
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputArtifact.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
	artifactsCheck(t, err)
	plan, err := controlplane.NewReviewRunPlan(scope, artifactsID("source-request"), artifactsID("review-policy"), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	artifactsCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	artifactsCheck(t, err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	artifactsCheck(t, err)
	_, err = coordinator.Advance(ctx, plan, time.UnixMilli(101))
	artifactsCheck(t, err)
	lease, _, err := coordinator.ClaimTask(ctx, plan, "source", handler.HandlerIdentity(), "fixture-worker", time.UnixMilli(102))
	artifactsCheck(t, err)
	execution, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	artifactsCheck(t, err)
	completion := handler.Execute(ctx, execution)
	if completion.Status() != controlplane.TaskCompletionSucceeded || external.calls != 1 {
		t.Fatal("source handler did not actually acquire evidence")
	}
	_, err = coordinator.CompleteTask(ctx, plan, lease, completion, clock.Now())
	artifactsCheck(t, err)
	headArtifact, err := store.Get(ctx, scope, completion.OutputIdentity(), clock.Now())
	artifactsCheck(t, err)
	head, err := source.ParseSnapshotArtifact(headArtifact)
	artifactsCheck(t, err)
	fileArtifact, err := store.Get(ctx, scope, head.Files()[0].ArtifactIdentity(), clock.Now())
	artifactsCheck(t, err)
	protectedFile, err := source.ParseFileArtifact(fileArtifact, head, head.Files()[0])
	artifactsCheck(t, err)
	span, err := evidence.NewSourceRange("a.go", 2, 2)
	artifactsCheck(t, err)
	snippet := []byte("func Changed(x int) int { return 10 / x }\n")
	binding, err := evidence.BindSourceSlice(file, protectedFile.Content(), span, snippet)
	artifactsCheck(t, err)
	item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), span)
	artifactsCheck(t, err)
	selected, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, snippet, binding)
	artifactsCheck(t, err)
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, []evidence.SourceRange{span})
	artifactsCheck(t, err)
	memScope, err := memory.NewScope(scope.TenantID(), scope.RepositoryID(), "reviewer", memory.RefVisibilityExact, artifactsID("review-policy"), []string{"."})
	artifactsCheck(t, err)
	query, err := memory.NewLexicalQuery(memScope, "a.go", nil, nil, clock.Now(), 1)
	artifactsCheck(t, err)
	retrieval, err := memory.NewLexicalIndex().Search(ctx, memScope, query)
	artifactsCheck(t, err)
	limits, err := review.NewContextLimits(65536, 0)
	artifactsCheck(t, err)
	packet, err := review.NewContextPacket(scope, memScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{selected}, retrieval, limits)
	artifactsCheck(t, err)
	policyBytes, err := os.ReadFile("../../internal/review/testdata/investigation-policy-v1.json")
	artifactsCheck(t, err)
	p, err := review.ParseInvestigationPolicy(policyBytes)
	artifactsCheck(t, err)
	g, gp, gc := artifactsRoute(t, "a")
	v, vp, vc := artifactsRoute(t, "b")
	gm := &artifactsModel{t: t, scope: scope, ledger: ledger, adapter: "adapter-a"}
	vm := &artifactsModel{t: t, scope: scope, ledger: ledger, adapter: "adapter-b"}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{gm, vm})
	artifactsCheck(t, err)
	requirements, err := provider.NewModelRequirements(1, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	artifactsCheck(t, err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	artifactsCheck(t, err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	artifactsCheck(t, err)
	budget, err := provider.NewModelCostBudget(1, 4096, 100000)
	artifactsCheck(t, err)
	pin, err := gateway.NewPinnedRouteRankingPolicy(g.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	artifactsCheck(t, err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	artifactsCheck(t, err)
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	artifactsCheck(t, err)
	contextBinding, err := review.NewInvestigationContextBinding(review.InvestigationContextBindingOptions{Scope: scope, HostSessionIdentity: artifactsID("host-session"), Policy: p, HeadSnapshotArtifactIdentity: headArtifact.Identity(), HeadSnapshotIdentity: head.Identity(), HeadManifestIdentity: head.ManifestIdentity(), HeadRevisionIdentity: head.RevisionIdentity(), InitialContext: packet, InitialSnapshot: snapshot, Deadline: time.UnixMilli(6000), Routing: review.InvestigationContextRouting{RegistryRevision: 1, PerformanceRevision: 1, Generation: gc, Verification: []review.InvestigationRouteContextClaim{vc}, Performance: []provider.RoutePerformanceObservation{gp, vp}, Requirements: requirements, Constraints: constraints, Budget: budget, VerificationRanking: ranking, Independence: independence, CatalogIdentity: catalog.Identity()}})
	artifactsCheck(t, err)
	contextValue, err := review.NewInvestigationGenerationContext(contextBinding, packet, snapshot, review.InvestigationContextState{Turn: 1, ScannedBytes: uint64(len(content))})
	artifactsCheck(t, err)
	request, err := contextValue.ProviderRequest()
	artifactsCheck(t, err)
	contextArtifact, err := artifact.New(scope, artifact.KindContextPacket, "application/json", headArtifact.Classification(), artifact.OriginHost, headArtifact.Protection(), []string{headArtifact.Identity(), contextBinding.Identity(), p.Identity()}, request.Payload(), clock.Now(), headArtifact.ExpiresAt())
	artifactsCheck(t, err)
	_, err = store.Put(ctx, contextArtifact, clock.Now())
	artifactsCheck(t, err)
	generationPlan, err := gateway.NewInvestigationRoutePlan(1, []gateway.ObservedRouteCandidate{g}, pin, 1, []provider.RoutePerformanceObservation{gp})
	artifactsCheck(t, err)
	verificationPlan, err := gateway.NewInvestigationRoutePlan(1, []gateway.ObservedRouteCandidate{v}, ranking, 1, []provider.RoutePerformanceObservation{vp})
	artifactsCheck(t, err)
	options := gateway.InvestigationRouteOwnerOptions{Scope: scope, SessionIdentity: contextBinding.Identity(), PolicyIdentity: p.Identity(), Deadline: time.UnixMilli(6000), MaxTurns: 5, Budget: budget, Requirements: requirements, Constraints: constraints, Generation: generationPlan, Verification: verificationPlan, Catalog: catalog, Ledger: ledger, Clock: clock}
	owner, err := gateway.NewInvestigationRouteOwner(options)
	artifactsCheck(t, err)
	expected := InvestigationArtifactExpectations{Scope: scope, SessionIdentity: contextBinding.Identity(), PolicyIdentity: p.Identity(), OwnerIdentity: artifactsOwnerID(options), HeadSnapshotArtifactIdentity: headArtifact.Identity(), HeadSnapshotIdentity: head.Identity(), HeadManifestIdentity: head.ManifestIdentity(), ContextArtifactIdentity: contextArtifact.Identity(), ToolResultArtifactIdentities: []string{}}
	return artifactsFixture{InvestigationArtifactContext{Context: contextValue, ContextArtifact: contextArtifact, HeadSnapshotArtifact: headArtifact, SourceFileArtifacts: []artifact.Artifact{fileArtifact}, ToolResultArtifacts: []artifact.Artifact{}}, contextBinding, expected, owner, options, gm, store, ledger, packet, clock}
}
func (f artifactsFixture) predicted(t *testing.T, request provider.Request) gateway.RouteAttemptAuthorization {
	t.Helper()
	encoded := request.Payload()
	budget, err := provider.NewModelCostBudget(max(uint64(f.options.Budget.EstimatedInputTokens()), uint64(len(encoded))+256), uint64(f.options.Budget.MaxOutputTokens()), f.options.Budget.MaxCostMicroUSD())
	artifactsCheck(t, err)
	input, err := gateway.NewReviewRoutingInput(f.options.Scope, request, f.options.Requirements, f.options.Constraints)
	artifactsCheck(t, err)
	route, performance, _ := artifactsRoute(t, "a")
	eligible, err := gateway.FilterEligibleRoutes(input, budget, 1, []gateway.ObservedRouteCandidate{route})
	artifactsCheck(t, err)
	pin, err := gateway.NewPinnedRouteRankingPolicy(route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	artifactsCheck(t, err)
	ranking, err := gateway.RankEligibleRoutes(eligible, pin, 1, []provider.RoutePerformanceObservation{performance})
	artifactsCheck(t, err)
	selection, err := gateway.NewRouteSelectionReceipt(eligible, ranking)
	artifactsCheck(t, err)
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	artifactsCheck(t, err)
	return authorization
}
func (f artifactsFixture) ownedTurn(t *testing.T) (artifact.Artifact, artifact.Artifact, InvestigationArtifactExpectations, gateway.InvestigationTurnRecord) {
	t.Helper()
	expected := f.expected
	request, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	predicted := f.predicted(t, request)
	events, err := f.ledger.Read(context.Background(), f.expected.Scope, 0, 100)
	artifactsCheck(t, err)
	if len(events) != 0 {
		t.Fatal("pure prediction fabricated route events")
	}
	input, err := NewInvestigationGenerationInputArtifact(f.context, predicted, expected, f.clock.Now())
	artifactsCheck(t, err)
	expected.InputArtifactIdentity = input.Identity()
	_, err = f.store.Put(context.Background(), input, f.clock.Now())
	artifactsCheck(t, err)
	turn, err := f.owner.Dispatch(context.Background(), gateway.InvestigationGenerationTurn, request)
	artifactsCheck(t, err)
	if turn.Authorization().Identity() != predicted.Identity() || len(f.model.calls) != 1 {
		t.Fatal("actual owned authorization differs from unclaimed input")
	}
	turnBytes, err := gateway.EncodeInvestigationTurnRecord(turn)
	artifactsCheck(t, err)
	parsed, err := gateway.ParseInvestigationTurnRecord(turnBytes)
	artifactsCheck(t, err)
	again, err := gateway.EncodeInvestigationTurnRecord(parsed)
	artifactsCheck(t, err)
	if !bytes.Equal(turnBytes, again) {
		t.Fatal("actual full turn codec did not roundtrip")
	}
	turnArtifact, err := artifact.New(expected.Scope, artifactsKind(t, "investigation_turn"), "application/json", f.context.ContextArtifact.Classification(), artifact.OriginHost, f.context.ContextArtifact.Protection(), []string{f.context.ContextArtifact.Identity(), input.Identity(), expected.HeadSnapshotArtifactIdentity, turn.Identity(), turn.Authorization().Identity(), turn.Outcome().Identity(), turn.Reconciliation().Identity(), expected.OwnerIdentity}, turnBytes, f.clock.Now(), f.context.ContextArtifact.ExpiresAt())
	artifactsCheck(t, err)
	expected.TurnArtifactIdentity = turnArtifact.Identity()
	_, err = f.store.Put(context.Background(), turnArtifact, f.clock.Now())
	artifactsCheck(t, err)
	return input, turnArtifact, expected, turn
}
func (f artifactsFixture) complete(t *testing.T) (artifact.Artifact, artifact.Artifact, artifact.Artifact, InvestigationArtifactExpectations, gateway.InvestigationTurnRecord) {
	t.Helper()
	input, turnArtifact, expected, turn := f.ownedTurn(t)
	result, err := NewInvestigationGenerationResultArtifact(input, f.context, turnArtifact, expected, f.clock.Now())
	artifactsCheck(t, err)
	expected.ResultArtifactIdentity = result.Identity()
	_, err = f.store.Put(context.Background(), result, f.clock.Now())
	artifactsCheck(t, err)
	return input, turnArtifact, result, expected, turn
}
func TestInvestigationArtifactsCompleteProtectedActualTurnReadback(t *testing.T) {
	f := newArtifactsFixture(t)
	input, turn, result, expected, owned := f.complete(t)
	inputExpected := expected
	inputExpected.TurnArtifactIdentity = ""
	inputExpected.ResultArtifactIdentity = ""
	decodedInput, err := ParseInvestigationGenerationInputArtifact(input, f.context, inputExpected, f.clock.Now())
	artifactsCheck(t, err)
	decoded, err := ParseInvestigationGenerationResultArtifact(result, input, f.context, turn, expected, f.clock.Now())
	artifactsCheck(t, err)
	resultBytes, err := EncodeInvestigationGenerationResult(decoded)
	artifactsCheck(t, err)
	if !bytes.Equal(resultBytes, result.Payload()) {
		t.Fatal("complete v2 result canonical re-encoding changed bytes")
	}
	for _, value := range []artifact.Artifact{f.context.ContextArtifact, input, turn, result} {
		encoded, err := artifact.Encode(value)
		artifactsCheck(t, err)
		parsed, err := artifact.Parse(encoded)
		artifactsCheck(t, err)
		again, err := artifact.Encode(parsed)
		artifactsCheck(t, err)
		if !bytes.Equal(encoded, again) {
			t.Fatal("full protected envelope failed canonical roundtrip")
		}
	}

	if decodedInput.Authorization().Identity() != owned.Authorization().Identity() || decoded.ContextIdentity() != f.context.Context.Identity() || decoded.Turn().Identity() != owned.Identity() || decoded.RouteExecution().Authorization().Identity() != owned.Authorization().Identity() || len(decoded.Candidates().Findings()) != 1 || decoded.Candidates().ResponseIdentity() != owned.Dispatch().Response().Identity() {
		t.Fatal("v2 readback lost actual context/input/model/evidence lineage")
	}
	if _, err := ParseGenerationInput(input.Payload()); err == nil {
		t.Fatal("old v1 input parser silently admitted v2")
	}
	if _, err := ParseGenerationResultArtifact(result, input, f.context.ContextArtifact); err == nil {
		t.Fatal("old v1 result parser silently admitted v2")
	}
	if review.ValidateCandidateModelRequest(f.model.calls[0].Request(), expected.Scope.Identity()) == nil {
		t.Fatal("default v3 execution gate admitted v4")
	}
	if _, err := ParseInvestigationGenerationResultArtifact(result, input, InvestigationArtifactContext{}, turn, expected, f.clock.Now()); err == nil {
		t.Fatal("unavailable live typed witness downgraded to digest-only readback")
	}
}

func artifactsRewrite(t *testing.T, value artifact.Artifact, scope audit.ReviewScope, origin artifact.Origin, protection artifact.Protection, payload []byte, provenance []string) artifact.Artifact {
	t.Helper()
	rewritten, err := artifact.New(scope, value.Kind(), value.MediaType(), value.Classification(), origin, protection, provenance, payload, value.CreatedAt(), value.ExpiresAt())
	artifactsCheck(t, err)
	return rewritten
}
func TestInvestigationArtifactCustodyRefusesCrossWiredAndMissingValues(t *testing.T) {
	f := newArtifactsFixture(t)
	input, turn, result, expected, _ := f.complete(t)
	for _, mode := range []string{"missing turn", "missing context", "missing source", "changed source", "missing typed witness", "wrong origin", "wrong classification", "wrong protection", "wrong scope", "truncated turn", "changed context", "duplicate source", "expected owner", "expected session", "expected policy", "expected predecessor", "expected head", "unexpected tool"} {
		t.Run(mode, func(t *testing.T) {
			bundle := f.context
			bundle.SourceFileArtifacts = append([]artifact.Artifact(nil), bundle.SourceFileArtifacts...)
			witness := turn
			want := expected
			switch mode {
			case "missing turn":
				witness = artifact.Artifact{}
			case "missing context":
				bundle.ContextArtifact = artifact.Artifact{}
			case "missing source":
				bundle.SourceFileArtifacts = nil
			case "changed source":
				original := bundle.SourceFileArtifacts[0]
				payload := original.Payload()
				payload[len(payload)/2] ^= 1
				bundle.SourceFileArtifacts[0] = artifactsRewrite(t, original, original.Scope(), original.Origin(), original.Protection(), payload, original.Provenance())
			case "missing typed witness":
				bundle.Context = review.InvestigationGenerationContext{}
			case "wrong origin":
				witness = artifactsRewrite(t, turn, turn.Scope(), artifact.OriginModel, turn.Protection(), turn.Payload(), turn.Provenance())
			case "wrong classification":
				var err error
				witness, err = artifact.New(turn.Scope(), turn.Kind(), turn.MediaType(), artifact.ClassificationPublic, turn.Origin(), turn.Protection(), turn.Provenance(), turn.Payload(), turn.CreatedAt(), turn.ExpiresAt())
				artifactsCheck(t, err)
			case "wrong protection":
				witness = artifactsRewrite(t, turn, turn.Scope(), turn.Origin(), artifact.ProtectionEnvelopeEncrypted, turn.Payload(), turn.Provenance())
			case "wrong scope":
				scope, err := audit.NewReviewScope("other-tenant", "artifact-repo", "artifact-run")
				artifactsCheck(t, err)
				witness = artifactsRewrite(t, turn, scope, turn.Origin(), turn.Protection(), turn.Payload(), turn.Provenance())
			case "truncated turn":
				payload := turn.Payload()
				witness = artifactsRewrite(t, turn, turn.Scope(), turn.Origin(), turn.Protection(), payload[:len(payload)-1], turn.Provenance())
			case "changed context":
				payload := bundle.ContextArtifact.Payload()
				payload = bytes.Replace(payload, []byte("return 10 / x"), []byte("return 11 / x"), 1)
				bundle.ContextArtifact = artifactsRewrite(t, bundle.ContextArtifact, bundle.ContextArtifact.Scope(), bundle.ContextArtifact.Origin(), bundle.ContextArtifact.Protection(), payload, bundle.ContextArtifact.Provenance())
			case "duplicate source":
				bundle.SourceFileArtifacts = append(bundle.SourceFileArtifacts, bundle.SourceFileArtifacts[0])
			case "expected owner":
				want.OwnerIdentity = artifactsID("other-owner")
			case "expected session":
				want.SessionIdentity = artifactsID("other-session")
			case "expected policy":
				want.PolicyIdentity = artifactsID("other-policy")
			case "expected predecessor":
				want.PreviousTurnIdentity = artifactsID("nonexistent-prior-turn")
			case "expected head":
				want.HeadSnapshotArtifactIdentity = artifactsID("other-head")
			case "unexpected tool":
				bundle.ToolResultArtifacts = []artifact.Artifact{f.context.HeadSnapshotArtifact}
			}
			if _, err := ParseInvestigationGenerationResultArtifact(result, input, bundle, witness, want, f.clock.Now()); err == nil {
				t.Fatal("unavailable or cross-wired witness gained readback authority")
			}
		})
	}
	if _, err := ParseInvestigationGenerationResultArtifact(result, input, f.context, turn, expected, turn.ExpiresAt()); err == nil {
		t.Fatal("expired protected witness accepted")
	}
}
func TestInvestigationArtifactsPinFullTurnBytesNotOnlyTurnIdentity(t *testing.T) {
	f := newArtifactsFixture(t)
	input, turn, result, expected, owned := f.complete(t)
	var wire map[string]json.RawMessage
	artifactsCheck(t, json.Unmarshal(turn.Payload(), &wire))
	var ranking map[string]json.RawMessage
	artifactsCheck(t, json.Unmarshal(wire["ranking"], &ranking))
	var routes []map[string]json.RawMessage
	artifactsCheck(t, json.Unmarshal(ranking["ranked_routes"], &routes))
	var size uint32
	artifactsCheck(t, json.Unmarshal(routes[0]["evidence_manifest_size_bytes"], &size))
	routes[0]["evidence_manifest_size_bytes"] = artifactsJSON(t, size+1)
	ranking["ranked_routes"] = artifactsJSON(t, routes)
	wire["ranking"] = artifactsJSON(t, ranking)
	changed := artifactsJSON(t, wire)
	parsed, err := gateway.ParseInvestigationTurnRecord(changed)
	artifactsCheck(t, err)
	if parsed.Identity() != owned.Identity() || bytes.Equal(changed, turn.Payload()) {
		t.Fatal("metadata control did not retain same accepted turn identity")
	}
	substituted := artifactsRewrite(t, turn, turn.Scope(), turn.Origin(), turn.Protection(), changed, turn.Provenance())
	if substituted.Identity() == expected.TurnArtifactIdentity {
		t.Fatal("full artifact identity failed to bind changed retained bytes")
	}
	if _, err := ParseInvestigationGenerationResultArtifact(result, input, f.context, substituted, expected, f.clock.Now()); err == nil {
		t.Fatal("opaque turn ID bypassed trusted full artifact reference")
	}
}
func TestInvestigationArtifactsRejectDifferentCompleteBundleUnderOriginalExpectations(t *testing.T) {
	first := newArtifactsFixture(t)
	_, _, _, expected, _ := first.complete(t)
	second := newArtifactsFixture(t, "independently-authorized-other-run")
	input, turn, result, own, _ := second.complete(t)
	if _, err := ParseInvestigationGenerationResultArtifact(result, input, second.context, turn, own, second.clock.Now()); err != nil {
		t.Fatal("separately held expectations refused their own complete bundle")
	}
	if _, err := ParseInvestigationGenerationResultArtifact(result, input, second.context, turn, expected, second.clock.Now()); err == nil {
		t.Fatal("self-consistent different artifacts replaced pinned custody")
	}
}
func TestInvestigationArtifactConstructorsRespectStageSpecificFutureReferences(t *testing.T) {
	f := newArtifactsFixture(t)
	request, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	prediction := f.predicted(t, request)
	for _, stage := range []string{"input", "turn", "result"} {
		want := f.expected
		switch stage {
		case "input":
			want.InputArtifactIdentity = artifactsID("future-input")
		case "turn":
			want.TurnArtifactIdentity = artifactsID("future-turn")
		case "result":
			want.ResultArtifactIdentity = artifactsID("future-result")
		}
		if _, err := NewInvestigationGenerationInputArtifact(f.context, prediction, want, f.clock.Now()); err == nil {
			t.Fatal("input constructor accepted invented future identity")
		}
	}
	input, err := NewInvestigationGenerationInputArtifact(f.context, prediction, f.expected, f.clock.Now())
	artifactsCheck(t, err)
	expected := f.expected
	expected.InputArtifactIdentity = input.Identity()
	if _, err := NewInvestigationGenerationResultArtifact(input, f.context, artifact.Artifact{}, expected, f.clock.Now()); err == nil {
		t.Fatal("result constructor synthesized missing actual turn")
	}
	if len(f.model.calls) != 0 {
		t.Fatal("pure artifact construction dispatched a model")
	}
}
func TestInvestigationArtifactInputClaimsRejectMalformedCanonicalPayload(t *testing.T) {
	f := newArtifactsFixture(t)
	request, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	input, err := NewInvestigationGenerationInputArtifact(f.context, f.predicted(t, request), f.expected, f.clock.Now())
	artifactsCheck(t, err)
	claims, err := ParseInvestigationGenerationInput(input.Payload())
	artifactsCheck(t, err)
	encoded, err := EncodeInvestigationGenerationInput(claims)
	artifactsCheck(t, err)
	if !bytes.Equal(encoded, input.Payload()) {
		t.Fatal("v2 input claims did not preserve complete canonical bytes")
	}
	for _, mode := range []string{"unknown", "null", "version", "overflow", "duplicate", "truncated", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			var wire map[string]json.RawMessage
			artifactsCheck(t, json.Unmarshal(input.Payload(), &wire))
			changed := []byte{}
			switch mode {
			case "unknown":
				wire["unexpected"] = artifactsJSON(t, true)
			case "null":
				wire["authorization"] = json.RawMessage("null")
			case "version":
				wire["schema_version"] = artifactsJSON(t, 1)
			case "overflow":
				wire["snapshot_ranges"] = json.RawMessage(`[{"path":"a.go","start_line":18446744073709551616,"end_line":2}]`)
			case "duplicate":
				changed = bytes.Replace(input.Payload(), []byte(`"schema_version":2`), []byte(`"schema_version":2,"schema_version":2`), 1)
			case "truncated":
				changed = input.Payload()[:len(input.Payload())-1]
			case "oversized":
				changed = bytes.Repeat([]byte{' '}, (256<<10)+1)
			}
			if len(changed) == 0 {
				delete(wire, "identity")
				wire["identity"] = artifactsJSON(t, artifactsHash(artifactsJSON(t, wire)))
				changed = artifactsJSON(t, wire)
			}
			if bytes.Equal(changed, input.Payload()) {
				t.Fatal("malformed mutation missed input")
			}
			if _, err := ParseInvestigationGenerationInput(changed); err == nil {
				t.Fatal("rehashed malformed v2 claims accepted")
			}
		})
	}
}
func TestInvestigationArtifactsKeepExistingV1AndV3CodecControlsExact(t *testing.T) {
	f := newArtifactsFixture(t)
	request, err := f.packet.ProviderRequest()
	artifactsCheck(t, err)
	before := append([]byte(nil), request.Payload()...)
	contextArtifact, err := artifact.New(f.expected.Scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{f.context.HeadSnapshotArtifact.Identity()}, request.Payload(), f.clock.Now(), f.context.HeadSnapshotArtifact.ExpiresAt())
	artifactsCheck(t, err)
	turn, err := f.owner.Dispatch(context.Background(), gateway.InvestigationGenerationTurn, request)
	artifactsCheck(t, err)
	input, err := NewGenerationInput(contextArtifact, f.packet, f.context.Context.Snapshot(), turn.Authorization())
	artifactsCheck(t, err)
	inputBytes, err := EncodeGenerationInput(input)
	artifactsCheck(t, err)
	parsedInput, err := ParseGenerationInput(inputBytes)
	artifactsCheck(t, err)
	again, err := EncodeGenerationInput(parsedInput)
	artifactsCheck(t, err)
	if !bytes.Equal(inputBytes, again) {
		t.Fatal("existing v1 input codec changed")
	}
	inputArtifact, err := NewGenerationInputArtifact(input, contextArtifact, []string{f.context.HeadSnapshotArtifact.Identity()}, f.clock.Now())
	artifactsCheck(t, err)
	candidates, err := review.ParseCandidateBatch(turn.Dispatch().Response(), f.context.Context.Snapshot(), f.packet.EvidenceItems())
	artifactsCheck(t, err)
	output, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, f.packet.Identity(), candidates.Identity(), request, turn.Authorization(), turn.Outcome())
	artifactsCheck(t, err)
	execution, err := gateway.NewRouteExecutionRecord(turn.Authorization(), turn.Outcome(), turn.Reconciliation(), output)
	artifactsCheck(t, err)
	result, err := newGenerationResult(inputArtifact.Identity(), contextArtifact.Identity(), f.packet.Identity(), candidates, execution)
	artifactsCheck(t, err)
	resultBytes, err := encodeGenerationResult(result)
	artifactsCheck(t, err)
	provenance := []string{inputArtifact.Identity(), contextArtifact.Identity(), candidates.Identity(), execution.Identity(), turn.Authorization().Identity(), turn.Outcome().Identity(), turn.Reconciliation().Identity(), output.Identity()}
	slices.Sort(provenance)
	resultArtifact, err := artifact.New(f.expected.Scope, artifact.KindCandidateBatch, "application/json", artifact.ClassificationConfidential, artifact.OriginModel, artifact.ProtectionProcessPrivate, provenance, resultBytes, f.clock.Now(), contextArtifact.ExpiresAt())
	artifactsCheck(t, err)
	parsedResult, err := ParseGenerationResultArtifact(resultArtifact, inputArtifact, contextArtifact)
	artifactsCheck(t, err)
	again, err = encodeGenerationResult(parsedResult)
	artifactsCheck(t, err)
	if !bytes.Equal(resultBytes, again) {
		t.Fatal("existing v1 result codec changed")
	}
	after, err := f.packet.ProviderRequest()
	artifactsCheck(t, err)
	if !bytes.Equal(before, after.Payload()) || request.Identity() != after.Identity() {
		t.Fatal("existing current v3 request changed")
	}
	artifactsCheck(t, review.ValidateCandidateModelRequest(after, f.expected.Scope.Identity()))
}

func TestInvestigationResultRejectsActualResponseWithForeignEvidenceInSameSnapshot(t *testing.T) {
	f := newArtifactsFixture(t)
	f.model.foreign = true
	input, turn, expected, owned := f.ownedTurn(t)
	if owned.Validate() != nil || len(f.model.calls) != 1 {
		t.Fatal("actual external response/owned turn control failed")
	}
	if _, err := NewInvestigationGenerationResultArtifact(input, f.context, turn, expected, f.clock.Now()); err == nil {
		t.Fatal("retained candidate response imported unknown same-snapshot evidence")
	}
}
func TestInvestigationResultCannotSubstituteLaterOwnedRequestForFinalInput(t *testing.T) {
	f := newArtifactsFixture(t)
	input, _, _, expected, first := f.complete(t)
	laterRequest, err := f.packet.ProviderRequest()
	artifactsCheck(t, err)
	later, err := f.owner.Dispatch(context.Background(), gateway.InvestigationGenerationTurn, laterRequest)
	artifactsCheck(t, err)
	if later.RequestIdentity() == first.RequestIdentity() || later.PreviousTurnIdentity() != first.Identity() || len(f.model.calls) != 2 {
		t.Fatal("second actual owner dispatch did not establish different request lineage")
	}
	encoded, err := gateway.EncodeInvestigationTurnRecord(later)
	artifactsCheck(t, err)
	witness, err := artifact.New(expected.Scope, artifactsKind(t, "investigation_turn"), "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{input.Identity(), f.context.ContextArtifact.Identity(), expected.HeadSnapshotArtifactIdentity, later.Identity(), later.Authorization().Identity(), later.Outcome().Identity(), later.Reconciliation().Identity(), expected.OwnerIdentity}, encoded, f.clock.Now(), f.context.ContextArtifact.ExpiresAt())
	artifactsCheck(t, err)
	// Pin the actual second turn observed by the host, but retain the first input/context.
	expected.ResultArtifactIdentity = ""
	expected.TurnArtifactIdentity = witness.Identity()
	expected.PreviousTurnIdentity = first.Identity()
	if _, err := NewInvestigationGenerationResultArtifact(input, f.context, witness, expected, f.clock.Now()); err == nil {
		t.Fatal("different later request replaced the context/input being finalized")
	}
}

func TestInvestigationInputRejectsToolReferenceCountAndDuplication(t *testing.T) {
	f := newArtifactsFixture(t)
	request, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	prediction := f.predicted(t, request)
	for _, refs := range [][]string{{artifactsID("missing-tool")}, {artifactsID("same-tool"), artifactsID("same-tool")}} {
		expected := f.expected
		expected.ToolResultArtifactIdentities = refs
		if _, err := NewInvestigationGenerationInputArtifact(f.context, prediction, expected, f.clock.Now()); err == nil {
			t.Fatal("missing/duplicated tool custody references accepted")
		}
	}
	if len(f.model.calls) != 0 {
		t.Fatal("input reference rejection dispatched model")
	}
}

func TestInvestigationNoToolCodecRefusesPlausibleToolArtifactAndTypedClaims(t *testing.T) {
	f := newArtifactsFixture(t)
	payload := artifactsJSON(t, map[string]any{"contract": "open-trestle/investigation-tool-result", "schema_version": 1, "session_identity": f.expected.SessionIdentity, "scope_identity": f.expected.Scope.Identity(), "snapshot_artifact_identity": f.expected.HeadSnapshotArtifactIdentity, "snapshot_identity": f.expected.HeadSnapshotIdentity, "operation_identity": artifactsID("plausible-only-operation"), "tool": "snapshot.read", "files": []any{}, "sources": []any{}})
	tool, err := artifact.New(f.expected.Scope, artifactsKind(t, "investigation_tool_result"), "application/json", artifact.ClassificationConfidential, artifact.OriginDeterministicTool, artifact.ProtectionProcessPrivate, []string{f.expected.HeadSnapshotArtifactIdentity, artifactsID("plausible-only-operation")}, payload, f.clock.Now(), f.context.ContextArtifact.ExpiresAt())
	artifactsCheck(t, err)
	annotation, err := review.NewInvestigationResultAnnotation(tool.Identity(), tool.Payload())
	artifactsCheck(t, err)
	encoded, err := artifact.Encode(tool)
	artifactsCheck(t, err)
	originalRequest, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	claimed, err := review.NewInvestigationGenerationContext(f.binding, f.packet, f.context.Context.Snapshot(), review.InvestigationContextState{Turn: 2, PreviousRequestIdentity: originalRequest.Identity(), PreviousOutcomeIdentity: artifactsID("unowned-outcome-claim"), NewResultArtifactIdentities: []string{tool.Identity()}, Results: []review.InvestigationResultAnnotation{annotation}, ScannedBytes: 100, ReturnedBytes: uint64(len(encoded)), ToolCallsUsed: 1})
	artifactsCheck(t, err)
	for _, mode := range []string{"nonempty artifacts", "typed tool claims only", "both matched"} {
		t.Run(mode, func(t *testing.T) {
			bundle := f.context
			expected := f.expected
			if mode != "typed tool claims only" {
				bundle.ToolResultArtifacts = []artifact.Artifact{tool}
				expected.ToolResultArtifactIdentities = []string{tool.Identity()}
			}
			if mode != "nonempty artifacts" {
				bundle.Context = claimed
				request, err := claimed.ProviderRequest()
				artifactsCheck(t, err)
				bundle.ContextArtifact, err = artifact.New(expected.Scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{expected.HeadSnapshotArtifactIdentity, expected.SessionIdentity, expected.PolicyIdentity}, request.Payload(), f.clock.Now(), f.context.ContextArtifact.ExpiresAt())
				artifactsCheck(t, err)
				expected.ContextArtifactIdentity = bundle.ContextArtifact.Identity()
			}
			request, err := bundle.Context.ProviderRequest()
			artifactsCheck(t, err)
			if _, err := NewInvestigationGenerationInputArtifact(bundle, f.predicted(t, request), expected, f.clock.Now()); err == nil {
				t.Fatal("no-tool codec accepted plausible kind/hash/annotation without actual tool ownership codec")
			}
		})
	}
	if len(f.model.calls) != 0 {
		t.Fatal("pure unsupported-tool refusal dispatched a model")
	}
}

func TestInvestigationSourceWorkAdmissionUsesMetadataBeforeCopies(t *testing.T) {
	f := newArtifactsFixture(t)
	headBytes := f.context.HeadSnapshotArtifact.PayloadSizeBytes()
	maximumFilePayload := ((16 << 20) - headBytes) / 2
	makeFile := func(size int) artifact.Artifact {
		value, err := artifact.New(f.expected.Scope, artifact.KindSourceFile, "application/json", artifact.ClassificationConfidential, artifact.OriginRepository, artifact.ProtectionProcessPrivate, []string{f.expected.HeadSnapshotArtifactIdentity}, bytes.Repeat([]byte{'x'}, size), f.clock.Now(), f.context.HeadSnapshotArtifact.ExpiresAt())
		artifactsCheck(t, err)
		return value
	}
	atLimit := f.context
	atLimit.SourceFileArtifacts = []artifact.Artifact{makeFile(maximumFilePayload)}
	over := f.context
	over.SourceFileArtifacts = []artifact.Artifact{makeFile(maximumFilePayload + 1)}
	// These malformed file payloads test length admission only, not source validity.
	if !investigationSourceWorkWithinLimit(atLimit) || investigationSourceWorkWithinLimit(over) {
		t.Fatal("16MiB weighted source-input boundary is incorrect")
	}
	counted := f.context
	counted.SourceFileArtifacts = make([]artifact.Artifact, 129)
	if investigationSourceWorkWithinLimit(counted) {
		t.Fatal("source artifact count is unbounded")
	}
	var allowed bool
	allocations := testing.AllocsPerRun(20, func() { allowed = investigationSourceWorkWithinLimit(over) })
	if allocations != 0 || allowed {
		t.Fatal("metadata preflight copied/validated/allocated source payloads")
	}
	request, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	prediction := f.predicted(t, request)
	if _, err := NewInvestigationGenerationInputArtifact(over, prediction, f.expected, f.clock.Now()); err == nil {
		t.Fatal("oversized aggregate source work reached artifact admission")
	}
	if len(f.model.calls) != 0 {
		t.Fatal("source resource refusal performed model work")
	}
}
