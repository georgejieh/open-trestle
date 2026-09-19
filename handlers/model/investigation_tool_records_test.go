package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
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
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const toolRecordChanged = "package p\nfunc Changed(x int) int { return 10 / x }\n"
const toolRecordNotes = "first\nzero<&>\nlast\n"

func toolRecordCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func toolRecordHash(b []byte) string {
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:])
}
func toolRecordJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	toolRecordCheck(t, err)
	return encoded
}
func toolRecordIDs(values ...string) []string {
	result := append([]string{}, values...)
	slices.Sort(result)
	return slices.Compact(result)
}

type toolRecordClock struct{ at time.Time }

func (c *toolRecordClock) Now() time.Time { return c.at }

type toolRecordContextKey struct{}

type toolRecordExternalSource struct {
	id     evidence.SourceAdapterIdentity
	result scm.SourceAdapterResult
	calls  int
}

func (s *toolRecordExternalSource) Identity() evidence.SourceAdapterIdentity { return s.id }
func (s *toolRecordExternalSource) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.calls++
	return s.result
}

type toolRecordStore struct {
	artifact.Store
	held                      map[string]artifact.Artifact
	gets                      []string
	ledger                    audit.Ledger
	scope                     audit.ReviewScope
	claim, outcome, operation string
	check                     bool
	failID                    string
	cancel                    context.CancelFunc
	contextValue              any
	wantContext               context.Context
	t                         *testing.T
}

func (s *toolRecordStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	added, err := s.Store.Put(ctx, value, at)
	if err == nil {
		s.held[value.Identity()] = value
	}
	return added, err
}
func (s *toolRecordStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.gets = append(s.gets, id)
	if s.check {
		if ctx.Value(toolRecordContextKey{}) != s.contextValue || ctx != s.wantContext {
			s.t.Error("reader lost exact caller context or deadline")
		}
		events, err := s.ledger.Read(ctx, s.scope, 0, 100)
		toolRecordCheck(s.t, err)
		var claim, outcome audit.Event
		for _, event := range events {
			if event.Identity() == s.claim {
				claim = event
			}
			if event.Kind() == audit.EventRouteDispatchCompleted && event.SubjectIdentity() == s.outcome {
				outcome = event
			}
		}
		if claim.Kind() != audit.EventInvestigationToolClaimed || claim.SubjectIdentity() != s.operation || outcome.Identity() == "" || claim.Sequence() <= outcome.Sequence() || !slices.Contains(claim.CausalParentIdentities(), s.outcome) {
			s.t.Error("actual reader Get preceded the actual owned-outcome-bound claim event")
		}
	}
	if s.cancel != nil && id == s.failID {
		s.cancel()
	}
	if id == s.failID {
		return artifact.Artifact{}, errors.New("fixture protected read refused")
	}
	return s.Store.Get(ctx, scope, id, at)
}

type toolRecordExternalModel struct {
	adapter string
	t       *testing.T
	ledger  audit.Ledger
	scope   audit.ReviewScope
	call    map[string]any
	shape   string
	calls   []gateway.RouteDispatchRequest
}

func (m *toolRecordExternalModel) AdapterID() string { return m.adapter }
func (m *toolRecordExternalModel) ConfigurationIdentity() string {
	return toolRecordHash([]byte(m.adapter))
}
func (m *toolRecordExternalModel) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	toolRecordCheck(m.t, request.Validate())
	events, err := m.ledger.Read(ctx, m.scope, 0, 100)
	toolRecordCheck(m.t, err)
	claimed := false
	for _, event := range events {
		if event.Kind() == audit.EventRouteAttemptClaimed && event.SubjectIdentity() == request.Authorization().Identity() {
			claimed = true
		}
	}
	if !claimed {
		m.t.Fatal("model effect preceded its actual route claim")
	}
	m.calls = append(m.calls, request)
	if m.shape == "foreign-snapshot" {
		m.call["snapshot_ref"] = strings.Repeat("f", 64)
	}
	if m.shape == "line-one" {
		m.call["start_line"], m.call["end_line"] = 1, 1
	}
	payload := toolRecordJSON(m.t, map[string]any{"schema_version": 1, "tool_calls": []any{m.call}})
	kind, mediaType, finish := provider.ResponsePartStructuredData, "application/json", provider.ResponseFinishStop
	if m.shape == "text" {
		kind, mediaType = provider.ResponsePartAssistantText, "text/plain"
	}
	if m.shape == "length" {
		finish = provider.ResponseFinishLength
	}
	part, err := provider.NewResponsePart(kind, mediaType, payload)
	toolRecordCheck(m.t, err)
	parts := []provider.ResponsePart{part}
	if m.shape == "multiple" {
		parts = append(parts, part)
	}
	usage, err := provider.NewRouteTokenUsage(100, 100, 0)
	toolRecordCheck(m.t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, finish, parts, usage)
	toolRecordCheck(m.t, err)
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	toolRecordCheck(m.t, err)
	return result
}

type toolRecordFixture struct {
	t               *testing.T
	ctx             context.Context
	clock           *toolRecordClock
	store           *toolRecordStore
	ledger          audit.Ledger
	scope           audit.ReviewScope
	head            artifact.Artifact
	snapshot        source.Snapshot
	manifest        evidence.RepositoryManifest
	policy          review.InvestigationPolicy
	limits          source.SnapshotReadLimits
	reader          *source.SnapshotReader
	files           []source.SnapshotFileRef
	initial         review.ContextPacket
	selected        review.ReviewSnapshot
	initialSources  []review.ContextSource
	memoryScope     memory.Scope
	retrieval       memory.LexicalRetrieval
	binding         review.InvestigationContextBinding
	current         review.InvestigationGenerationContext
	contextArtifact artifact.Artifact
	state           review.InvestigationContextState
	owner           *gateway.InvestigationRouteOwner
	model           *toolRecordExternalModel
	allSourceIDs    []string
}

func newToolRecordFixture(t *testing.T, label string, projectionCap bool) *toolRecordFixture {
	t.Helper()
	f := &toolRecordFixture{t: t, clock: &toolRecordClock{time.UnixMilli(1000)}}
	f.ctx = context.WithValue(context.Background(), toolRecordContextKey{}, "caller-"+label)
	var err error
	f.scope, err = audit.NewReviewScope("tool-tenant", "tool-repo", "tool-"+label)
	toolRecordCheck(t, err)
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	toolRecordCheck(t, err)
	f.ledger = audit.NewMemoryLedger()
	f.store = &toolRecordStore{Store: store, held: map[string]artifact.Artifact{}, ledger: f.ledger, scope: f.scope, t: t, contextValue: f.ctx.Value(toolRecordContextKey{})}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "repo")
	toolRecordCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	toolRecordCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "tool-record-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	toolRecordCheck(t, err)
	contents := map[string][]byte{"a.go": []byte(toolRecordChanged), "notes.txt": []byte(toolRecordNotes)}
	files := []evidence.RepositoryFile{}
	for _, path := range []string{"a.go", "notes.txt"} {
		file, err := evidence.NewRepositoryFile(path, contents[path])
		toolRecordCheck(t, err)
		files = append(files, file)
	}
	f.manifest, err = evidence.NewRepositoryManifest(files)
	toolRecordCheck(t, err)
	external := &toolRecordExternalSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: f.manifest, Contents: contents}}
	handler, err := source.NewHandler(f.store, external, f.clock)
	toolRecordCheck(t, err)
	input, err := source.NewInput(repository, revision, adapter)
	toolRecordCheck(t, err)
	inputArtifact, err := source.NewInputArtifact(f.scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{toolRecordHash([]byte("host-input"))}, time.UnixMilli(100), time.UnixMilli(6000))
	toolRecordCheck(t, err)
	_, err = f.store.Put(f.ctx, inputArtifact, time.UnixMilli(100))
	toolRecordCheck(t, err)
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputArtifact.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
	toolRecordCheck(t, err)
	plan, err := controlplane.NewReviewRunPlan(f.scope, toolRecordHash([]byte("request")), toolRecordHash([]byte("review-policy")), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	toolRecordCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	toolRecordCheck(t, err)
	_, err = coordinator.Open(f.ctx, plan, time.UnixMilli(100))
	toolRecordCheck(t, err)
	_, err = coordinator.Advance(f.ctx, plan, time.UnixMilli(101))
	toolRecordCheck(t, err)
	lease, acquired, err := coordinator.ClaimTask(f.ctx, plan, "source", handler.HandlerIdentity(), "fixture-worker", time.UnixMilli(102))
	toolRecordCheck(t, err)
	if !acquired {
		t.Fatal("source task was not actually claimed")
	}
	execution, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	toolRecordCheck(t, err)
	completion := handler.Execute(f.ctx, execution)
	if completion.Status() != controlplane.TaskCompletionSucceeded || external.calls != 1 {
		t.Fatal("actual source handler did not acquire protected files")
	}
	_, err = coordinator.CompleteTask(f.ctx, plan, lease, completion, f.clock.Now())
	toolRecordCheck(t, err)
	f.head, err = f.store.Get(f.ctx, f.scope, completion.OutputIdentity(), f.clock.Now())
	toolRecordCheck(t, err)
	f.snapshot, err = source.ParseSnapshotArtifact(f.head)
	toolRecordCheck(t, err)
	for _, file := range f.snapshot.Files() {
		f.allSourceIDs = append(f.allSourceIDs, file.ArtifactIdentity())
	}
	f.allSourceIDs = toolRecordIDs(f.allSourceIDs...)
	f.limits = source.SnapshotReadLimits{MaxFiles: 2, MaxLines: 20, MaxResultBytes: 8192, MaxMatches: 8, MaxScannedBytes: 65536}
	f.reader, err = source.NewSnapshotReader(f.ctx, f.store, f.clock, f.scope, f.head.Identity(), f.snapshot.Identity(), f.limits)
	toolRecordCheck(t, err)
	bootstrap, err := f.reader.List(f.ctx)
	toolRecordCheck(t, err)
	f.files = bootstrap.Files()
	var initial source.SnapshotSlice
	for _, file := range f.files {
		if file.Path() == "a.go" {
			initial, err = f.reader.Read(f.ctx, file.Ref(), 2, 2)
			toolRecordCheck(t, err)
		}
	}
	item, err := evidence.NewEvidenceItem(initial.Binding().Identity(), evidence.EvidenceKindSource, initial.Binding().SliceDigest(), initial.Binding().SourceRange())
	toolRecordCheck(t, err)
	bound, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, initial.Content(), initial.Binding())
	toolRecordCheck(t, err)
	f.initialSources = []review.ContextSource{bound}
	f.selected, err = review.NewAcquiredReviewPipelineSnapshot(f.scope.ReviewRunID(), f.manifest, []evidence.SourceRange{initial.Binding().SourceRange()})
	toolRecordCheck(t, err)
	f.memoryScope, err = memory.NewScope(f.scope.TenantID(), f.scope.RepositoryID(), "actor", memory.RefVisibilityExact, toolRecordHash([]byte("review-policy")), []string{"."})
	toolRecordCheck(t, err)
	query, err := memory.NewLexicalQuery(f.memoryScope, "a.go", nil, nil, f.clock.Now(), 1)
	toolRecordCheck(t, err)
	f.retrieval, err = memory.NewLexicalIndex().Search(f.ctx, f.memoryScope, query)
	toolRecordCheck(t, err)
	contextLimits, err := review.NewContextLimits(65536, 0)
	toolRecordCheck(t, err)
	f.initial, err = review.NewContextPacket(f.scope, f.memoryScope, f.selected, review.ContextTaskCandidateGeneration, f.initialSources, f.retrieval, contextLimits)
	toolRecordCheck(t, err)
	policyBytes, err := os.ReadFile("../../internal/review/testdata/investigation-policy-v1.json")
	toolRecordCheck(t, err)
	if projectionCap {
		var wire map[string]any
		toolRecordCheck(t, json.Unmarshal(policyBytes, &wire))
		wire["max_result_bytes"] = bootstrap.SerializedBytes()
		policyBytes = toolRecordJSON(t, wire)
		f.limits.MaxResultBytes = int(bootstrap.SerializedBytes())
		f.reader, err = source.NewSnapshotReader(f.ctx, f.store, f.clock, f.scope, f.head.Identity(), f.snapshot.Identity(), f.limits)
		toolRecordCheck(t, err)
	}
	f.policy, err = review.ParseInvestigationPolicy(policyBytes)
	toolRecordCheck(t, err)
	routes := []map[string]any{}
	for _, name := range []string{"a", "b"} {
		routes = append(routes, map[string]any{"zone": "local", "provider_id": "provider-" + name, "adapter_id": "adapter-" + name, "connection_id": "connection-" + name, "model_id": "model-" + name, "model_version": "1", "max_context_tokens": 128000, "max_output_tokens": 4096, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 1000000, "output_micro_usd_per_million_tokens": 1000000, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte("approved route fixture")), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": true, "p95_latency_milliseconds": 10, "latency_sample_count": 20})
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(f.ctx, bytes.NewReader(toolRecordJSON(t, map[string]any{"schema_version": 1, "routes": routes})))
	toolRecordCheck(t, err)
	var generation, verification gateway.ObservedRouteCandidate
	for _, route := range inventory.Candidates() {
		if route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generation = route
		} else {
			verification = route
		}
	}
	f.model = &toolRecordExternalModel{adapter: "adapter-a", t: t, ledger: f.ledger, scope: f.scope}
	verifier := &toolRecordExternalModel{adapter: "adapter-b", t: t, ledger: f.ledger, scope: f.scope}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{f.model, verifier})
	toolRecordCheck(t, err)
	requirements, err := provider.NewModelRequirements(1, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	toolRecordCheck(t, err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	toolRecordCheck(t, err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	toolRecordCheck(t, err)
	budget, err := provider.NewModelCostBudget(1, 4096, 100000)
	toolRecordCheck(t, err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	toolRecordCheck(t, err)
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	toolRecordCheck(t, err)
	claim := func(route gateway.ObservedRouteCandidate) review.InvestigationRouteContextClaim {
		return review.InvestigationRouteContextClaim{Record: route.ResolvedRecord().RouteRegistryRecord(), ManifestSizeBytes: route.ResolvedRecord().EvidenceManifestSizeBytes(), Operational: route.OperationalState()}
	}
	options := review.InvestigationContextBindingOptions{Scope: f.scope, HostSessionIdentity: toolRecordHash([]byte("host-" + label)), Policy: f.policy, HeadSnapshotArtifactIdentity: f.head.Identity(), HeadSnapshotIdentity: f.snapshot.Identity(), HeadManifestIdentity: f.manifest.Identity(), HeadRevisionIdentity: f.snapshot.RevisionIdentity(), InitialContext: f.initial, InitialSnapshot: f.selected, Deadline: time.UnixMilli(6000), Routing: review.InvestigationContextRouting{RegistryRevision: inventory.RegistryRevision(), PerformanceRevision: inventory.PerformanceRevision(), Generation: claim(generation), Verification: []review.InvestigationRouteContextClaim{claim(verification)}, Performance: inventory.PerformanceObservations(), Requirements: requirements, Constraints: constraints, Budget: budget, VerificationRanking: ranking, Independence: independence, CatalogIdentity: catalog.Identity()}}
	f.binding, err = review.NewInvestigationContextBinding(options)
	toolRecordCheck(t, err)
	makePlan := func(route gateway.ObservedRouteCandidate) gateway.InvestigationRoutePlan {
		observations := []provider.RoutePerformanceObservation{}
		for _, observation := range inventory.PerformanceObservations() {
			if observation.RecordIdentity() == route.ResolvedRecord().RouteRegistryRecord().Identity() {
				observations = append(observations, observation)
			}
		}
		pin, err := gateway.NewPinnedRouteRankingPolicy(route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
		toolRecordCheck(t, err)
		plan, err := gateway.NewInvestigationRoutePlan(inventory.RegistryRevision(), []gateway.ObservedRouteCandidate{route}, pin, inventory.PerformanceRevision(), observations)
		toolRecordCheck(t, err)
		return plan
	}
	f.owner, err = gateway.NewInvestigationRouteOwner(gateway.InvestigationRouteOwnerOptions{Scope: f.scope, SessionIdentity: f.binding.Identity(), PolicyIdentity: f.policy.Identity(), Deadline: options.Deadline, MaxTurns: uint8(f.policy.MaxModelTurns()), Budget: budget, Requirements: requirements, Constraints: constraints, Generation: makePlan(generation), Verification: makePlan(verification), Catalog: catalog, Ledger: f.ledger, Clock: f.clock})
	toolRecordCheck(t, err)
	f.state = review.InvestigationContextState{Turn: 1, ScannedBytes: initial.ScannedBytes()}
	f.setContext(f.initial, f.selected)
	f.store.gets = nil
	return f
}

func (f *toolRecordFixture) setContext(packet review.ContextPacket, snapshot review.ReviewSnapshot) {
	var err error
	f.current, err = review.NewInvestigationGenerationContext(f.binding, packet, snapshot, f.state)
	toolRecordCheck(f.t, err)
	request, err := f.current.ProviderRequest()
	toolRecordCheck(f.t, err)
	f.contextArtifact, err = artifact.New(f.scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, toolRecordIDs(append([]string{f.head.Identity()}, f.allSourceIDs...)...), request.Payload(), f.clock.Now(), time.UnixMilli(6000))
	toolRecordCheck(f.t, err)
	_, err = f.store.Put(f.ctx, f.contextArtifact, f.clock.Now())
	toolRecordCheck(f.t, err)
}

func (f *toolRecordFixture) file(path string) source.SnapshotFileRef {
	for _, file := range f.files {
		if file.Path() == path {
			return file
		}
	}
	f.t.Fatal("fixture file not found")
	return source.SnapshotFileRef{}
}

func (f *toolRecordFixture) dispatch(tool, callID, literal string, refs []string) (InvestigationToolEvidence, InvestigationToolExpectations, gateway.InvestigationTurnRecord, review.InvestigationProposal) {
	t := f.t
	request, err := f.current.ProviderRequest()
	toolRecordCheck(t, err)
	var packet struct {
		Investigation struct {
			SnapshotRef string `json:"snapshot_ref"`
		} `json:"investigation"`
	}
	toolRecordCheck(t, json.Unmarshal(request.Payload(), &packet))
	call := map[string]any{"tool": tool, "call_id": callID, "snapshot_ref": packet.Investigation.SnapshotRef}
	if tool == "snapshot.read" {
		call["file_ref"], call["start_line"], call["end_line"] = refs[0], 2, 2
	}
	if tool == "snapshot.search" {
		call["file_refs"], call["literal"] = refs, literal
	}
	f.model.call = call
	turn, err := f.owner.Dispatch(f.ctx, gateway.InvestigationGenerationTurn, request)
	toolRecordCheck(t, err)
	if turn.Validate() != nil || turn.RequestIdentity() != request.Identity() {
		t.Fatal("actual owner returned an invalid turn")
	}
	turnBytes, err := gateway.EncodeInvestigationTurnRecord(turn)
	toolRecordCheck(t, err)
	var header struct {
		Owner string `json:"owner_identity"`
	}
	toolRecordCheck(t, json.Unmarshal(turnBytes, &header))
	turnArtifact, err := artifact.New(f.scope, artifact.KindInvestigationTurn, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, toolRecordIDs(f.contextArtifact.Identity(), f.head.Identity(), turn.Identity(), turn.Outcome().Identity(), turn.Dispatch().Response().Identity()), turnBytes, f.clock.Now(), time.UnixMilli(6000))
	toolRecordCheck(t, err)
	_, err = f.store.Put(f.ctx, turnArtifact, f.clock.Now())
	toolRecordCheck(t, err)
	bundle := InvestigationToolEvidence{Policy: f.policy, ReaderLimits: f.limits, Context: f.current, ContextArtifact: f.contextArtifact, HeadArtifact: f.head, TurnArtifact: turnArtifact, SourceArtifacts: []artifact.Artifact{}}
	for _, id := range f.allSourceIDs {
		bundle.SourceArtifacts = append(bundle.SourceArtifacts, f.store.held[id])
	}
	expected := InvestigationToolExpectations{Scope: f.scope, Deadline: time.UnixMilli(6000), SessionIdentity: f.binding.Identity(), PolicyIdentity: f.policy.Identity(), OwnerIdentity: header.Owner, ContextArtifactIdentity: f.contextArtifact.Identity(), ContextIdentity: f.current.Identity(), RequestIdentity: request.Identity(), HeadArtifactIdentity: f.head.Identity(), HeadSnapshotIdentity: f.snapshot.Identity(), HeadManifestIdentity: f.manifest.Identity(), TurnArtifactIdentity: turnArtifact.Identity(), TurnIdentity: turn.Identity(), PreviousTurnIdentity: turn.PreviousTurnIdentity(), OutcomeIdentity: turn.Outcome().Identity(), ResponseIdentity: turn.Dispatch().Response().Identity(), SourceArtifactIdentities: append([]string(nil), f.allSourceIDs...)}
	proposal, err := review.ParseInvestigationProposal(turn.Dispatch().Response().Parts()[0].Payload())
	toolRecordCheck(t, err)
	return bundle, expected, turn, proposal
}

type toolRecordFileProjection struct {
	Ref              string `json:"ref"`
	Path             string `json:"path"`
	Digest           string `json:"digest"`
	SizeBytes        int    `json:"size_bytes"`
	ArtifactIdentity string `json:"file_artifact_identity"`
}
type toolRecordSliceProjection struct {
	File    toolRecordFileProjection `json:"file"`
	Start   int                      `json:"start_line"`
	End     int                      `json:"end_line"`
	Binding string                   `json:"binding_identity"`
	Content string                   `json:"content"`
}

func toolRecordFileWire(file source.SnapshotFileRef) toolRecordFileProjection {
	return toolRecordFileProjection{file.Ref(), file.Path(), file.Digest(), file.SizeBytes(), file.ArtifactIdentity()}
}
func toolRecordSliceWire(value source.SnapshotSlice) toolRecordSliceProjection {
	span := value.Binding().SourceRange()
	return toolRecordSliceProjection{toolRecordFileWire(value.File()), span.StartLine(), span.EndLine(), value.Binding().Identity(), string(value.Content())}
}

type toolRecordCapture struct {
	invocation          InvestigationToolInvocation
	listing             source.SnapshotListing
	slice               source.SnapshotSlice
	search              source.SnapshotSearchResult
	projection          []byte
	files               []source.SnapshotFileRef
	sources             []source.SnapshotSlice
	sourceIDs           []string
	scanned, serialized uint64
	started, finished   time.Time
	ordinal             uint64
	omitted             int
}

func (f *toolRecordFixture) capture(ctx context.Context, op InvestigationToolOperation, turn gateway.InvestigationTurnRecord) (toolRecordCapture, error) {
	if ctx == nil || ctx.Err() != nil {
		return toolRecordCapture{}, errors.New("invocation context unavailable")
	}
	head, exists, err := f.ledger.Head(ctx, f.scope)
	if err != nil {
		return toolRecordCapture{}, err
	}
	sequence, previous := uint64(1), ""
	if exists {
		sequence, previous = head.Sequence()+1, head.Identity()
	}
	claim, err := audit.NewEvent(f.scope, sequence, previous, audit.EventInvestigationToolClaimed, op.Identity(), toolRecordIDs(f.binding.Identity(), f.head.Identity(), turn.Identity(), turn.Outcome().Identity(), turn.Dispatch().Response().Identity()), f.clock.Now())
	if err != nil {
		return toolRecordCapture{}, err
	}
	if err := f.ledger.Append(ctx, previous, claim); err != nil {
		return toolRecordCapture{}, err
	}
	f.store.claim, f.store.outcome, f.store.operation, f.store.check = claim.Identity(), turn.Outcome().Identity(), op.Identity(), true
	f.store.wantContext = ctx
	defer func() { f.store.check = false }()
	captured := toolRecordCapture{files: []source.SnapshotFileRef{}, sources: []source.SnapshotSlice{}, sourceIDs: []string{}, started: f.clock.Now(), ordinal: uint64(f.state.Turn)}
	switch op.Tool() {
	case "snapshot.list":
		captured.listing, err = f.reader.List(ctx)
		if err != nil {
			return toolRecordCapture{}, err
		}
		captured.files, captured.omitted, captured.serialized = captured.listing.Files(), captured.listing.OmittedCount(), captured.listing.SerializedBytes()
		files := []toolRecordFileProjection{}
		for _, file := range captured.files {
			files = append(files, toolRecordFileWire(file))
		}
		captured.projection = toolRecordJSON(f.t, struct {
			Files   []toolRecordFileProjection `json:"files"`
			Omitted int                        `json:"omitted_file_count"`
		}{files, captured.omitted})
		captured.finished = f.clock.Now()
		captured.invocation, err = newInvestigationListingInvocation(op, turn, captured.ordinal, f.limits, captured.sourceIDs, captured.started, captured.finished, captured.listing)
	case "snapshot.read":
		captured.slice, err = f.reader.Read(ctx, op.FileRef(), op.StartLine(), op.EndLine())
		if err != nil {
			return toolRecordCapture{}, err
		}
		captured.files, captured.sources = []source.SnapshotFileRef{captured.slice.File()}, []source.SnapshotSlice{captured.slice}
		captured.scanned, captured.serialized = captured.slice.ScannedBytes(), captured.slice.SerializedBytes()
		captured.sourceIDs = []string{captured.slice.File().ArtifactIdentity()}
		captured.projection = toolRecordJSON(f.t, struct {
			Source  toolRecordSliceProjection `json:"source"`
			Scanned uint64                    `json:"scanned_bytes"`
		}{toolRecordSliceWire(captured.slice), captured.scanned})
		captured.finished = f.clock.Now()
		captured.invocation, err = newInvestigationReadInvocation(op, turn, captured.ordinal, f.limits, captured.sourceIDs, captured.started, captured.finished, captured.slice)
	case "snapshot.search":
		refs := op.FileRefs()
		if !slices.IsSorted(refs) {
			f.t.Fatal("search execution was not the canonical operation set")
		}
		captured.search, err = f.reader.Search(ctx, refs, op.Literal())
		if err != nil {
			return toolRecordCapture{}, err
		}
		captured.sources, captured.scanned, captured.serialized = captured.search.Matches(), captured.search.ScannedBytes(), captured.search.SerializedBytes()
		for _, ref := range refs {
			for _, file := range f.files {
				if file.Ref() == ref {
					captured.files = append(captured.files, file)
					captured.sourceIDs = append(captured.sourceIDs, file.ArtifactIdentity())
				}
			}
		}
		captured.sourceIDs = toolRecordIDs(captured.sourceIDs...)
		matches := []toolRecordSliceProjection{}
		for _, match := range captured.sources {
			matches = append(matches, toolRecordSliceWire(match))
		}
		captured.projection = toolRecordJSON(f.t, struct {
			Matches  []toolRecordSliceProjection `json:"matches"`
			Complete bool                        `json:"complete"`
			Scanned  uint64                      `json:"scanned_bytes"`
		}{matches, captured.search.Complete(), captured.scanned})
		captured.finished = f.clock.Now()
		captured.invocation, err = newInvestigationSearchInvocation(op, turn, captured.ordinal, f.limits, captured.sourceIDs, captured.started, captured.finished, captured.files, captured.search)
	default:
		return toolRecordCapture{}, errors.New("unsupported fixture operation")
	}
	if err != nil {
		return toolRecordCapture{}, err
	}
	if captured.serialized != uint64(len(captured.projection)) {
		f.t.Fatal("reader projection recipe changed")
	}
	return captured, nil
}

func toolRecordOperationPreimage(e InvestigationToolExpectations, proposal review.InvestigationProposal) []any {
	refs := append([]string{}, proposal.FileRefs()...)
	slices.Sort(refs)
	return []any{"open-trestle/investigation-tool-operation", 1, e.Scope.Identity(), e.SessionIdentity, e.PolicyIdentity, e.HeadArtifactIdentity, e.HeadSnapshotIdentity, e.HeadManifestIdentity, proposal.SnapshotRef(), proposal.Tool(), proposal.FileRef(), proposal.StartLine(), proposal.EndLine(), refs, proposal.Literal()}
}
func toolRecordOperationWire(e InvestigationToolExpectations, proposal review.InvestigationProposal, identity string) map[string]any {
	refs := append([]string{}, proposal.FileRefs()...)
	slices.Sort(refs)
	return map[string]any{"contract": "open-trestle/investigation-tool-operation", "schema_version": 1, "identity": identity, "scope_identity": e.Scope.Identity(), "session_identity": e.SessionIdentity, "policy_identity": e.PolicyIdentity, "snapshot_artifact_identity": e.HeadArtifactIdentity, "snapshot_identity": e.HeadSnapshotIdentity, "manifest_identity": e.HeadManifestIdentity, "snapshot_ref": proposal.SnapshotRef(), "tool": proposal.Tool(), "file_ref": proposal.FileRef(), "start_line": proposal.StartLine(), "end_line": proposal.EndLine(), "file_refs": refs, "literal": proposal.Literal()}
}
func toolRecordOperation(t *testing.T, bundle InvestigationToolEvidence, expected InvestigationToolExpectations, proposal review.InvestigationProposal, at time.Time) InvestigationToolOperation {
	t.Helper()
	op, err := NewInvestigationToolOperation(bundle, expected, at)
	toolRecordCheck(t, err)
	preimage := toolRecordOperationPreimage(expected, proposal)
	if len(preimage) != 15 || op.Identity() != toolRecordHash(toolRecordJSON(t, preimage)) || op.Validate() != nil {
		t.Fatal("operation lost exact fifteen-element identity")
	}
	encoded, err := EncodeInvestigationToolOperation(op)
	toolRecordCheck(t, err)
	if !bytes.Equal(encoded, toolRecordJSON(t, toolRecordOperationWire(expected, proposal, op.Identity()))) {
		t.Fatal("operation wire is not exact canonical normalized arguments")
	}
	return op
}

func toolRecordResultPayload(t *testing.T, op InvestigationToolOperation, bundle InvestigationToolEvidence, expected InvestigationToolExpectations, proposal review.InvestigationProposal, captured toolRecordCapture) []byte {
	t.Helper()
	proposalBytes, err := review.EncodeInvestigationProposal(proposal)
	toolRecordCheck(t, err)
	files, sources := []any{}, []any{}
	for _, file := range captured.files {
		files = append(files, map[string]any{"ref": file.Ref(), "path": file.Path(), "digest": file.Digest(), "size_bytes": file.SizeBytes(), "file_artifact_identity": file.ArtifactIdentity()})
	}
	for _, value := range captured.sources {
		binding := value.Binding()
		span := binding.SourceRange()
		sources = append(sources, map[string]any{"file_ref": value.File().Ref(), "path": span.Path(), "start_line": span.StartLine(), "end_line": span.EndLine(), "content": string(value.Content()), "binding_identity": binding.Identity(), "repository_file_identity": binding.RepositoryFileIdentity(), "repository_file_digest": binding.RepositoryFileDigest(), "slice_digest": binding.SliceDigest(), "slice_bytes": binding.SliceBytes()})
	}
	wire := map[string]any{
		"contract": "open-trestle/investigation-tool-result", "schema_version": 1,
		"scope_identity": expected.Scope.Identity(), "session_identity": expected.SessionIdentity, "policy_identity": expected.PolicyIdentity, "owner_identity": expected.OwnerIdentity,
		"context_artifact_identity": expected.ContextArtifactIdentity, "context_identity": expected.ContextIdentity, "request_identity": expected.RequestIdentity,
		"snapshot_artifact_identity": expected.HeadArtifactIdentity, "snapshot_identity": expected.HeadSnapshotIdentity, "manifest_identity": expected.HeadManifestIdentity, "snapshot_ref": proposal.SnapshotRef(),
		"turn_artifact_identity": expected.TurnArtifactIdentity, "turn_identity": expected.TurnIdentity, "previous_turn_identity": expected.PreviousTurnIdentity, "outcome_identity": expected.OutcomeIdentity,
		"proposal_response_identity": expected.ResponseIdentity, "proposal_identity": proposal.Identity(), "proposal": json.RawMessage(proposalBytes), "operation_identity": op.Identity(), "invocation_identity": captured.invocation.Identity(),
		"tool": op.Tool(), "call_id": proposal.CallID(), "file_ref": op.FileRef(), "start_line": op.StartLine(), "end_line": op.EndLine(), "file_refs": append([]string{}, op.FileRefs()...), "literal": op.Literal(),
		"files": files, "sources": sources, "complete": true, "omitted_file_count": captured.omitted, "scanned_bytes": captured.scanned, "reader_serialized_bytes": captured.serialized,
	}
	wire["identity"] = toolRecordHash(toolRecordJSON(t, wire))
	return toolRecordJSON(t, wire)
}

func toolRecordNewResult(op InvestigationToolOperation, bundle InvestigationToolEvidence, invocation InvestigationToolInvocation, expected InvestigationToolExpectations, at time.Time) (artifact.Artifact, error) {
	switch op.Tool() {
	case "snapshot.list":
		return NewInvestigationListToolResultArtifact(op, bundle, invocation, expected, at)
	case "snapshot.read":
		return NewInvestigationReadToolResultArtifact(op, bundle, invocation, expected, at)
	case "snapshot.search":
		return NewInvestigationSearchToolResultArtifact(op, bundle, invocation, expected, at)
	}
	return artifact.Artifact{}, errors.New("unsupported fixture operation")
}
func toolRecordParseResult(value artifact.Artifact, op InvestigationToolOperation, bundle InvestigationToolEvidence, invocation InvestigationToolInvocation, expected InvestigationToolExpectations, at time.Time) (InvestigationToolResult, error) {
	switch op.Tool() {
	case "snapshot.list":
		return ParseInvestigationListToolResultArtifact(value, op, bundle, invocation, expected, at)
	case "snapshot.read":
		return ParseInvestigationReadToolResultArtifact(value, op, bundle, invocation, expected, at)
	case "snapshot.search":
		return ParseInvestigationSearchToolResultArtifact(value, op, bundle, invocation, expected, at)
	}
	return InvestigationToolResult{}, errors.New("unsupported fixture operation")
}

func (f *toolRecordFixture) result(op InvestigationToolOperation, bundle InvestigationToolEvidence, expected InvestigationToolExpectations, proposal review.InvestigationProposal, captured toolRecordCapture) (artifact.Artifact, InvestigationToolResult, InvestigationToolExpectations) {
	t := f.t
	limits := f.limits
	preimage := []any{"open-trestle/investigation-tool-invocation", 1, op.Identity(), expected.TurnIdentity, captured.ordinal, captured.started.UnixMilli(), captured.finished.UnixMilli(), []any{limits.MaxFiles, limits.MaxLines, limits.MaxResultBytes, limits.MaxMatches, limits.MaxScannedBytes}, captured.sourceIDs, toolRecordHash(captured.projection)}
	if len(preimage) != 10 || captured.invocation.Identity() != toolRecordHash(toolRecordJSON(t, preimage)) || captured.invocation.Validate() != nil {
		t.Fatal("captured invocation lost exact ten-element association")
	}
	expected.OperationIdentity, expected.InvocationIdentity = op.Identity(), captured.invocation.Identity()
	beforeGets, beforeState := len(f.store.gets), f.owner.State()
	beforeEvents, err := f.ledger.Read(f.ctx, f.scope, 0, 100)
	toolRecordCheck(t, err)
	value, err := toolRecordNewResult(op, bundle, captured.invocation, expected, f.clock.Now())
	toolRecordCheck(t, err)
	if !bytes.Equal(value.Payload(), toolRecordResultPayload(t, op, bundle, expected, proposal, captured)) {
		t.Fatal("result payload differs from complete exact v1 preimage/fields")
	}
	if value.Kind() != artifact.KindInvestigationToolResult || value.Origin() != artifact.OriginDeterministicTool || value.Scope() != f.scope || value.Protection() != artifact.ProtectionProcessPrivate || value.ExpiresAt().After(expected.Deadline) {
		t.Fatal("result artifact lost protected metadata or deadline bound")
	}
	provenance := []string{expected.HeadArtifactIdentity, op.Identity(), expected.TurnIdentity, expected.ResponseIdentity, expected.ContextArtifactIdentity, expected.TurnArtifactIdentity}
	for _, file := range captured.files {
		provenance = append(provenance, file.ArtifactIdentity())
	}
	if !slices.Equal(value.Provenance(), toolRecordIDs(provenance...)) {
		t.Fatal("result provenance is not the exact selected protected-reference set")
	}
	_, err = f.store.Put(f.ctx, value, f.clock.Now())
	toolRecordCheck(t, err)
	expected.ResultArtifactIdentity = value.Identity()
	parsed, err := toolRecordParseResult(value, op, bundle, captured.invocation, expected, f.clock.Now())
	toolRecordCheck(t, err)
	encoded, err := EncodeInvestigationToolResult(parsed)
	toolRecordCheck(t, err)
	if !bytes.Equal(encoded, value.Payload()) || parsed.Validate() != nil || parsed.OperationIdentity() != op.Identity() || parsed.InvocationIdentity() != captured.invocation.Identity() || parsed.ScannedBytes() != captured.scanned || parsed.ReaderSerializedBytes() != captured.serialized {
		t.Fatal("result readback lost actual invocation or byte accounting")
	}
	if parsed.Tool() != op.Tool() || parsed.CallID() != proposal.CallID() || parsed.RequestIdentity() != expected.RequestIdentity || parsed.ProposalIdentity() != proposal.Identity() || parsed.ResponseIdentity() != expected.ResponseIdentity || parsed.TurnIdentity() != expected.TurnIdentity || parsed.OutcomeIdentity() != expected.OutcomeIdentity {
		t.Fatal("result getters lost complete owned proposal lineage")
	}
	if len(parsed.Sources()) != len(captured.sources) || len(parsed.Files()) != len(captured.files) || parsed.OmittedFileCount() != captured.omitted || !parsed.Complete() {
		t.Fatal("result invented or dropped reader outputs")
	}
	for i, file := range parsed.Files() {
		if file != captured.files[i] {
			t.Fatal("result file reference differs from held reader witness")
		}
	}
	for i, source := range parsed.Sources() {
		if source.Stage() != review.ContextStageRepositoryContext || source.ReferenceID() != captured.sources[i].Binding().Identity() || !bytes.Equal(source.Content(), captured.sources[i].Content()) {
			t.Fatal("result source is not the held physical repository binding")
		}
	}
	encoded[0] = 'x'
	copySources := parsed.Sources()
	if len(copySources) > 0 {
		copySources[0] = review.ContextSource{}
	}
	again, err := EncodeInvestigationToolResult(parsed)
	toolRecordCheck(t, err)
	if !bytes.Equal(again, value.Payload()) {
		t.Fatal("result getters or encoding alias internal state")
	}
	afterEvents, err := f.ledger.Read(f.ctx, f.scope, 0, 100)
	toolRecordCheck(t, err)
	if beforeGets != len(f.store.gets) || !reflect.DeepEqual(beforeState, f.owner.State()) || !reflect.DeepEqual(beforeEvents, afterEvents) {
		t.Fatal("pure codec executed Get, changed audit state or touched the owner")
	}
	return value, parsed, expected
}

func (f *toolRecordFixture) advance(value artifact.Artifact, result InvestigationToolResult, turn gateway.InvestigationTurnRecord) {
	t := f.t
	head, exists, err := f.ledger.Head(f.ctx, f.scope)
	toolRecordCheck(t, err)
	if !exists {
		t.Fatal("actual tool claim missing")
	}
	completion, err := audit.NewEvent(f.scope, head.Sequence()+1, head.Identity(), audit.EventInvestigationToolCompleted, value.Identity(), toolRecordIDs(result.OperationIdentity(), turn.Identity(), f.head.Identity()), f.clock.Now())
	toolRecordCheck(t, err)
	toolRecordCheck(t, f.ledger.Append(f.ctx, head.Identity(), completion))
	annotation, err := review.NewInvestigationResultAnnotation(value.Identity(), value.Payload())
	toolRecordCheck(t, err)
	envelope, err := artifact.Encode(value)
	toolRecordCheck(t, err)
	if uint64(len(envelope)) <= result.ReaderSerializedBytes() || len(envelope) <= len(value.Payload()) {
		t.Fatal("fixture did not separate reader projection, payload and full artifact framing")
	}
	f.state.Turn++
	f.state.ToolCallsUsed++
	f.state.PreviousRequestIdentity, f.state.PreviousOutcomeIdentity = turn.RequestIdentity(), turn.Outcome().Identity()
	f.state.Results = append(f.state.Results, annotation)
	f.state.NewResultArtifactIdentities = []string{value.Identity()}
	f.state.ScannedBytes += result.ScannedBytes()
	f.state.ReturnedBytes += uint64(len(envelope))
	f.initialSources = append(f.initialSources, result.Sources()...)
	ranges := []evidence.SourceRange{}
	for _, source := range f.initialSources {
		ranges = append(ranges, source.EvidenceItem().SourceRange())
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(f.scope.ReviewRunID(), f.manifest, ranges)
	toolRecordCheck(t, err)
	limits, err := review.NewContextLimits(65536, 0)
	toolRecordCheck(t, err)
	packet, err := review.NewContextPacket(f.scope, f.memoryScope, snapshot, review.ContextTaskCandidateGeneration, f.initialSources, f.retrieval, limits)
	toolRecordCheck(t, err)
	f.setContext(packet, snapshot)
}

func TestInvestigationToolRecordsListThenReadAddsPhysicalSourceToV4(t *testing.T) {
	f := newToolRecordFixture(t, "list-read", false)
	listBundle, listExpected, listTurn, listProposal := f.dispatch("snapshot.list", "list-a", "", nil)
	before := len(f.store.gets)
	listOp := toolRecordOperation(t, listBundle, listExpected, listProposal, f.clock.Now())
	if len(f.store.gets) != before {
		t.Fatal("pure operation constructor performed source I/O")
	}
	listCapture, err := f.capture(f.ctx, listOp, listTurn)
	toolRecordCheck(t, err)
	listArtifact, listResult, _ := f.result(listOp, listBundle, listExpected, listProposal, listCapture)
	if listResult.ScannedBytes() != 0 || len(listResult.Sources()) != 0 {
		t.Fatal("metadata listing invented file scans or source authority")
	}
	f.advance(listArtifact, listResult, listTurn)
	ref := ""
	for _, file := range listResult.Files() {
		if file.Path() == "notes.txt" {
			ref = file.Ref()
		}
	}
	if ref == "" {
		t.Fatal("list result did not expose an actual protected snapshot ref")
	}
	readBundle, readExpected, readTurn, readProposal := f.dispatch("snapshot.read", "read-a", "", []string{ref})
	if bytes.Contains(f.model.calls[0].Request().Payload(), []byte(ref)) || !bytes.Contains(f.model.calls[1].Request().Payload(), []byte(ref)) {
		t.Fatal("list discovery was not present in the actual next owned model request")
	}
	readOp := toolRecordOperation(t, readBundle, readExpected, readProposal, f.clock.Now())
	readCapture, err := f.capture(f.ctx, readOp, readTurn)
	toolRecordCheck(t, err)
	readArtifact, readResult, _ := f.result(readOp, readBundle, readExpected, readProposal, readCapture)
	if string(readResult.Sources()[0].Content()) != "zero<&>\n" || readResult.ScannedBytes() != uint64(len(toolRecordNotes)) || !readResult.Sources()[0].HasSliceBinding() || readResult.Sources()[0].SliceBindingIdentity() != readCapture.slice.Binding().Identity() {
		t.Fatal("read output lost actual full-file charge or physical line binding")
	}
	f.advance(readArtifact, readResult, readTurn)
	request, err := f.current.ProviderRequest()
	toolRecordCheck(t, err)
	var wire struct {
		Sources []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
			Stage   string `json:"stage"`
		} `json:"sources"`
		Investigation struct {
			Head            string                       `json:"snapshot_identity"`
			PreviousRequest string                       `json:"previous_request_identity"`
			PreviousOutcome string                       `json:"previous_outcome_identity"`
			Results         []map[string]json.RawMessage `json:"tool_results"`
		} `json:"investigation"`
	}
	toolRecordCheck(t, json.Unmarshal(request.Payload(), &wire))
	if len(wire.Sources) != 2 || len(wire.Investigation.Results) != 2 || wire.Investigation.Head != f.snapshot.Identity() || wire.Investigation.PreviousRequest != readTurn.RequestIdentity() || wire.Investigation.PreviousOutcome != readTurn.Outcome().Identity() || f.current.Snapshot().Identity() == f.selected.Identity() {
		t.Fatal("list/read lineage did not reach a fresh expanded selected v4 context")
	}
	found := false
	for _, item := range wire.Sources {
		found = found || item.Path == "notes.txt" && item.Content == "zero<&>\n" && item.Stage == "repository_context"
	}
	if !found {
		t.Fatal("actual newly bound source was omitted from v4")
	}
	for i, stored := range []artifact.Artifact{listArtifact, readArtifact} {
		var id string
		toolRecordCheck(t, json.Unmarshal(wire.Investigation.Results[i]["artifact_identity"], &id))
		delete(wire.Investigation.Results[i], "artifact_identity")
		if id != stored.Identity() || !bytes.Equal(toolRecordJSON(t, wire.Investigation.Results[i]), stored.Payload()) {
			t.Fatal("context-only annotation changed stored payload or made self-reference")
		}
	}
	listBytes, err := artifact.Encode(listArtifact)
	toolRecordCheck(t, err)
	readBytes, err := artifact.Encode(readArtifact)
	toolRecordCheck(t, err)
	if f.state.ReturnedBytes != uint64(len(listBytes)+len(readBytes)) || f.state.ScannedBytes != uint64(len(toolRecordChanged)+len(toolRecordNotes)) || f.owner.State().RemainingCostMicroUSD() != 99600 || len(f.model.calls) != 2 {
		t.Fatal("tool record framing or context progression reset actual shared accounting")
	}
}

func TestInvestigationToolNoMatchWitnessesRequireCapturedInvocationAssociation(t *testing.T) {
	f := newToolRecordFixture(t, "no-match", false)
	refs := []string{f.file("notes.txt").Ref(), f.file("a.go").Ref()}
	bundleA, expectedA, turnA, proposalA := f.dispatch("snapshot.search", "search-a", "absent-one", refs)
	opA := toolRecordOperation(t, bundleA, expectedA, proposalA, f.clock.Now())
	captureA, err := f.capture(f.ctx, opA, turnA)
	toolRecordCheck(t, err)
	artifactA, resultA, pinnedA := f.result(opA, bundleA, expectedA, proposalA, captureA)
	f.advance(artifactA, resultA, turnA)
	bundleB, expectedB, turnB, proposalB := f.dispatch("snapshot.search", "search-b", "absent-two", refs)
	opB := toolRecordOperation(t, bundleB, expectedB, proposalB, f.clock.Now())
	captureB, err := f.capture(f.ctx, opB, turnB)
	toolRecordCheck(t, err)
	_, resultB, _ := f.result(opB, bundleB, expectedB, proposalB, captureB)
	if !bytes.Equal(captureA.projection, captureB.projection) || len(captureA.search.Matches()) != 0 || len(captureB.search.Matches()) != 0 || !captureA.search.Complete() || !captureB.search.Complete() {
		t.Fatal("counterexample did not produce equal complete no-match projections from two actual queries")
	}
	if opA.Identity() == opB.Identity() || captureA.invocation.Identity() == captureB.invocation.Identity() {
		t.Fatal("different executed literals lost their captured operation association")
	}
	for _, result := range []InvestigationToolResult{resultA, resultB} {
		if len(result.Sources()) != 0 || result.ScannedBytes() != uint64(len(toolRecordChanged)+len(toolRecordNotes)) {
			t.Fatal("no-match result invented sources or free input scans")
		}
	}
	if _, err := ParseInvestigationSearchToolResultArtifact(artifactA, opA, bundleA, captureB.invocation, pinnedA, f.clock.Now()); err == nil {
		t.Fatal("equal naked result projection relabeled a foreign invocation under fixed expected association")
	}
	createA := pinnedA
	createA.ResultArtifactIdentity = ""
	if _, err := NewInvestigationSearchToolResultArtifact(opA, bundleA, captureB.invocation, createA, f.clock.Now()); err == nil {
		t.Fatal("constructor re-derived association from current arguments plus a foreign no-match result")
	}
}

func TestInvestigationToolOperationExcludesRelabelAndSearchOrderButBindsArguments(t *testing.T) {
	for _, tool := range []string{"snapshot.read", "snapshot.search"} {
		t.Run(tool, func(t *testing.T) {
			f := newToolRecordFixture(t, strings.TrimPrefix(tool, "snapshot."), false)
			refs := []string{f.file("notes.txt").Ref()}
			if tool == "snapshot.search" {
				refs = append(refs, f.file("a.go").Ref())
			}
			bundleA, expectedA, turnA, proposalA := f.dispatch(tool, "call-a", "absent", refs)
			opA := toolRecordOperation(t, bundleA, expectedA, proposalA, f.clock.Now())
			captureA, err := f.capture(f.ctx, opA, turnA)
			toolRecordCheck(t, err)
			value, result, _ := f.result(opA, bundleA, expectedA, proposalA, captureA)
			f.advance(value, result, turnA)
			slices.Reverse(refs)
			bundleB, expectedB, turnB, proposalB := f.dispatch(tool, "call-b", "absent", refs)
			before := len(f.store.gets)
			opB := toolRecordOperation(t, bundleB, expectedB, proposalB, f.clock.Now())
			if proposalA.Identity() == proposalB.Identity() || turnA.RequestIdentity() == turnB.RequestIdentity() || turnA.Dispatch().Response().Identity() == turnB.Dispatch().Response().Identity() || opA.Identity() != opB.Identity() || len(f.store.gets) != before {
				t.Fatal("operation replay identity included call/response/request/ordinal or input set order")
			}
			// No second reader call: deriving a replay key is not an atomic operation admission.
		})
	}
}

func TestInvestigationToolOperationRejectsForeignRefsAndResponseShapesBeforeReader(t *testing.T) {
	for _, shape := range []string{"foreign-file", "foreign-snapshot", "text", "multiple", "length"} {
		t.Run(shape, func(t *testing.T) {
			f := newToolRecordFixture(t, shape, false)
			f.model.shape = shape
			ref := f.file("notes.txt").Ref()
			if shape == "foreign-file" {
				ref = strings.Repeat("f", 64)
			}
			bundle, expected, _, _ := f.dispatch("snapshot.read", "bad-read", "", []string{ref})
			before := len(f.store.gets)
			if op, err := NewInvestigationToolOperation(bundle, expected, f.clock.Now()); err == nil || op.Identity() != "" || len(f.store.gets) != before {
				t.Fatal("foreign reference or unsupported actual response shape reached tool execution")
			}
		})
	}
}

func TestInvestigationToolResultRequiresEveryPinnedBindingAndProtectedWitness(t *testing.T) {
	f := newToolRecordFixture(t, "bindings", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.read", "read-a", "", []string{f.file("notes.txt").Ref()})
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	value, _, pinned := f.result(op, bundle, expected, proposal, captured)
	wrong := strings.Repeat("f", 64)
	for name, change := range map[string]func(*InvestigationToolExpectations){
		"session":            func(e *InvestigationToolExpectations) { e.SessionIdentity = wrong },
		"policy":             func(e *InvestigationToolExpectations) { e.PolicyIdentity = wrong },
		"owner":              func(e *InvestigationToolExpectations) { e.OwnerIdentity = wrong },
		"context artifact":   func(e *InvestigationToolExpectations) { e.ContextArtifactIdentity = wrong },
		"context":            func(e *InvestigationToolExpectations) { e.ContextIdentity = wrong },
		"request":            func(e *InvestigationToolExpectations) { e.RequestIdentity = wrong },
		"head artifact":      func(e *InvestigationToolExpectations) { e.HeadArtifactIdentity = wrong },
		"head snapshot":      func(e *InvestigationToolExpectations) { e.HeadSnapshotIdentity = wrong },
		"manifest":           func(e *InvestigationToolExpectations) { e.HeadManifestIdentity = wrong },
		"turn artifact":      func(e *InvestigationToolExpectations) { e.TurnArtifactIdentity = wrong },
		"turn":               func(e *InvestigationToolExpectations) { e.TurnIdentity = wrong },
		"previous":           func(e *InvestigationToolExpectations) { e.PreviousTurnIdentity = wrong },
		"outcome":            func(e *InvestigationToolExpectations) { e.OutcomeIdentity = wrong },
		"response":           func(e *InvestigationToolExpectations) { e.ResponseIdentity = wrong },
		"sources":            func(e *InvestigationToolExpectations) { e.SourceArtifactIdentities = []string{wrong} },
		"operation":          func(e *InvestigationToolExpectations) { e.OperationIdentity = wrong },
		"invocation":         func(e *InvestigationToolExpectations) { e.InvocationIdentity = wrong },
		"missing invocation": func(e *InvestigationToolExpectations) { e.InvocationIdentity = "" },
		"result":             func(e *InvestigationToolExpectations) { e.ResultArtifactIdentity = wrong },
		"missing scope":      func(e *InvestigationToolExpectations) { e.Scope = audit.ReviewScope{} },
		"deadline":           func(e *InvestigationToolExpectations) { e.Deadline = time.UnixMilli(999) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := pinned
			change(&changed)
			if parsed, err := ParseInvestigationReadToolResultArtifact(value, op, bundle, captured.invocation, changed, f.clock.Now()); err == nil || parsed.Identity() != "" {
				t.Fatal("result ignored an independently pinned expected binding")
			}
		})
	}
	for name, change := range map[string]func(*InvestigationToolEvidence){
		"missing context witness":  func(b *InvestigationToolEvidence) { b.Context = review.InvestigationGenerationContext{} },
		"missing policy":           func(b *InvestigationToolEvidence) { b.Policy = review.InvestigationPolicy{} },
		"missing context artifact": func(b *InvestigationToolEvidence) { b.ContextArtifact = artifact.Artifact{} },
		"missing head":             func(b *InvestigationToolEvidence) { b.HeadArtifact = artifact.Artifact{} },
		"missing turn":             func(b *InvestigationToolEvidence) { b.TurnArtifact = artifact.Artifact{} },
		"missing source artifacts": func(b *InvestigationToolEvidence) { b.SourceArtifacts = nil },
		"wrong limits":             func(b *InvestigationToolEvidence) { b.ReaderLimits.MaxMatches++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := bundle
			change(&changed)
			if _, err := ParseInvestigationReadToolResultArtifact(value, op, changed, captured.invocation, pinned, f.clock.Now()); err == nil {
				t.Fatal("result was rehydrated without its complete host-held witness")
			}
		})
	}
	if _, err := ParseInvestigationReadToolResultArtifact(value, op, bundle, InvestigationToolInvocation{}, pinned, f.clock.Now()); err == nil {
		t.Fatal("zero invocation became a successful reader witness")
	}
	if _, err := ParseInvestigationListToolResultArtifact(value, op, bundle, captured.invocation, pinned, f.clock.Now()); err == nil {
		t.Fatal("read invocation accepted through the list variant")
	}
	for _, at := range []time.Time{time.UnixMilli(99), time.UnixMilli(6000)} {
		if _, err := ParseInvestigationReadToolResultArtifact(value, op, bundle, captured.invocation, pinned, at); err == nil {
			t.Fatal("readback ignored protected lifetime or session deadline")
		}
	}
	for _, changedPayload := range [][]byte{[]byte(`{"identity":"forged"}`), bytes.Replace(value.Payload(), []byte("zero"), []byte("fake"), 1)} {
		changed, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), changedPayload, value.CreatedAt(), value.ExpiresAt())
		toolRecordCheck(t, err)
		if changed.Identity() == value.Identity() {
			t.Fatal("rehash mutation did not change protected bytes")
		}
		if _, err := ParseInvestigationReadToolResultArtifact(changed, op, bundle, captured.invocation, pinned, f.clock.Now()); err == nil {
			t.Fatal("rehashed caller artifact replaced the fixed trusted protected record")
		}
	}
}

func TestInvestigationToolCaptureRejectsZeroAndMismatchedAssociationMetadata(t *testing.T) {
	f := newToolRecordFixture(t, "capture", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.read", "read-a", "", []string{f.file("notes.txt").Ref()})
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	for _, mode := range []string{"zero operation", "zero turn", "zero ordinal", "ordinal limit", "limits", "source refs", "start", "time order", "deadline", "zero result"} {
		t.Run(mode, func(t *testing.T) {
			operation, owned, ordinal, limits, refs, start, finish, result := op, turn, captured.ordinal, f.limits, append([]string(nil), captured.sourceIDs...), captured.started, captured.finished, captured.slice
			switch mode {
			case "zero operation":
				operation = InvestigationToolOperation{}
			case "zero turn":
				owned = gateway.InvestigationTurnRecord{}
			case "zero ordinal":
				ordinal = 0
			case "ordinal limit":
				ordinal = f.policy.MaxToolCalls() + 1
			case "limits":
				limits.MaxFiles++
			case "source refs":
				refs = []string{f.file("a.go").ArtifactIdentity()}
			case "start":
				start = time.UnixMilli(999)
			case "time order":
				finish = start.Add(-time.Millisecond)
			case "deadline":
				finish = time.UnixMilli(6000)
			case "zero result":
				result = source.SnapshotSlice{}
			}
			if invocation, err := newInvestigationReadInvocation(operation, owned, ordinal, limits, refs, start, finish, result); err == nil || invocation.Identity() != "" {
				t.Fatal("invalid association metadata became held invocation")
			}
		})
	}
	if (InvestigationToolInvocation{}).Validate() == nil || (InvestigationToolOperation{}).Validate() == nil || (InvestigationToolResult{}).Validate() == nil {
		t.Fatal("zero pure record validated")
	}
	if encoded, err := EncodeInvestigationToolOperation(InvestigationToolOperation{}); err == nil || len(encoded) != 0 {
		t.Fatal("zero operation encoded")
	}
	if encoded, err := EncodeInvestigationToolResult(InvestigationToolResult{}); err == nil || len(encoded) != 0 {
		t.Fatal("zero result encoded")
	}
	for _, value := range []any{op, captured.invocation, InvestigationToolResult{}} {
		kind := reflect.TypeOf(value)
		for i := 0; i < kind.NumField(); i++ {
			if kind.Field(i).PkgPath == "" {
				t.Fatal("pure record exposes mutable successful-witness fields")
			}
		}
		for _, name := range []string{"Execute", "Dispatch", "Restore", "Settle", "Reset", "AcceptResponse", "SetResult"} {
			if _, ok := kind.MethodByName(name); ok {
				t.Fatal("pure record exposes execution or public successful-witness mutation")
			}
		}
	}
}

func TestInvestigationToolReaderFailureCancelAndExpiryLeaveNoInvocation(t *testing.T) {
	for _, mode := range []string{"canceled", "expired", "failed get", "canceled during get"} {
		t.Run(mode, func(t *testing.T) {
			f := newToolRecordFixture(t, strings.ReplaceAll(mode, " ", "-"), false)
			bundle, expected, turn, proposal := f.dispatch("snapshot.read", "read-a", "", []string{f.file("notes.txt").Ref()})
			op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			switch mode {
			case "canceled":
				cancel()
			case "expired":
				f.clock.at = time.UnixMilli(6000)
			case "failed get":
				f.store.failID = f.file("notes.txt").ArtifactIdentity()
			case "canceled during get":
				f.store.failID, f.store.cancel = f.file("notes.txt").ArtifactIdentity(), cancel
			}
			captured, err := f.capture(ctx, op, turn)
			if err == nil || captured.invocation.Identity() != "" {
				t.Fatal("unsuccessful actual reader path manufactured a completed invocation")
			}
			if mode == "canceled during get" && ctx.Err() == nil {
				t.Fatal("fixture did not cancel actual reader context")
			}
		})
	}
}

func TestInvestigationToolResultCountsWrapperNotOnlyReaderProjection(t *testing.T) {
	f := newToolRecordFixture(t, "projection-cap", true)
	bundle, expected, turn, proposal := f.dispatch("snapshot.list", "list-a", "", nil)
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	expected.OperationIdentity, expected.InvocationIdentity = op.Identity(), captured.invocation.Identity()
	if captured.serialized != f.policy.MaxResultBytes() {
		t.Fatal("fixture did not reach a reader-valid projection-sized cap")
	}
	if value, err := NewInvestigationListToolResultArtifact(op, bundle, captured.invocation, expected, f.clock.Now()); err == nil || value.Identity() != "" {
		t.Fatal("projection-sized limit ignored full result wrapper and annotation budget")
	}
	// This post-read refusal is not a pre-effect admission gate or a spending refund.
}

func TestInvestigationToolResultPayloadCanonicalBoundsAndRedaction(t *testing.T) {
	f := newToolRecordFixture(t, "canonical", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.list", "list-a", "", nil)
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	value, parsed, _ := f.result(op, bundle, expected, proposal, captured)
	payload := value.Payload()
	if err := validateInvestigationToolResultPayload(payload); err != nil {
		t.Fatal("valid canonical claims payload refused")
	}
	for name, raw := range map[string][]byte{
		"empty":           nil,
		"over cap":        bytes.Repeat([]byte{' '}, (64<<10)+1),
		"space":           append([]byte{' '}, payload...),
		"newline":         append(append([]byte(nil), payload...), '\n'),
		"duplicate":       bytes.Replace(payload, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"unknown":         append([]byte(`{"unknown":0,`), payload[1:]...),
		"self annotation": append([]byte(`{"artifact_identity":"`+value.Identity()+`",`), payload[1:]...),
		"null":            bytes.Replace(payload, []byte(`"sources":[]`), []byte(`"sources":null`), 1),
		"fraction":        bytes.Replace(payload, []byte(`"schema_version":1`), []byte(`"schema_version":1.0`), 1),
		"UTF8":            []byte{'{', '"', 0xff, '"', ':', '0', '}'},
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(raw, payload) {
				t.Fatal("malformed payload mutation missed")
			}
			if validateInvestigationToolResultPayload(raw) == nil {
				t.Fatal("claims-only preflight admitted malformed or noncanonical payload")
			}
		})
	}
	malformed := append([]byte(`{"private_tool_error_marker":0,`), payload[1:]...)
	parseErr := validateInvestigationToolResultPayload(malformed)
	if parseErr == nil {
		t.Fatal("unknown payload member did not refuse")
	}
	for _, value := range []any{op, captured.invocation, parsed, parseErr} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q", "%s"} {
			text := fmt.Sprintf(verb, value)
			for _, secret := range []string{expected.SessionIdentity, turn.Identity(), proposal.CallID(), f.file("notes.txt").Ref(), "notes.txt", "private_tool_error_marker"} {
				if strings.Contains(text, secret) {
					t.Fatal("formatting exposed tool record content or lineage")
				}
			}
		}
	}
}

func TestInvestigationToolReaderKeepsCallerDeadline(t *testing.T) {
	f := newToolRecordFixture(t, "deadline", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.read", "read-a", "", []string{f.file("notes.txt").Ref()})
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	ctx, cancel := context.WithDeadline(f.ctx, time.Now().Add(time.Minute))
	defer cancel()
	captured, err := f.capture(ctx, op, turn)
	toolRecordCheck(t, err)
	if captured.invocation.Identity() == "" {
		t.Fatal("successful bounded invocation was not captured")
	}
}

func TestInvestigationToolResultRejectsOtherActualProtectedBundle(t *testing.T) {
	f := newToolRecordFixture(t, "original", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.read", "read-a", "", []string{f.file("notes.txt").Ref()})
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	value, _, pinned := f.result(op, bundle, expected, proposal, captured)
	other := newToolRecordFixture(t, "foreign", false)
	foreign, _, _, _ := other.dispatch("snapshot.list", "list-foreign", "", nil)
	for _, part := range []string{"context", "context artifact", "head", "turn", "sources"} {
		t.Run(part, func(t *testing.T) {
			changed := bundle
			switch part {
			case "context":
				changed.Context = foreign.Context
			case "context artifact":
				changed.ContextArtifact = foreign.ContextArtifact
			case "head":
				changed.HeadArtifact = foreign.HeadArtifact
			case "turn":
				changed.TurnArtifact = foreign.TurnArtifact
			case "sources":
				changed.SourceArtifacts = append([]artifact.Artifact(nil), foreign.SourceArtifacts...)
			}
			if _, err := ParseInvestigationReadToolResultArtifact(value, op, changed, captured.invocation, pinned, f.clock.Now()); err == nil {
				t.Fatal("another actual source/model bundle replaced fixed protected evidence")
			}
		})
	}
}

func TestInvestigationToolResultClaimsValidatorRejectsRehashedInvalidShape(t *testing.T) {
	f := newToolRecordFixture(t, "claims", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.list", "list-a", "", nil)
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	value, _, _ := f.result(op, bundle, expected, proposal, captured)
	for _, mode := range []string{"unknown", "self annotation", "null sources", "files count", "call mismatch", "required missing"} {
		t.Run(mode, func(t *testing.T) {
			var claims map[string]json.RawMessage
			toolRecordCheck(t, json.Unmarshal(value.Payload(), &claims))
			switch mode {
			case "unknown":
				claims["unknown"] = json.RawMessage(`true`)
			case "self annotation":
				claims["artifact_identity"] = toolRecordJSON(t, value.Identity())
			case "null sources":
				claims["sources"] = json.RawMessage(`null`)
			case "files count":
				var files []json.RawMessage
				toolRecordCheck(t, json.Unmarshal(claims["files"], &files))
				oversized := make([]json.RawMessage, 65)
				for i := range oversized {
					oversized[i] = files[0]
				}
				claims["files"] = toolRecordJSON(t, oversized)
			case "call mismatch":
				claims["call_id"] = toolRecordJSON(t, "call-changed")
			case "required missing":
				delete(claims, "invocation_identity")
			}
			delete(claims, "identity")
			claims["identity"] = toolRecordJSON(t, toolRecordHash(toolRecordJSON(t, claims)))
			encoded := toolRecordJSON(t, claims)
			if len(encoded) > 64<<10 {
				t.Fatal("shape fixture only exercised outer size")
			}
			if validateInvestigationToolResultPayload(encoded) == nil {
				t.Fatal("claims preflight accepted rehashed invalid shape or repeated proposal binding")
			}
		})
	}
}

func TestInvestigationToolRecordConstructionUsesOnlyPriorStageExpectations(t *testing.T) {
	f := newToolRecordFixture(t, "stages", false)
	bundle, expected, turn, proposal := f.dispatch("snapshot.list", "list-a", "", nil)
	op := toolRecordOperation(t, bundle, expected, proposal, f.clock.Now())
	for _, field := range []string{"operation", "invocation", "result"} {
		changed := expected
		switch field {
		case "operation":
			changed.OperationIdentity = strings.Repeat("f", 64)
		case "invocation":
			changed.InvocationIdentity = strings.Repeat("f", 64)
		case "result":
			changed.ResultArtifactIdentity = strings.Repeat("f", 64)
		}
		if _, err := NewInvestigationToolOperation(bundle, changed, f.clock.Now()); err == nil {
			t.Fatal("operation constructor accepted a future-stage expected identity")
		}
	}
	captured, err := f.capture(f.ctx, op, turn)
	toolRecordCheck(t, err)
	_, _, pinned := f.result(op, bundle, expected, proposal, captured)
	if _, err := NewInvestigationListToolResultArtifact(op, bundle, captured.invocation, pinned, f.clock.Now()); err == nil {
		t.Fatal("result construction accepted its own future artifact identity")
	}
	pinned.ResultArtifactIdentity, pinned.InvocationIdentity = "", ""
	if _, err := NewInvestigationListToolResultArtifact(op, bundle, captured.invocation, pinned, f.clock.Now()); err == nil {
		t.Fatal("result construction did not require actual host-pinned invocation")
	}
}

func TestInvestigationToolOperationChangesWithExactReadAndSearchArguments(t *testing.T) {
	for _, mode := range []string{"range", "file", "search-set"} {
		t.Run(mode, func(t *testing.T) {
			f := newToolRecordFixture(t, mode, false)
			tool := "snapshot.read"
			if mode == "search-set" {
				tool = "snapshot.search"
			}
			refs := []string{f.file("notes.txt").Ref()}
			bundleA, expectedA, turnA, proposalA := f.dispatch(tool, "first", "absent", refs)
			opA := toolRecordOperation(t, bundleA, expectedA, proposalA, f.clock.Now())
			captured, err := f.capture(f.ctx, opA, turnA)
			toolRecordCheck(t, err)
			value, result, _ := f.result(opA, bundleA, expectedA, proposalA, captured)
			f.advance(value, result, turnA)
			switch mode {
			case "range":
				f.model.shape = "line-one"
			case "file":
				refs = []string{f.file("a.go").Ref()}
			case "search-set":
				refs = append(refs, f.file("a.go").Ref())
			}
			bundleB, expectedB, _, proposalB := f.dispatch(tool, "second", "absent", refs)
			opB := toolRecordOperation(t, bundleB, expectedB, proposalB, f.clock.Now())
			if expectedA.SessionIdentity != expectedB.SessionIdentity || expectedA.HeadArtifactIdentity != expectedB.HeadArtifactIdentity || opA.Identity() == opB.Identity() {
				t.Fatal("fixed-session operation identity ignored an exact tool argument")
			}
		})
	}
}
