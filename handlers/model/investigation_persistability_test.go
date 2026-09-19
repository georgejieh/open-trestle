package model_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	model "github.com/georgejieh/open-trestle/handlers/model"
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

const persistTurnRequestBoundary = 3488139
const persistBudget = uint64(1 << 40)

type persistStore struct {
	artifact.Store
	reads []string
}

func (s *persistStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.reads = append(s.reads, id)
	return s.Store.Get(ctx, scope, id, at)
}

func persistIDs(ids ...string) []string {
	result := append([]string{}, ids...)
	slices.Sort(result)
	return slices.Compact(result)
}

func persistClose(t *testing.T, close func(context.Context) error) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := close(ctx); err != nil {
			t.Error(err)
		}
	})
}

type persistModel struct {
	t                     *testing.T
	adapter, mode, target string
	store                 *persistStore
	ledger                audit.Ledger
	scope                 audit.ReviewScope
	calls                 []gateway.RouteDispatchRequest
	readCursor            int
}

func (m *persistModel) AdapterID() string             { return m.adapter }
func (m *persistModel) ConfigurationIdentity() string { return upperDigest([]byte(m.adapter)) }
func (m *persistModel) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	upperCheck(m.t, request.Validate())
	bound, sizeErr := gateway.EstimateInvestigationTurnPayloadBytes(uint64(len(request.Request().Payload())))
	if sizeErr != nil || bound > 16<<20 {
		m.t.Error("controller released an unpersistable actual request to the fake model")
	}
	events, err := m.ledger.Read(ctx, m.scope, 0, 100)
	upperCheck(m.t, err)
	claimed := false
	for _, event := range events {
		if event.Kind() == audit.EventRouteAttemptClaimed && event.SubjectIdentity() == request.Authorization().Identity() {
			claimed = true
		}
	}
	if !claimed {
		m.t.Fatal("fake external model preceded actual owner claim")
	}
	var packet upperPacket
	upperCheck(m.t, json.Unmarshal(request.Request().Payload(), &packet))
	m.calls = append(m.calls, request)
	if len(packet.Sources) == 0 {
		m.t.Fatal("fixture has no selected source")
	}
	var response any
	if packet.Task == "candidate_verification" {
		if m.adapter != "adapter-b" || packet.Schema != 3 || len(packet.Candidates) != 1 {
			m.t.Fatal("independent verifier fixture changed")
		}
		response = map[string]any{"schema_version": 1, "verdicts": []any{map[string]any{"candidate_id": packet.Candidates[0].ID, "outcome": "verified", "severity": "high", "rationale": "The fixture verifier accepts the cited selected source.", "evidence_ids": []string{packet.Sources[0].ID}}}}
	} else {
		if packet.Schema != 4 || packet.Investigation.Mode != "fixed_generation_route_v1" || packet.Investigation.Pin != request.Authorization().RouteRecordIdentity() {
			m.t.Fatal("actual generation request lost its fixed route")
		}
		if m.mode != "terminal" && packet.Investigation.Turn == 1 {
			call := map[string]any{"call_id": "persist-a", "tool": m.mode, "snapshot_ref": packet.Investigation.SnapshotRef}
			switch m.mode {
			case "snapshot.list":
			case "snapshot.read":
				call["file_ref"], call["start_line"], call["end_line"] = m.target, 2, 2
			case "search-hit", "search-miss":
				call["tool"], call["file_refs"], call["literal"] = "snapshot.search", []string{m.target}, "zero"
				if m.mode == "search-miss" {
					call["literal"] = "absent"
				}
			default:
				m.t.Fatal("unknown fake model mode")
			}
			response = map[string]any{"schema_version": 1, "tool_calls": []any{call}}
		} else {
			selected := packet.Sources[0]
			response = map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Selected change requires review", "claim": "The selected changed line requires review.", "severity_hint": "high", "source_range": map[string]any{"source_id": selected.ID, "start_line": selected.Start, "end_line": selected.Start}, "evidence_ids": []string{selected.ID}}}}
		}
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", upperJSON(m.t, response))
	upperCheck(m.t, err)
	usage, err := provider.NewRouteTokenUsage(100, 100, 0)
	upperCheck(m.t, err)
	normalized, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	upperCheck(m.t, err)
	result, err := gateway.NewSuccessfulRouteDispatchResult(normalized)
	upperCheck(m.t, err)
	m.readCursor = len(m.store.reads)
	return result
}

type persistFixtureData struct {
	t                        *testing.T
	options                  model.InvestigationOptions
	store                    *persistStore
	generation, verification *persistModel
	head                     artifact.Artifact
	snapshot                 source.Snapshot
	files                    []source.SnapshotFileRef
	current                  review.InvestigationGenerationContext
	binding                  review.InvestigationContextBinding
	request                  provider.Request
	bootstrap                uint64
}

func persistPolicy(t *testing.T, result, returned uint64) review.InvestigationPolicy {
	t.Helper()
	value, err := review.ParseInvestigationPolicy(upperJSON(t, map[string]any{
		"contract": "open-trestle/investigation-policy", "schema_version": 1, "profile": "snapshot-read-v1",
		"max_cost_micro_usd": persistBudget, "max_files": 64, "max_lines_per_read": 256, "max_matches": 1,
		"max_model_turns": 5, "max_tool_calls": 3, "max_result_bytes": result, "max_returned_bytes": returned,
		"max_scanned_bytes": 16 << 20, "timeout_milliseconds": 900000,
	}))
	upperCheck(t, err)
	return value
}

func persistFixture(t *testing.T, mode string, fileCount, ranges, angles int, result, returned uint64) *persistFixtureData {
	t.Helper()
	f := &persistFixtureData{t: t}
	ctx, clock := context.Background(), upperClock{}
	scope, err := audit.NewReviewScope("persist-tenant", "persist-repo", "persist-run")
	upperCheck(t, err)
	backing, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 256)
	upperCheck(t, err)
	f.store = &persistStore{Store: backing}
	ledger := audit.NewMemoryLedger()
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "repo")
	upperCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	upperCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "persist-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	upperCheck(t, err)
	contents := map[string][]byte{}
	if ranges > 1 {
		for i := 0; i < fileCount; i++ {
			contents["d/"+strings.Repeat("p", 120)+fmt.Sprintf("/f%02d.txt", i)] = []byte(strings.Repeat(strings.Repeat("<", angles)+"\n", ranges) + strings.Repeat("x\n", 512))
		}
	} else {
		contents["a.go"], contents["notes.txt"] = []byte(upperInitial), []byte(upperNotes)
		for i := 2; i < fileCount; i++ {
			contents[fmt.Sprintf("z%02d.txt", i)] = []byte("unused\n")
		}
	}
	entries := []evidence.RepositoryFile{}
	for path, content := range contents {
		file, err := evidence.NewRepositoryFile(path, content)
		upperCheck(t, err)
		entries = append(entries, file)
	}
	manifest, err := evidence.NewRepositoryManifest(entries)
	upperCheck(t, err)
	external := &upperSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}}
	handler, err := model.NewInvestigationAcquisitionHandler(f.store, external, clock)
	upperCheck(t, err)
	persistClose(t, handler.Close)
	input, err := source.NewInput(repository, revision, adapter)
	upperCheck(t, err)
	inputArtifact, err := source.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{upperDigest([]byte("host-input"))}, time.UnixMilli(100), time.UnixMilli(1000000))
	upperCheck(t, err)
	_, err = f.store.Put(ctx, inputArtifact, time.UnixMilli(100))
	upperCheck(t, err)
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputArtifact.Identity(), handler.HandlerIdentity(), nil, 1, 0, 30000, true)
	upperCheck(t, err)
	plan, err := controlplane.NewReviewRunPlan(scope, upperDigest([]byte("request")), upperDigest([]byte("review-policy")), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	upperCheck(t, err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	upperCheck(t, err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	upperCheck(t, err)
	_, err = coordinator.Advance(ctx, plan, time.UnixMilli(101))
	upperCheck(t, err)
	lease, acquired, err := coordinator.ClaimTask(ctx, plan, "source", handler.HandlerIdentity(), "fixture-worker", time.UnixMilli(102))
	upperCheck(t, err)
	if !acquired {
		t.Fatal("source task was not claimed")
	}
	execution, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	upperCheck(t, err)
	completion := handler.Execute(ctx, execution)
	if completion.Status() != controlplane.TaskCompletionSucceeded || external.calls != 1 {
		t.Fatal("real acquisition handler did not acquire source")
	}
	_, err = coordinator.CompleteTask(ctx, plan, lease, completion, clock.Now())
	upperCheck(t, err)
	f.head, err = f.store.Get(ctx, scope, completion.OutputIdentity(), clock.Now())
	upperCheck(t, err)
	f.snapshot, err = source.ParseSnapshotArtifact(f.head)
	upperCheck(t, err)
	acquisition, err := handler.Acquisition(ctx, plan, f.head.Identity())
	upperCheck(t, err)
	reader, err := source.NewSnapshotReader(ctx, f.store, clock, scope, f.head.Identity(), f.snapshot.Identity(), source.SnapshotReadLimits{MaxFiles: 64, MaxLines: 256, MaxResultBytes: 65536, MaxMatches: 1, MaxScannedBytes: 16 << 20})
	upperCheck(t, err)
	listing, err := reader.List(ctx)
	upperCheck(t, err)
	f.files = listing.Files()
	if len(f.files) != fileCount || listing.SerializedBytes() > 65536 {
		t.Fatal("fixture listing is not within reader limits")
	}
	selected := []review.ContextSource{}
	spans := []evidence.SourceRange{}
	for _, file := range f.files {
		if ranges == 1 && file.Path() != "a.go" {
			continue
		}
		for n := 1; n <= ranges; n++ {
			line := n
			if ranges == 1 {
				line = 2
			}
			physical, err := reader.Read(ctx, file.Ref(), line, line)
			upperCheck(t, err)
			if physical.SerializedBytes() > 65536 || file.SizeBytes() > 10<<20 {
				t.Fatal("initial reader projection or file exceeds its existing limit")
			}
			f.bootstrap += physical.ScannedBytes()
			binding := physical.Binding()
			item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), binding.SourceRange())
			upperCheck(t, err)
			bound, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, physical.Content(), binding)
			upperCheck(t, err)
			selected = append(selected, bound)
			spans = append(spans, binding.SourceRange())
		}
	}
	selectedSnapshot, err := review.NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, spans)
	upperCheck(t, err)
	memoryScope, err := memory.NewScope(scope.TenantID(), scope.RepositoryID(), "reviewer", memory.RefVisibilityExact, upperDigest([]byte("review-policy")), []string{"."})
	upperCheck(t, err)
	query, err := memory.NewLexicalQuery(memoryScope, "source", nil, nil, clock.Now(), 1)
	upperCheck(t, err)
	retrieval, err := memory.NewLexicalIndex().Search(ctx, memoryScope, query)
	upperCheck(t, err)
	contextLimits, err := review.NewContextLimits(2<<20, 0)
	upperCheck(t, err)
	// Omission rows describe real unselected lines as explicit host fixture input.
	omissions := []review.ContextSourceOmission{}
	if ranges > 1 {
		for _, file := range f.files {
			for line := ranges + 1; line <= ranges+512; line++ {
				omission, err := review.NewContextSourceOmission(file.Path(), line, line, "candidate_limit")
				upperCheck(t, err)
				omissions = append(omissions, omission)
			}
		}
	}
	packet, err := review.NewContextPacketWithAccounting(scope, memoryScope, selectedSnapshot, review.ContextTaskCandidateGeneration, selected, []memory.LexicalRetrieval{retrieval}, omissions, contextLimits)
	upperCheck(t, err)
	if packet.SourceCount() != len(selected) || len(packet.SourceOmissions()) != len(omissions) {
		t.Fatal("fixture silently dropped selected ranges or explicit host omission accounting")
	}
	routes := []map[string]any{}
	for _, name := range []string{"a", "b"} {
		routes = append(routes, map[string]any{"zone": "local", "provider_id": "provider-" + name, "adapter_id": "adapter-" + name, "connection_id": "connection-" + name, "model_id": "model-" + name, "model_version": "1", "max_context_tokens": 1 << 30, "max_output_tokens": 4096, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 1000000, "output_micro_usd_per_million_tokens": 1000000, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte("approved fixture route")), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": true, "p95_latency_milliseconds": 10, "latency_sample_count": 20})
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(ctx, bytes.NewReader(upperJSON(t, map[string]any{"schema_version": 1, "routes": routes})))
	upperCheck(t, err)
	var generation, verification gateway.ObservedRouteCandidate
	for _, route := range inventory.Candidates() {
		if route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generation = route
		} else {
			verification = route
		}
	}
	f.generation = &persistModel{t: t, adapter: "adapter-a", mode: mode, store: f.store, ledger: ledger, scope: scope}
	f.verification = &persistModel{t: t, adapter: "adapter-b", mode: "terminal", store: f.store, ledger: ledger, scope: scope}
	for _, file := range f.files {
		if file.Path() == "notes.txt" {
			f.generation.target = file.Ref()
		}
	}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{f.generation, f.verification})
	upperCheck(t, err)
	requirements, err := provider.NewModelRequirements(1, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	upperCheck(t, err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	upperCheck(t, err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	upperCheck(t, err)
	budget, err := provider.NewModelCostBudget(1, 4096, persistBudget)
	upperCheck(t, err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	upperCheck(t, err)
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	upperCheck(t, err)
	f.options = model.InvestigationOptions{Scope: scope, MemoryScope: memoryScope, SessionIdentity: upperDigest([]byte("persist-session")), Policy: persistPolicy(t, result, returned), Routing: model.InvestigationRoutingOptions{RegistryRevision: 1, PerformanceRevision: 1, Generation: generation, Verification: []gateway.ObservedRouteCandidate{verification}, Observations: inventory.PerformanceObservations(), VerificationRanking: ranking, Requirements: requirements, Constraints: constraints, Budget: budget, Independence: independence}, Catalog: catalog, Ledger: ledger, Clock: clock, Deadline: time.UnixMilli(601000), Store: f.store, Acquisition: acquisition, HeadSnapshotArtifactIdentity: f.head.Identity(), InitialContext: packet, InitialSnapshot: selectedSnapshot}
	f.rebuild()
	f.store.reads = nil
	return f
}

func (f *persistFixtureData) rebuild() {
	t, o := f.t, f.options
	claim := func(route gateway.ObservedRouteCandidate) review.InvestigationRouteContextClaim {
		return review.InvestigationRouteContextClaim{Record: route.ResolvedRecord().RouteRegistryRecord(), ManifestSizeBytes: route.ResolvedRecord().EvidenceManifestSizeBytes(), Operational: route.OperationalState()}
	}
	verification := []review.InvestigationRouteContextClaim{}
	for _, route := range o.Routing.Verification {
		verification = append(verification, claim(route))
	}
	var err error
	f.binding, err = review.NewInvestigationContextBinding(review.InvestigationContextBindingOptions{Scope: o.Scope, HostSessionIdentity: o.SessionIdentity, Policy: o.Policy, HeadSnapshotArtifactIdentity: f.head.Identity(), HeadSnapshotIdentity: f.snapshot.Identity(), HeadManifestIdentity: f.snapshot.ManifestIdentity(), HeadRevisionIdentity: f.snapshot.RevisionIdentity(), InitialContext: o.InitialContext, InitialSnapshot: o.InitialSnapshot, Deadline: o.Deadline, Routing: review.InvestigationContextRouting{RegistryRevision: o.Routing.RegistryRevision, PerformanceRevision: o.Routing.PerformanceRevision, Generation: claim(o.Routing.Generation), Verification: verification, Performance: o.Routing.Observations, Requirements: o.Routing.Requirements, Constraints: o.Routing.Constraints, Budget: o.Routing.Budget, VerificationRanking: o.Routing.VerificationRanking, Independence: o.Routing.Independence, CatalogIdentity: o.Catalog.Identity()}})
	upperCheck(t, err)
	f.current, err = review.NewInvestigationGenerationContext(f.binding, o.InitialContext, o.InitialSnapshot, review.InvestigationContextState{Turn: 1, ScannedBytes: f.bootstrap})
	upperCheck(t, err)
	f.request, err = f.current.ProviderRequest()
	upperCheck(t, err)
	if len(f.request.Payload()) > 8<<20 || f.bootstrap > o.Policy.MaxScannedBytes() {
		t.Fatal("fixture context or repeated bootstrap scans exceed existing bounds")
	}
}

func (f *persistFixtureData) preflight() {
	t, o := f.t, f.options
	budget, err := provider.NewModelCostBudget(uint64(len(f.request.Payload()))+256, 4096, o.Routing.Budget.MaxCostMicroUSD())
	upperCheck(t, err)
	input, err := gateway.NewReviewRoutingInput(o.Scope, f.request, o.Routing.Requirements, o.Routing.Constraints)
	upperCheck(t, err)
	eligible, err := gateway.FilterEligibleRoutes(input, budget, o.Routing.RegistryRevision, []gateway.ObservedRouteCandidate{o.Routing.Generation})
	upperCheck(t, err)
	pin, err := gateway.NewPinnedRouteRankingPolicy(o.Routing.Generation.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	upperCheck(t, err)
	observations := []provider.RoutePerformanceObservation{}
	for _, observation := range o.Routing.Observations {
		if observation.RecordIdentity() == o.Routing.Generation.ResolvedRecord().RouteRegistryRecord().Identity() {
			observations = append(observations, observation)
		}
	}
	ranked, err := gateway.RankEligibleRoutes(eligible, pin, o.Routing.PerformanceRevision, observations)
	upperCheck(t, err)
	selection, err := gateway.NewRouteSelectionReceipt(eligible, ranked)
	upperCheck(t, err)
	authorization, err := gateway.NewInitialRouteAttemptAuthorization(f.request, selection, ranked)
	upperCheck(t, err)
	upperCheck(t, gateway.VerifyIndependentRouteCandidate(o.Routing.Independence, authorization, o.Routing.Verification[0]))
	events, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
	upperCheck(t, err)
	if len(events) != 0 || len(f.generation.calls) != 0 || len(f.verification.calls) != 0 {
		t.Fatal("pure preflight created a model effect or ledger event")
	}
}

func (f *persistFixtureData) readerGets(start int) (int, int) {
	head, files := 0, 0
	for _, id := range f.store.reads[start:] {
		if id == f.head.Identity() {
			head++
		}
		for _, file := range f.files {
			if id == file.ArtifactIdentity() {
				files++
			}
		}
	}
	return head, files
}

func TestInvestigationPersistabilityInitialTurnGateUsesActualRequest(t *testing.T) {
	base := persistFixture(t, "terminal", 16, 2, 8000, 65536, 262144)
	baseBytes := len(base.request.Payload())
	if baseBytes >= persistTurnRequestBoundary {
		t.Fatal("baseline leaves no controlled escape-expansion interval")
	}
	angles := 8000 + (persistTurnRequestBoundary-baseBytes)/(6*32)
	if angles < 8000 || angles >= 9998 {
		t.Fatal("turn threshold crossed a fixture scalar-width or reader-projection boundary")
	}
	positive := persistFixture(t, "terminal", 16, 2, angles, 65536, 262144)
	negative := persistFixture(t, "terminal", 16, 2, angles+1, 65536, 262144)
	small, large := len(positive.request.Payload()), len(negative.request.Payload())
	if small > persistTurnRequestBoundary || large <= persistTurnRequestBoundary || large-small != 6*32 || persistTurnRequestBoundary-small >= 6*32 {
		t.Fatal("real context requests do not tightly straddle the accepted turn limit")
	}
	for _, f := range []*persistFixtureData{positive, negative} {
		f.preflight()
		if f.options.InitialContext.SourceCount() != 32 || len(f.options.InitialContext.SourceOmissions()) != 8192 {
			t.Fatal("selected-count or bounded host omission fixture changed")
		}
		referenceWork := uint64(f.head.PayloadSizeBytes())
		for _, file := range f.files {
			metadata := upperJSON(t, map[string]any{"contract": "open-trestle/source-file", "schema_version": 1, "acquisition_execution_identity": f.snapshot.AcquisitionExecutionIdentity(), "path": file.Path(), "digest": file.Digest(), "size_bytes": file.SizeBytes(), "content": ""})
			referenceWork += 2 * uint64(len(metadata)+base64.StdEncoding.EncodedLen(file.SizeBytes()))
		}
		if referenceWork > 16<<20 {
			t.Fatal("turn fixture also exceeds retained source framing admission")
		}
		wantAngles := angles
		if f == negative {
			wantAngles++
		}
		if f.bootstrap != uint64(16*2*(2*(wantAngles+1)+512*2)) {
			t.Fatal("initial ranges lost repeated full-file scan accounting")
		}
	}
	admitted, err := model.NewInvestigation(context.Background(), positive.options)
	upperCheck(t, err)
	persistClose(t, admitted.Close)
	generation, err := admitted.Generate(context.Background())
	upperCheck(t, err)
	if len(positive.generation.calls) != 1 || generation.FinalTurn().RequestIdentity() != positive.request.Identity() || !bytes.Equal(positive.generation.calls[0].Request().Payload(), positive.request.Payload()) {
		t.Fatal("controller dispatched a different request than the measured/admitted one")
	}
	encoded, err := gateway.EncodeInvestigationTurnRecord(generation.FinalTurn())
	upperCheck(t, err)
	bound, err := gateway.EstimateInvestigationTurnPayloadBytes(uint64(small))
	upperCheck(t, err)
	if uint64(len(encoded)) > bound || bound > 16<<20 {
		t.Fatal("admitted actual turn exceeds retained payload bound")
	}
	refused, err := model.NewInvestigation(context.Background(), negative.options)
	if err == nil {
		persistClose(t, refused.Close)
		step, stepErr := refused.Step(context.Background())
		if stepErr == nil || step.NextRequest().Identity() != "" {
			t.Fatal("oversize actual initial request retained next authority")
		}
		if _, generateErr := refused.Generate(context.Background()); generateErr == nil {
			t.Fatal("Generate bypassed the same size refusal")
		}
	} else if refused != nil {
		t.Fatal("refused constructor exposed a controller")
	}
	events, err := negative.options.Ledger.Read(context.Background(), negative.options.Scope, 0, 100)
	upperCheck(t, err)
	if len(events) != 0 || len(negative.generation.calls) != 0 || len(negative.verification.calls) != 0 {
		t.Fatal("oversize turn selected, claimed or dispatched before storage admission")
	}
}

type persistSizing struct {
	operation                     model.InvestigationToolOperation
	bundle                        model.InvestigationToolEvidence
	expected                      model.InvestigationToolExpectations
	payload, envelope, provenance uint64
}

func (f *persistFixtureData) operation(contextArtifact, turnArtifact artifact.Artifact) persistSizing {
	t, o := f.t, f.options
	turn, err := gateway.ParseInvestigationTurnRecord(turnArtifact.Payload())
	upperCheck(t, err)
	var header struct {
		Owner string `json:"owner_identity"`
	}
	upperCheck(t, json.Unmarshal(turnArtifact.Payload(), &header))
	ids := []string{}
	sources := []artifact.Artifact{}
	for _, file := range f.files {
		value, err := f.store.Get(context.Background(), o.Scope, file.ArtifactIdentity(), o.Clock.Now())
		upperCheck(t, err)
		ids = append(ids, value.Identity())
		sources = append(sources, value)
	}
	ids = persistIDs(ids...)
	bundle := model.InvestigationToolEvidence{Policy: o.Policy, ReaderLimits: source.SnapshotReadLimits{MaxFiles: int(o.Policy.MaxFiles()), MaxLines: int(o.Policy.MaxLinesPerRead()), MaxResultBytes: int(o.Policy.MaxResultBytes()), MaxMatches: int(o.Policy.MaxMatches()), MaxScannedBytes: o.Policy.MaxScannedBytes()}, Context: f.current, ContextArtifact: contextArtifact, HeadArtifact: f.head, TurnArtifact: turnArtifact, SourceArtifacts: sources}
	expected := model.InvestigationToolExpectations{Scope: o.Scope, Deadline: o.Deadline, SessionIdentity: f.binding.Identity(), PolicyIdentity: o.Policy.Identity(), OwnerIdentity: header.Owner, ContextArtifactIdentity: contextArtifact.Identity(), ContextIdentity: f.current.Identity(), RequestIdentity: f.request.Identity(), HeadArtifactIdentity: f.head.Identity(), HeadSnapshotIdentity: f.snapshot.Identity(), HeadManifestIdentity: f.snapshot.ManifestIdentity(), TurnArtifactIdentity: turnArtifact.Identity(), TurnIdentity: turn.Identity(), PreviousTurnIdentity: turn.PreviousTurnIdentity(), OutcomeIdentity: turn.Outcome().Identity(), ResponseIdentity: turn.Dispatch().Response().Identity(), SourceArtifactIdentities: ids}
	operation, err := model.NewInvestigationToolOperation(bundle, expected, o.Clock.Now())
	upperCheck(t, err)
	before := len(f.store.reads)
	calls := len(f.generation.calls) + len(f.verification.calls)
	beforeEvents, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
	upperCheck(t, err)
	payload, envelope, provenance, err := model.EstimateInvestigationToolResultArtifactBytes(operation)
	upperCheck(t, err)
	afterEvents, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
	upperCheck(t, err)
	if len(f.store.reads) != before || len(f.generation.calls)+len(f.verification.calls) != calls || !slices.EqualFunc(beforeEvents, afterEvents, func(a, b audit.Event) bool { return a.Identity() == b.Identity() }) {
		t.Fatal("pure tool estimator performed a source/model/ledger effect")
	}
	if payload == 0 || envelope <= payload {
		t.Fatal("estimator lost complete raw/envelope distinction")
	}
	return persistSizing{operation, bundle, expected, payload, envelope, provenance}
}

// Calibration dispatches a real owner on a separate ledger, never seeds the controller.
func (f *persistFixtureData) calibrate() persistSizing {
	t, o := f.t, f.options
	ledger := audit.NewMemoryLedger()
	generation := &persistModel{t: t, adapter: "adapter-a", mode: f.generation.mode, target: f.generation.target, store: f.store, ledger: ledger, scope: o.Scope}
	verification := &persistModel{t: t, adapter: "adapter-b", mode: "terminal", store: f.store, ledger: ledger, scope: o.Scope}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{generation, verification})
	upperCheck(t, err)
	makePlan := func(routes []gateway.ObservedRouteCandidate, ranking gateway.RouteRankingPolicy) gateway.InvestigationRoutePlan {
		observations := []provider.RoutePerformanceObservation{}
		for _, route := range routes {
			for _, obs := range o.Routing.Observations {
				if obs.RecordIdentity() == route.ResolvedRecord().RouteRegistryRecord().Identity() {
					observations = append(observations, obs)
				}
			}
		}
		plan, err := gateway.NewInvestigationRoutePlan(o.Routing.RegistryRevision, routes, ranking, o.Routing.PerformanceRevision, observations)
		upperCheck(t, err)
		return plan
	}
	pin, err := gateway.NewPinnedRouteRankingPolicy(o.Routing.Generation.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	upperCheck(t, err)
	owner, err := gateway.NewInvestigationRouteOwner(gateway.InvestigationRouteOwnerOptions{Scope: o.Scope, SessionIdentity: f.binding.Identity(), PolicyIdentity: o.Policy.Identity(), Deadline: o.Deadline, MaxTurns: uint8(o.Policy.MaxModelTurns()), Budget: o.Routing.Budget, Requirements: o.Routing.Requirements, Constraints: o.Routing.Constraints, Generation: makePlan([]gateway.ObservedRouteCandidate{o.Routing.Generation}, pin), Verification: makePlan(o.Routing.Verification, o.Routing.VerificationRanking), Catalog: catalog, Ledger: ledger, Clock: o.Clock})
	upperCheck(t, err)
	turn, err := owner.Dispatch(context.Background(), gateway.InvestigationGenerationTurn, f.request)
	upperCheck(t, err)
	if len(generation.calls) != 1 || turn.Validate() != nil || turn.RequestIdentity() != f.request.Identity() {
		t.Fatal("calibration did not obtain an actual owned turn")
	}
	contextArtifact, err := artifact.New(o.Scope, artifact.KindContextPacket, "application/json", f.head.Classification(), artifact.OriginHost, f.head.Protection(), []string{f.head.Identity()}, f.request.Payload(), o.Clock.Now(), o.Deadline)
	upperCheck(t, err)
	encoded, err := gateway.EncodeInvestigationTurnRecord(turn)
	upperCheck(t, err)
	turnArtifact, err := artifact.New(o.Scope, artifact.KindInvestigationTurn, "application/json", f.head.Classification(), artifact.OriginHost, f.head.Protection(), persistIDs(f.head.Identity(), contextArtifact.Identity(), turn.Identity(), turn.Outcome().Identity(), turn.Dispatch().Response().Identity()), encoded, o.Clock.Now(), o.Deadline)
	upperCheck(t, err)
	result := f.operation(contextArtifact, turnArtifact)
	events, err := o.Ledger.Read(context.Background(), o.Scope, 0, 100)
	upperCheck(t, err)
	if len(events) != 0 || len(f.generation.calls) != 0 || len(f.verification.calls) != 0 {
		t.Fatal("calibration seeded controller authority or effects")
	}
	return result
}

func persistSelected(f *persistFixtureData, operation model.InvestigationToolOperation) []source.SnapshotFileRef {
	selected := []source.SnapshotFileRef{}
	for _, file := range f.files {
		if operation.Tool() == "snapshot.list" || operation.FileRef() == file.Ref() || slices.Contains(operation.FileRefs(), file.Ref()) {
			selected = append(selected, file)
		}
	}
	return selected
}

func persistProvenance(f *persistFixtureData, sizing persistSizing) []string {
	e := sizing.expected
	ids := []string{e.HeadArtifactIdentity, sizing.operation.Identity(), e.TurnIdentity, e.ResponseIdentity, e.ContextArtifactIdentity, e.TurnArtifactIdentity}
	for _, file := range persistSelected(f, sizing.operation) {
		ids = append(ids, file.ArtifactIdentity())
	}
	return persistIDs(ids...)
}

// Count accepted wire fields independently; this creates no result or invocation value.
func persistIndependentPayloadUpper(t *testing.T, f *persistFixtureData, sizing persistSizing, value artifact.Artifact) uint64 {
	t.Helper()
	var fields map[string]json.RawMessage
	upperCheck(t, json.Unmarshal(value.Payload(), &fields))
	if len(fields) != 36 {
		t.Fatal("complete tool-result wire field set changed")
	}
	quoted := func(text string) uint64 { return uint64(len(upperJSON(t, text))) }
	size := uint64(2 + len(fields) - 1)
	for key, raw := range fields {
		size += quoted(key) + 1
		switch key {
		case "reader_serialized_bytes":
			size += uint64(len(strconv.FormatUint(f.options.Policy.MaxResultBytes(), 10)))
		case "sources":
			if sizing.operation.Tool() == "snapshot.list" {
				size += 2
				continue
			}
			selected := persistSelected(f, sizing.operation)
			if len(selected) != 1 || f.options.Policy.MaxMatches() != 1 {
				t.Fatal("independent single-file/single-match oracle fixture changed")
			}
			file := selected[0]
			start, end := sizing.operation.StartLine(), sizing.operation.EndLine()
			if sizing.operation.Tool() == "snapshot.search" {
				start, end = 1000000, 1000000
			}
			lengths := map[string]uint64{
				"binding_identity": 66, "content": 2 + 6*uint64(file.SizeBytes()), "end_line": uint64(len(strconv.Itoa(end))),
				"file_ref": quoted(file.Ref()), "path": quoted(file.Path()), "repository_file_digest": 66, "repository_file_identity": 66,
				"slice_bytes": uint64(len(strconv.Itoa(file.SizeBytes()))), "slice_digest": 66, "start_line": uint64(len(strconv.Itoa(start))),
			}
			row := uint64(2 + len(lengths) - 1)
			for name, length := range lengths {
				row += quoted(name) + 1 + length
			}
			size += 2 + row
		default:
			size += uint64(len(raw))
		}
	}
	return size
}

func persistCheckActualTool(t *testing.T, f *persistFixtureData, value artifact.Artifact, sizing persistSizing, returned uint64) {
	t.Helper()
	encoded, err := artifact.Encode(value)
	upperCheck(t, err)
	payload := value.Payload()
	if value.Kind() != artifact.KindInvestigationToolResult || value.Origin() != artifact.OriginDeterministicTool || uint64(len(payload)) > sizing.payload || uint64(len(encoded)) > sizing.envelope || returned != uint64(len(encoded)) {
		t.Fatal("actual protected result is not bounded/charged as a complete envelope")
	}
	var envelope map[string]json.RawMessage
	upperCheck(t, json.Unmarshal(encoded, &envelope))
	metadata := 2 + len(envelope) - 1
	for key, raw := range envelope {
		metadata += len(upperJSON(t, key)) + 1
		if key == "payload" {
			metadata += 2
		} else {
			metadata += len(raw)
		}
	}
	if metadata+base64.StdEncoding.EncodedLen(len(payload)) != len(encoded) {
		t.Fatal("independent artifact metadata/base64 arithmetic disagrees with actual encoding")
	}
	if sizing.envelope < uint64(metadata)+4*((sizing.payload+2)/3) {
		t.Fatal("reported full envelope does not even bound its raw payload with actual metadata")
	}
	if uint64(len(payload)) > persistIndependentPayloadUpper(t, f, sizing, value) {
		t.Fatal("independent known-file result bound undercounts actual wire bytes")
	}
	want := persistProvenance(f, sizing)
	if sizing.provenance != uint64(len(want)) || !slices.Equal(value.Provenance(), want) || len(want) > 32 {
		t.Fatal("estimator or result used the wrong exact provenance union")
	}
	var projection struct {
		Reader  uint64            `json:"reader_serialized_bytes"`
		Sources []json.RawMessage `json:"sources"`
	}
	upperCheck(t, json.Unmarshal(payload, &projection))
	if projection.Reader >= uint64(len(payload)) || projection.Reader >= returned {
		t.Fatal("fixture did not distinguish reader projection, complete payload and envelope")
	}
	if f.generation.mode == "search-miss" && len(projection.Sources) != 0 || f.generation.mode == "search-hit" && len(projection.Sources) != 1 {
		t.Fatal("actual positive/no-match search witness changed")
	}
}

func persistActualSizing(t *testing.T, f *persistFixtureData, result artifact.Artifact) persistSizing {
	t.Helper()
	var pins struct {
		Context string `json:"context_artifact_identity"`
		Turn    string `json:"turn_artifact_identity"`
	}
	upperCheck(t, json.Unmarshal(result.Payload(), &pins))
	contextArtifact, err := f.store.Get(context.Background(), f.options.Scope, pins.Context, f.options.Clock.Now())
	upperCheck(t, err)
	turnArtifact, err := f.store.Get(context.Background(), f.options.Scope, pins.Turn, f.options.Clock.Now())
	upperCheck(t, err)
	return f.operation(contextArtifact, turnArtifact)
}

func persistRefuseBeforeReader(t *testing.T, f *persistFixtureData) {
	t.Helper()
	f.preflight()
	f.store.reads = nil
	controller, err := model.NewInvestigation(context.Background(), f.options)
	if err != nil {
		if controller != nil || len(f.generation.calls) != 0 || len(f.verification.calls) != 0 {
			t.Fatal("constructor refusal exposed model authority")
		}
		events, readErr := f.options.Ledger.Read(context.Background(), f.options.Scope, 0, 100)
		upperCheck(t, readErr)
		if len(events) != 0 {
			t.Fatal("constructor size refusal selected or claimed a model")
		}
		for _, id := range f.store.reads {
			for _, file := range f.files {
				if file.Path() != "a.go" && id == file.ArtifactIdentity() {
					t.Fatal("refused constructor prefetched an unselected source")
				}
			}
		}
		return
	}
	persistClose(t, controller.Close)
	step, err := controller.Step(context.Background())
	if err == nil || step.NextRequest().Identity() != "" || step.ToolResultArtifactIdentity() != "" || len(f.generation.calls) != 1 || len(f.verification.calls) != 0 {
		t.Fatal("size refusal returned successful progression or extra model effects")
	}
	if !bytes.Equal(f.generation.calls[0].Request().Payload(), f.request.Payload()) {
		t.Fatal("refusal fixture dispatched a different request")
	}
	head, files := f.readerGets(f.generation.readCursor)
	if head != 0 || files != 0 {
		t.Fatal("full-result/provenance size refusal occurred after reader Get")
	}
	before := len(f.generation.calls)
	if _, err := controller.Generate(context.Background()); err == nil || len(f.generation.calls) != before {
		t.Fatal("failed size admission was refunded or retried by Generate")
	}
	if _, err := controller.Verify(context.Background()); err == nil || len(f.verification.calls) != 0 {
		t.Fatal("failed size admission exposed verifier authority")
	}
}

func TestInvestigationPersistabilityFullToolEnvelopeBeforeReader(t *testing.T) {
	var estimate func(model.InvestigationToolOperation) (uint64, uint64, uint64, error) = model.EstimateInvestigationToolResultArtifactBytes
	if _, _, _, err := estimate(model.InvestigationToolOperation{}); err == nil {
		t.Fatal("zero operation received a size bound")
	}
	for _, mode := range []string{"snapshot.list", "snapshot.read", "search-hit", "search-miss"} {
		t.Run(mode, func(t *testing.T) {
			positive := persistFixture(t, mode, 2, 1, 0, 8192, 262144)
			initial := positive.calibrate()
			if initial.payload > 8192 || initial.envelope > 262144 || initial.provenance > 32 {
				t.Fatal("small known-file operation has no useful admitted bound")
			}
			positive.options.Policy = persistPolicy(t, 8192, initial.envelope)
			positive.rebuild()
			own := positive.calibrate()
			if own.envelope != positive.options.Policy.MaxReturnedBytes() || own.payload > positive.options.Policy.MaxResultBytes() {
				t.Fatal("changed positive policy was not recalculated at its own conservative boundary")
			}
			positive.preflight()
			positive.store.reads = nil
			controller, err := model.NewInvestigation(context.Background(), positive.options)
			upperCheck(t, err)
			persistClose(t, controller.Close)
			first, err := controller.Step(context.Background())
			upperCheck(t, err)
			if len(positive.generation.calls) != 1 || !bytes.Equal(positive.generation.calls[0].Request().Payload(), positive.request.Payload()) || first.Turn().RequestIdentity() != positive.request.Identity() {
				t.Fatal("tool control did not dispatch the actual measured request")
			}
			head, files := positive.readerGets(positive.generation.readCursor)
			wantFiles := 1
			if mode == "snapshot.list" {
				wantFiles = 0
			}
			if head != 1 || files != wantFiles {
				t.Fatal("controller did not invoke exactly the real reader without prefetch/revalidation Gets")
			}
			wantScan := positive.bootstrap
			if mode != "snapshot.list" {
				wantScan += uint64(len(upperNotes))
			}
			if first.ScannedBytes() != wantScan {
				t.Fatal("listing/read/no-match reset or omitted actual full-file scans")
			}
			value, err := positive.store.Get(context.Background(), positive.options.Scope, first.ToolResultArtifactIdentity(), positive.options.Clock.Now())
			upperCheck(t, err)
			actual := persistActualSizing(t, positive, value)
			if actual.payload != own.payload || actual.envelope != own.envelope || actual.provenance != own.provenance {
				t.Fatal("calibration metadata did not match the actual controller operation bound")
			}
			persistCheckActualTool(t, positive, value, actual, first.ReturnedBytes())
			generation, err := controller.Generate(context.Background())
			upperCheck(t, err)
			if generation.FinalTurn().RequestIdentity() != first.NextRequest().Identity() || len(positive.generation.calls) != 2 {
				t.Fatal("Generate did not continue the admitted controller account")
			}
			verified, err := controller.Verify(context.Background())
			upperCheck(t, err)
			if len(positive.verification.calls) != 1 || verified.FinalTurn().Authorization().RemainingCostBeforeMicroUSD() != persistBudget-400 || verified.FinalTurn().Reconciliation().RemainingCostMicroUSD() != persistBudget-600 {
				t.Fatal("Verify reset the shared model budget")
			}
			negative := persistFixture(t, mode, 2, 1, 0, 8192, own.envelope-1)
			denied := negative.calibrate()
			if denied.envelope != own.envelope || denied.envelope <= negative.options.Policy.MaxReturnedBytes() || denied.payload > negative.options.Policy.MaxResultBytes() || denied.provenance > 32 {
				t.Fatal("negative policy does not isolate its own full-envelope bound one byte above cap")
			}
			persistRefuseBeforeReader(t, negative)
		})
	}
}

func TestInvestigationPersistabilityCompletePayloadIsNotReaderProjection(t *testing.T) {
	positive := persistFixture(t, "snapshot.read", 2, 1, 0, 8192, 262144)
	initial := positive.calibrate()
	positive.options.Policy = persistPolicy(t, initial.payload, 262144)
	positive.rebuild()
	own := positive.calibrate()
	if own.payload != positive.options.Policy.MaxResultBytes() || own.envelope > positive.options.Policy.MaxReturnedBytes() {
		t.Fatal("known-file raw boundary changed after coherent reader-limit recalculation")
	}
	positive.store.reads = nil
	controller, err := model.NewInvestigation(context.Background(), positive.options)
	upperCheck(t, err)
	persistClose(t, controller.Close)
	step, err := controller.Step(context.Background())
	upperCheck(t, err)
	value, err := positive.store.Get(context.Background(), positive.options.Scope, step.ToolResultArtifactIdentity(), positive.options.Clock.Now())
	upperCheck(t, err)
	actual := persistActualSizing(t, positive, value)
	persistCheckActualTool(t, positive, value, actual, step.ReturnedBytes())
	negative := persistFixture(t, "snapshot.read", 2, 1, 0, own.payload-1, 262144)
	denied := negative.calibrate()
	if denied.payload <= negative.options.Policy.MaxResultBytes() || denied.envelope > negative.options.Policy.MaxReturnedBytes() || denied.provenance > 32 {
		t.Fatal("negative raw-payload boundary did not isolate full wrapper overhead")
	}
	var projected struct {
		Reader uint64 `json:"reader_serialized_bytes"`
	}
	upperCheck(t, json.Unmarshal(value.Payload(), &projected))
	if projected.Reader >= negative.options.Policy.MaxResultBytes() {
		t.Fatal("negative fixture also violates the reader projection cap")
	}
	persistRefuseBeforeReader(t, negative)
}

func TestInvestigationPersistabilityProvenanceBeforeListingRefresh(t *testing.T) {
	for _, count := range []int{26, 27} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f := persistFixture(t, "snapshot.list", count, 1, 0, 65536, 262144)
			sizing := f.calibrate()
			if sizing.provenance != uint64(6+count) || sizing.provenance != uint64(len(persistProvenance(f, sizing))) || sizing.payload > 65536 || sizing.envelope > 262144 {
				t.Fatal("fixture does not isolate exact six-plus-selected provenance union")
			}
			if count == 27 {
				persistRefuseBeforeReader(t, f)
				return
			}
			f.store.reads = nil
			controller, err := model.NewInvestigation(context.Background(), f.options)
			upperCheck(t, err)
			persistClose(t, controller.Close)
			step, err := controller.Step(context.Background())
			upperCheck(t, err)
			head, files := f.readerGets(f.generation.readCursor)
			if head != 1 || files != 0 {
				t.Fatal("admitted listing performed full-file Gets or missed the real refresh")
			}
			value, err := f.store.Get(context.Background(), f.options.Scope, step.ToolResultArtifactIdentity(), f.options.Clock.Now())
			upperCheck(t, err)
			actual := persistActualSizing(t, f, value)
			persistCheckActualTool(t, f, value, actual, step.ReturnedBytes())
			if len(value.Provenance()) != 32 || step.ScannedBytes() != f.bootstrap {
				t.Fatal("positive provenance boundary is not an actual metadata-only listing")
			}
		})
	}
}
