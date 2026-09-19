package model_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	model "github.com/georgejieh/open-trestle/handlers/model"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	memory "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const upperNotes = "first\nzero<&>\nlast\n"
const upperInitial = "package p\nfunc Changed(x int) int { return 10 / x }\n"

type upperClock struct{}

func (upperClock) Now() time.Time { return time.UnixMilli(1000) }
func upperCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func upperDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func upperJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	upperCheck(t, err)
	return b
}

type upperSource struct {
	id     evidence.SourceAdapterIdentity
	result scm.SourceAdapterResult
	calls  int
}

func (s *upperSource) Identity() evidence.SourceAdapterIdentity { return s.id }
func (s *upperSource) Acquire(ctx context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.calls++
	return s.result
}

type upperStore struct {
	artifact.Store
	mu                     sync.Mutex
	gets                   []string
	sourceIDs              map[string]bool
	blockID                string
	ledger                 audit.Ledger
	scope                  audit.ReviewScope
	checkClaims            bool
	block                  bool
	entered, release       chan struct{}
	enterOnce, releaseOnce sync.Once
	t                      *testing.T
}

func (s *upperStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.mu.Lock()
	check, block := s.checkClaims, s.block
	s.gets = append(s.gets, id)
	s.mu.Unlock()
	if check && id == s.blockID {
		events, err := s.ledger.Read(ctx, s.scope, 0, 100)
		upperCheck(s.t, err)
		var outcome, claim audit.Event
		for _, e := range events {
			if e.Kind() == audit.EventRouteDispatchCompleted {
				outcome = e
			}
			if e.Kind().String() == "investigation_tool_claimed" {
				claim = e
			}
		}
		if outcome.Identity() == "" || claim.Identity() == "" || claim.Sequence() <= outcome.Sequence() || !slices.Contains(claim.CausalParentIdentities(), outcome.SubjectIdentity()) {
			s.t.Error("source read did not follow a claim bound to actual latest model outcome")
		}
	}
	if block && id == s.blockID {
		s.enterOnce.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return artifact.Artifact{}, ctx.Err()
		}
	}
	return s.Store.Get(ctx, scope, id, at)
}
func (s *upperStore) fileGets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, id := range s.gets {
		if s.sourceIDs[id] {
			n++
		}
	}
	return n
}
func (s *upperStore) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.block = true
	s.entered = make(chan struct{})
	s.release = make(chan struct{})
}
func (s *upperStore) unblock() { s.releaseOnce.Do(func() { close(s.release) }) }

type upperPacket struct {
	Schema            int    `json:"schema_version"`
	Task              string `json:"task"`
	GenerationContext string `json:"generation_context_identity"`
	Snapshot          string `json:"snapshot_identity"`
	Sources           []struct {
		ID      string `json:"source_id"`
		Path    string `json:"path"`
		Stage   string `json:"stage"`
		Start   int    `json:"start_line"`
		End     int    `json:"end_line"`
		Content string `json:"content"`
	} `json:"sources"`
	Candidates []struct {
		ID string `json:"candidate_id"`
	} `json:"candidates"`
	Investigation struct {
		Session         string `json:"session_identity"`
		Snapshot        string `json:"snapshot_identity"`
		SnapshotRef     string `json:"snapshot_ref"`
		Mode            string `json:"routing_mode"`
		Pin             string `json:"generation_route_record_identity"`
		Turn            int    `json:"turn"`
		PreviousRequest string `json:"previous_request_identity"`
		PreviousOutcome string `json:"previous_outcome_identity"`
		Results         []struct {
			Tool  string `json:"tool"`
			Files []struct {
				Ref  string `json:"ref"`
				Path string `json:"path"`
			} `json:"files"`
		} `json:"tool_results"`
	} `json:"investigation"`
}
type upperModel struct {
	mu      sync.Mutex
	config  string
	t       *testing.T
	adapter string
	mode    string
	calls   []gateway.RouteDispatchRequest
	packets []upperPacket
}

func (m *upperModel) AdapterID() string { return m.adapter }
func (m *upperModel) ConfigurationIdentity() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config != "" {
		return m.config
	}
	return upperDigest([]byte(m.adapter))
}
func (m *upperModel) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.calls) }
func (m *upperModel) DispatchRoute(ctx context.Context, r gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	upperCheck(m.t, r.Validate())
	var p upperPacket
	upperCheck(m.t, json.Unmarshal(r.Request().Payload(), &p))
	m.mu.Lock()
	m.calls = append(m.calls, r)
	m.packets = append(m.packets, p)
	m.mu.Unlock()
	var result any
	if p.Task == "candidate_verification" {
		if m.adapter != "adapter-b" || p.Schema != 3 || len(p.Candidates) != 1 {
			m.t.Fatal("verifier lost exact independent final candidate")
		}
		ids := []string{}
		for _, s := range p.Sources {
			ids = append(ids, s.ID)
		}
		result = map[string]any{"schema_version": 1, "verdicts": []any{map[string]any{"candidate_id": p.Candidates[0].ID, "outcome": "verified", "severity": "high", "rationale": "The unguarded division is enabled for zero requests by the cited source.", "evidence_ids": ids}}}
	} else {
		if p.Schema != 4 || p.Investigation.Mode != "fixed_generation_route_v1" || p.Investigation.Pin != r.Authorization().RouteRecordIdentity() {
			m.t.Fatal("generation did not bind explicit actual fixed route")
		}
		ref := ""
		for _, result := range p.Investigation.Results {
			for _, file := range result.Files {
				if file.Path == "notes.txt" {
					ref = file.Ref
				}
			}
		}
		allRefs := []string{}
		seenRefs := map[string]bool{}
		for _, result := range p.Investigation.Results {
			for _, file := range result.Files {
				if !seenRefs[file.Ref] {
					seenRefs[file.Ref] = true
					allRefs = append(allRefs, file.Ref)
				}
			}
		}
		slices.Sort(allRefs)
		call := map[string]any{"call_id": "list-a", "tool": "snapshot.list", "snapshot_ref": p.Investigation.SnapshotRef}
		switch p.Investigation.Turn {
		case 1:
			for _, s := range p.Sources {
				if s.Path == "notes.txt" {
					m.t.Fatal("target already selected before model request")
				}
			}
		case 2:
			if ref == "" {
				m.t.Fatal("model did not discover actual host file reference")
			}
			call = map[string]any{"call_id": "read-a", "tool": "snapshot.read", "snapshot_ref": p.Investigation.SnapshotRef, "file_ref": ref, "start_line": 2, "end_line": 2}
			if m.mode == "reorder" {
				call = map[string]any{"call_id": "search-a", "tool": "snapshot.search", "snapshot_ref": p.Investigation.SnapshotRef, "file_refs": allRefs, "literal": "absent"}
			}
			if m.mode == "forged ref" {
				call["file_ref"] = strings.Repeat("f", 64)
			}
		case 3:
			if m.mode == "reorder" {
				reversed := append([]string(nil), allRefs...)
				slices.Reverse(reversed)
				call = map[string]any{"call_id": "search-b", "tool": "snapshot.search", "snapshot_ref": p.Investigation.SnapshotRef, "file_refs": reversed, "literal": "absent"}
				break
			}
			if m.mode == "relabel" {
				call = map[string]any{"call_id": "read-b", "tool": "snapshot.read", "snapshot_ref": p.Investigation.SnapshotRef, "file_ref": ref, "start_line": 2, "end_line": 2}
				break
			}
			if m.mode == "scan" {
				call = map[string]any{"call_id": "read-b", "tool": "snapshot.read", "snapshot_ref": p.Investigation.SnapshotRef, "file_ref": ref, "start_line": 1, "end_line": 1}
				break
			}
			if m.mode == "no-match scan" {
				call = map[string]any{"call_id": "search-b", "tool": "snapshot.search", "snapshot_ref": p.Investigation.SnapshotRef, "file_refs": []string{ref}, "literal": "absent"}
				break
			}
			ids := []string{}
			changed := ""
			notes := false
			for _, s := range p.Sources {
				ids = append(ids, s.ID)
				if s.Path == "a.go" {
					changed = s.ID
				}
				if s.Path == "notes.txt" && s.Content == "zero<&>\n" && s.Stage == "repository_context" {
					notes = true
				}
			}
			if !notes || changed == "" || len(ids) != 2 {
				m.t.Fatal("bound new source did not reach candidate request")
			}
			result = map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Enabled zero requests divide by zero", "claim": "The unguarded division is reachable for zero-valued enabled requests.", "severity_hint": "high", "source_range": map[string]any{"source_id": changed, "start_line": 2, "end_line": 2}, "evidence_ids": ids}}}
		default:
			m.t.Fatal("unbounded generation turn")
		}
		if result == nil {
			result = map[string]any{"schema_version": 1, "tool_calls": []any{call}}
		}
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", upperJSON(m.t, result))
	upperCheck(m.t, err)
	usage, err := provider.NewRouteTokenUsage(100, 100, 0)
	upperCheck(m.t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	upperCheck(m.t, err)
	dispatch, err := gateway.NewSuccessfulRouteDispatchResult(response)
	upperCheck(m.t, err)
	return dispatch
}

func upperFixture(t *testing.T, mode string, generationCapacity ...uint64) (model.InvestigationOptions, *upperStore, *upperModel, *upperModel, source.Snapshot, uint64) {
	t.Helper()
	ctx := context.Background()
	clock := upperClock{}
	scope, err := audit.NewReviewScope("upper-tenant", "upper-repo", "upper-run")
	upperCheck(t, err)
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	upperCheck(t, err)
	ledger := audit.NewMemoryLedger()
	spy := &upperStore{Store: store, sourceIDs: map[string]bool{}, ledger: ledger, scope: scope, t: t}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"owner"}, "repo")
	upperCheck(t, err)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	upperCheck(t, err)
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "upper-fixture", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	upperCheck(t, err)
	contents := map[string][]byte{"a.go": []byte(upperInitial), "notes.txt": []byte(upperNotes)}
	if mode == "other source" {
		contents["a.go"] = []byte("package p\nfunc Changed(x int) int { return 1 }\n")
	}
	files := []evidence.RepositoryFile{}
	for name, b := range contents {
		file, err := evidence.NewRepositoryFile(name, b)
		upperCheck(t, err)
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	upperCheck(t, err)
	external := &upperSource{id: adapter, result: scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}}
	handler, err := model.NewInvestigationAcquisitionHandler(spy, external, clock)
	upperCheck(t, err)
	input, err := source.NewInput(repository, revision, adapter)
	upperCheck(t, err)
	inputArtifact, err := source.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{upperDigest([]byte("host-input"))}, time.UnixMilli(100), time.UnixMilli(100000))
	upperCheck(t, err)
	_, err = store.Put(ctx, inputArtifact, time.UnixMilli(100))
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
	lease, _, err := coordinator.ClaimTask(ctx, plan, "source", handler.HandlerIdentity(), "fixture-worker", time.UnixMilli(102))
	upperCheck(t, err)
	execution, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	upperCheck(t, err)
	completion := handler.Execute(ctx, execution)
	if completion.Status() != controlplane.TaskCompletionSucceeded || external.calls != 1 {
		t.Fatal("actual source handler did not acquire snapshot")
	}
	_, err = coordinator.CompleteTask(ctx, plan, lease, completion, clock.Now())
	upperCheck(t, err)
	headArtifact, err := store.Get(ctx, scope, completion.OutputIdentity(), clock.Now())
	upperCheck(t, err)
	head, err := source.ParseSnapshotArtifact(headArtifact)
	upperCheck(t, err)
	acquisition, err := handler.Acquisition(ctx, plan, headArtifact.Identity())
	upperCheck(t, err)
	reader, err := source.NewSnapshotReader(ctx, store, clock, scope, headArtifact.Identity(), head.Identity(), source.SnapshotReadLimits{MaxFiles: 2, MaxLines: 20, MaxScannedBytes: 65536, MaxResultBytes: 8192, MaxMatches: 8})
	upperCheck(t, err)
	listing, err := reader.List(ctx)
	upperCheck(t, err)
	var changed source.SnapshotSlice
	for _, ref := range listing.Files() {
		if ref.Path() == "a.go" {
			changed, err = reader.Read(ctx, ref.Ref(), 2, 2)
			upperCheck(t, err)
		}
		spy.sourceIDs[ref.ArtifactIdentity()] = true
		if ref.Path() == "notes.txt" {
			spy.blockID = ref.ArtifactIdentity()
		}
	}
	span := changed.Binding().SourceRange()
	item, err := evidence.NewEvidenceItem(changed.Binding().Identity(), evidence.EvidenceKindSource, changed.Binding().SliceDigest(), span)
	upperCheck(t, err)
	bound, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, changed.Content(), changed.Binding())
	upperCheck(t, err)
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, []evidence.SourceRange{span})
	upperCheck(t, err)
	memoryScope, err := memory.NewScope("upper-tenant", "upper-repo", "reviewer", memory.RefVisibilityExact, upperDigest([]byte("review-policy")), []string{"."})
	upperCheck(t, err)
	query, err := memory.NewLexicalQuery(memoryScope, "a.go", nil, nil, clock.Now(), 1)
	upperCheck(t, err)
	retrieval, err := memory.NewLexicalIndex().Search(ctx, memoryScope, query)
	upperCheck(t, err)
	limits, err := review.NewContextLimits(65536, 0)
	upperCheck(t, err)
	packet, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{bound}, retrieval, limits)
	upperCheck(t, err)
	policyBytes, err := os.ReadFile("../../internal/review/testdata/investigation-policy-v1.json")
	upperCheck(t, err)
	var policyWire map[string]any
	upperCheck(t, json.Unmarshal(policyBytes, &policyWire))
	if mode == "scan" || mode == "no-match scan" {
		policyWire["max_scanned_bytes"] = len(upperInitial) + 2*len(upperNotes) - 1
	}
	if mode == "envelope" {
		policyWire["max_returned_bytes"] = listing.SerializedBytes()
	}
	policyValue, err := review.ParseInvestigationPolicy(upperJSON(t, policyWire))
	upperCheck(t, err)
	routes := []map[string]any{}
	for _, name := range []string{"a", "b"} {
		routes = append(routes, map[string]any{"zone": "local", "provider_id": "provider-" + name, "adapter_id": "adapter-" + name, "connection_id": "connection-" + name, "model_id": "model-" + name, "model_version": "1", "max_context_tokens": 128000, "max_output_tokens": 4096, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 1000000, "output_micro_usd_per_million_tokens": 1000000, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte("approved fixture route")), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": true, "p95_latency_milliseconds": 10, "latency_sample_count": 20})
	}
	if mode == "non-independent" {
		routes[1]["provider_id"] = "provider-a"
	}
	if len(generationCapacity) == 1 {
		routes[0]["max_context_tokens"] = generationCapacity[0]
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
	a, b := &upperModel{t: t, adapter: "adapter-a", mode: mode}, &upperModel{t: t, adapter: "adapter-b", mode: mode}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{a, b})
	upperCheck(t, err)
	requirements, err := provider.NewModelRequirements(1, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	upperCheck(t, err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	upperCheck(t, err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	upperCheck(t, err)
	budget, err := provider.NewModelCostBudget(1, 4096, 100000)
	upperCheck(t, err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	upperCheck(t, err)
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	upperCheck(t, err)
	options := model.InvestigationOptions{Scope: scope, MemoryScope: memoryScope, SessionIdentity: upperDigest([]byte("upper-host-session")), Policy: policyValue, Routing: model.InvestigationRoutingOptions{RegistryRevision: inventory.RegistryRevision(), PerformanceRevision: inventory.PerformanceRevision(), Generation: generation, Verification: []gateway.ObservedRouteCandidate{verification}, Observations: inventory.PerformanceObservations(), VerificationRanking: ranking, Requirements: requirements, Constraints: constraints, Budget: budget, Independence: independence}, Catalog: catalog, Ledger: ledger, Clock: clock, Deadline: time.UnixMilli(10000), Store: spy, Acquisition: acquisition, HeadSnapshotArtifactIdentity: headArtifact.Identity(), InitialContext: packet, InitialSnapshot: snapshot}
	spy.gets = nil
	return options, spy, a, b, head, listing.SerializedBytes()
}

func TestInvestigationUpperReadsProtectedUnselectedSourceAndProjectsVerifier(t *testing.T) {
	options, store, a, b, head, projectionBytes := upperFixture(t, "")
	controller, err := model.NewInvestigation(context.Background(), options)
	upperCheck(t, err)
	for _, name := range []string{"Admit", "AcceptResponse", "Settle", "Restore"} {
		if _, ok := reflect.TypeOf(controller).MethodByName(name); ok {
			t.Fatal("controller accepts caller-owned response or accounting authority")
		}
	}
	first, err := controller.Step(context.Background())
	upperCheck(t, err)
	listArtifact, err := store.Get(context.Background(), options.Scope, first.ToolResultArtifactIdentity(), options.Clock.Now())
	upperCheck(t, err)
	encoded, err := artifact.Encode(listArtifact)
	upperCheck(t, err)
	if first.ReturnedBytes() != uint64(len(encoded)) || uint64(len(encoded)) <= projectionBytes {
		t.Fatal("account charged reader projection instead of complete protected envelope")
	}
	store.checkClaims = true
	second, err := controller.Step(context.Background())
	upperCheck(t, err)
	store.checkClaims = false
	if first.ScannedBytes() != uint64(len(upperInitial)) || second.ScannedBytes() != uint64(len(upperInitial)+len(upperNotes)) || first.Turn().RequestIdentity() == second.Turn().RequestIdentity() || second.NextRequest().Identity() == second.Turn().RequestIdentity() {
		t.Fatal("read reset scan accounting or reused successful model request")
	}
	var next upperPacket
	upperCheck(t, json.Unmarshal(second.NextRequest().Payload(), &next))
	if next.Investigation.PreviousRequest != second.Turn().RequestIdentity() || next.Investigation.PreviousOutcome != second.Turn().Outcome().Identity() || next.Investigation.Snapshot != head.Identity() {
		t.Fatal("fresh request lost actual outcome or fixed acquired head")
	}
	readArtifact, err := store.Get(context.Background(), options.Scope, second.ToolResultArtifactIdentity(), options.Clock.Now())
	upperCheck(t, err)
	var resultWire struct {
		Session   string `json:"session_identity"`
		Scope     string `json:"scope_identity"`
		Head      string `json:"snapshot_artifact_identity"`
		Snapshot  string `json:"snapshot_identity"`
		Turn      string `json:"turn_identity"`
		Response  string `json:"proposal_response_identity"`
		Operation string `json:"operation_identity"`
	}
	upperCheck(t, json.Unmarshal(readArtifact.Payload(), &resultWire))
	readEncoded, err := artifact.Encode(readArtifact)
	upperCheck(t, err)
	if second.ReturnedBytes() != uint64(len(encoded)+len(readEncoded)) {
		t.Fatal("second result reset cumulative full-envelope charge")
	}
	if readArtifact.Scope().Identity() != options.Scope.Identity() || readArtifact.Origin() != artifact.OriginDeterministicTool || resultWire.Session != next.Investigation.Session || resultWire.Scope != options.Scope.Identity() || resultWire.Head != options.HeadSnapshotArtifactIdentity || resultWire.Snapshot != head.Identity() || resultWire.Turn != second.Turn().Identity() || resultWire.Response != second.Turn().Dispatch().Response().Identity() || resultWire.Operation == "" {
		t.Fatal("tool result does not bind actual owned response and protected snapshot")
	}
	events, err := options.Ledger.Read(context.Background(), options.Scope, 0, 100)
	upperCheck(t, err)
	claimed, completed := 0, 0
	for _, event := range events {
		var want []string
		if event.Kind().String() == "investigation_tool_claimed" && event.SubjectIdentity() == resultWire.Operation {
			claimed++
			want = []string{resultWire.Session, options.HeadSnapshotArtifactIdentity, second.Turn().Identity(), second.Turn().Outcome().Identity(), resultWire.Response}
		}
		if event.Kind().String() == "investigation_tool_completed" && event.SubjectIdentity() == readArtifact.Identity() {
			completed++
			want = []string{resultWire.Operation, second.Turn().Identity(), options.HeadSnapshotArtifactIdentity}
		}
		if want != nil {
			slices.Sort(want)
			if !slices.Equal(event.CausalParentIdentities(), want) {
				t.Fatal("tool event has wrong exact causal parents")
			}
		}
	}
	if claimed != 1 || completed != 1 {
		t.Fatal("read lacks one actual operation claim/completion")
	}
	for _, id := range []string{options.HeadSnapshotArtifactIdentity, resultWire.Operation, second.Turn().Identity(), resultWire.Response} {
		if !slices.Contains(readArtifact.Provenance(), id) {
			t.Fatal("protected result omitted source/operation/model provenance")
		}
	}
	generation, err := controller.Generate(context.Background())
	upperCheck(t, err)
	if a.count() != 3 || generation.FinalTurn().RequestIdentity() != second.NextRequest().Identity() || generation.Snapshot().Identity() == options.InitialSnapshot.Identity() || len(generation.EvidenceItems()) != 2 {
		t.Fatal("final generation not bound to expanded selected ranges")
	}
	var finalInput struct {
		Schema          int    `json:"schema_version"`
		Context         string `json:"context_identity"`
		ContextArtifact string `json:"context_artifact_identity"`
	}
	upperCheck(t, json.Unmarshal(generation.InputArtifact().Payload(), &finalInput))
	var finalResult struct {
		Schema          int    `json:"schema_version"`
		Input           string `json:"input_artifact_identity"`
		Context         string `json:"context_identity"`
		ContextArtifact string `json:"context_artifact_identity"`
	}
	upperCheck(t, json.Unmarshal(generation.ResultArtifact().Payload(), &finalResult))
	if finalInput.Schema != 2 || finalResult.Schema != 2 || finalInput.Context != generation.ContextIdentity() || finalResult.Context != generation.ContextIdentity() || finalInput.ContextArtifact != generation.ContextArtifact().Identity() || finalResult.ContextArtifact != generation.ContextArtifact().Identity() || finalResult.Input != generation.InputArtifact().Identity() {
		t.Fatal("final artifact lineage points to initial or caller-invented generation")
	}
	if review.ValidateCandidateModelRequest(second.NextRequest(), options.Scope.Identity()) == nil {
		t.Fatal("legacy v3 gate silently granted v4 tools")
	}
	verified, err := controller.Verify(context.Background())
	upperCheck(t, err)
	if b.count() != 1 || b.packets[0].GenerationContext != generation.ContextIdentity() || verified.Context().Identity() == generation.ContextIdentity() || verified.IndependentReceipt().VerifiedCount() != 1 {
		t.Fatal("v4 generation did not reach actual independent v3 verifier")
	}
	if verified.FinalTurn().Authorization().RemainingCostBeforeMicroUSD() != 99400 || verified.FinalTurn().Reconciliation().RemainingCostMicroUSD() != 99200 {
		t.Fatal("verifier reset shared account after three successful model turns")
	}
	for _, call := range a.calls {
		if call.Authorization().RouteRecordIdentity() != options.Routing.Generation.ResolvedRecord().RouteRegistryRecord().Identity() {
			t.Fatal("generation silently rerouted")
		}
	}
	if _, err := controller.Verify(context.Background()); err == nil || b.count() != 1 {
		t.Fatal("final verification replayed")
	}
}
func TestInvestigationUpperRejectsRelabeledAndCumulativeScanBeforeFileGet(t *testing.T) {
	for _, mode := range []string{"relabel", "reorder", "scan", "no-match scan"} {
		t.Run(mode, func(t *testing.T) {
			options, store, a, b, _, _ := upperFixture(t, mode)
			controller, err := model.NewInvestigation(context.Background(), options)
			upperCheck(t, err)
			_, err = controller.Step(context.Background())
			upperCheck(t, err)
			_, err = controller.Step(context.Background())
			upperCheck(t, err)
			before := store.fileGets()
			step, err := controller.Step(context.Background())
			if err == nil || step.NextRequest().Identity() != "" || store.fileGets() != before || a.count() != 3 || b.count() != 0 {
				t.Fatal("duplicate or over-budget operation accessed source or exposed next authority")
			}
		})
	}
}
func TestInvestigationUpperFullEnvelopeBudgetCannotUseProjectionCounter(t *testing.T) {
	options, _, a, b, _, _ := upperFixture(t, "envelope")
	controller, err := model.NewInvestigation(context.Background(), options)
	upperCheck(t, err)
	step, err := controller.Step(context.Background())
	if err == nil || step.NextRequest().Identity() != "" || a.count() != 1 || b.count() != 0 {
		t.Fatal("projection-sized cap admitted larger full result envelope")
	}
}
func TestInvestigationUpperNonIndependentOnlyRefusesBeforeAnyModel(t *testing.T) {
	options, _, a, b, _, _ := upperFixture(t, "non-independent")
	gref := options.Routing.Generation.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	vref := options.Routing.Verification[0].ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	if gref == vref || gref.ProviderID() != vref.ProviderID() || gref.AdapterID() == vref.AdapterID() || gref.ModelID() == vref.ModelID() || gref.ConnectionID() == vref.ConnectionID() {
		t.Fatal("non-independent fixture lacks distinct valid same-provider routes")
	}
	pin, err := gateway.NewPinnedRouteRankingPolicy(gref, nil)
	upperCheck(t, err)
	observations := func(routes []gateway.ObservedRouteCandidate) []provider.RoutePerformanceObservation {
		out := []provider.RoutePerformanceObservation{}
		for _, route := range routes {
			for _, obs := range options.Routing.Observations {
				if obs.RecordIdentity() == route.ResolvedRecord().RouteRegistryRecord().Identity() {
					out = append(out, obs)
				}
			}
		}
		return out
	}
	gp, err := gateway.NewInvestigationRoutePlan(options.Routing.RegistryRevision, []gateway.ObservedRouteCandidate{options.Routing.Generation}, pin, options.Routing.PerformanceRevision, observations([]gateway.ObservedRouteCandidate{options.Routing.Generation}))
	upperCheck(t, err)
	vp, err := gateway.NewInvestigationRoutePlan(options.Routing.RegistryRevision, options.Routing.Verification, options.Routing.VerificationRanking, options.Routing.PerformanceRevision, observations(options.Routing.Verification))
	upperCheck(t, err)
	_, err = gateway.NewInvestigationRouteOwner(gateway.InvestigationRouteOwnerOptions{Scope: options.Scope, SessionIdentity: options.SessionIdentity, PolicyIdentity: options.Policy.Identity(), Deadline: options.Deadline, MaxTurns: 5, Budget: options.Routing.Budget, Requirements: options.Routing.Requirements, Constraints: options.Routing.Constraints, Generation: gp, Verification: vp, Catalog: options.Catalog, Ledger: options.Ledger, Clock: options.Clock})
	upperCheck(t, err)
	controller, err := model.NewInvestigation(context.Background(), options)
	if err == nil || controller != nil || a.count() != 0 || b.count() != 0 {
		t.Fatal("valid correlated-only verifier plan reached model dispatch")
	}
	events, err := options.Ledger.Read(context.Background(), options.Scope, 0, 100)
	upperCheck(t, err)
	for _, event := range events {
		if event.Kind() == audit.EventRouteSelected || event.Kind() == audit.EventRouteAttemptClaimed {
			t.Fatal("independence refusal created route authority")
		}
	}
}

func TestInvestigationUpperEarlyVerifyAndControllerAdmission(t *testing.T) {
	options, store, a, b, _, _ := upperFixture(t, "")
	controller, err := model.NewInvestigation(context.Background(), options)
	upperCheck(t, err)
	if _, err := controller.Verify(context.Background()); err == nil || a.count() != 0 || b.count() != 0 {
		t.Fatal("early Verify admitted a model effect")
	}
	_, err = controller.Step(context.Background())
	upperCheck(t, err)
	store.arm()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan error, 1)
	finished := make(chan struct{})
	go func() { defer close(finished); _, err := controller.Step(ctx); firstDone <- err }()
	var competing sync.WaitGroup
	competingDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		store.unblock()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("source-wait fixture did not drain")
		}
		select {
		case <-competingDone:
		case <-time.After(time.Second):
			t.Error("competing controller calls did not drain")
		}
	})
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		close(competingDone)
		t.Fatal("between-turn protected read was not reached")
	}
	results := make(chan error, 3)
	for _, action := range []func(context.Context) error{
		func(ctx context.Context) error { _, err := controller.Step(ctx); return err },
		func(ctx context.Context) error { _, err := controller.Generate(ctx); return err },
		func(ctx context.Context) error { _, err := controller.Verify(ctx); return err },
	} {
		competing.Add(1)
		go func(action func(context.Context) error) { defer competing.Done(); results <- action(ctx) }(action)
	}
	go func() { competing.Wait(); close(competingDone) }()
	for i := 0; i < 3; i++ {
		select {
		case err := <-results:
			if err == nil {
				t.Fatal("concurrent controller entry admitted between-turn work")
			}
		case <-time.After(time.Second):
			t.Fatal("controller entry queued behind tool read instead of refusing")
		}
	}
	if a.count() != 2 || b.count() != 0 {
		t.Fatal("controller admission relied only on model-inflight guard")
	}
	store.unblock()
	select {
	case err := <-firstDone:
		upperCheck(t, err)
	case <-time.After(time.Second):
		t.Fatal("admitted read did not finish after release")
	}
}
func TestInvestigationUpperRebindsInitialContextToProtectedHead(t *testing.T) {
	options, _, a, b, _, _ := upperFixture(t, "")
	other, _, _, _, _, _ := upperFixture(t, "other source")
	options.InitialContext = other.InitialContext
	options.InitialSnapshot = other.InitialSnapshot
	controller, err := model.NewInvestigation(context.Background(), options)
	if err == nil || controller != nil || a.count() != 0 || b.count() != 0 {
		t.Fatal("typed foreign context replaced actual protected head binding")
	}
}
func TestInvestigationUpperChangedPinnedConfigurationRefuses(t *testing.T) {
	options, _, a, b, _, _ := upperFixture(t, "")
	controller, err := model.NewInvestigation(context.Background(), options)
	upperCheck(t, err)
	a.mu.Lock()
	a.config = upperDigest([]byte("changed pinned dispatcher configuration"))
	a.mu.Unlock()
	step, err := controller.Step(context.Background())
	if err == nil || step.NextRequest().Identity() != "" || a.count() != 0 || b.count() != 0 {
		t.Fatal("changed pinned configuration dispatched or silently rerouted")
	}
}
func TestInvestigationUpperPinnedCapacityGrowthCannotReroute(t *testing.T) {
	control, _, modelA, _, _, _ := upperFixture(t, "")
	baseline, err := model.NewInvestigation(context.Background(), control)
	upperCheck(t, err)
	first, err := baseline.Step(context.Background())
	upperCheck(t, err)
	initialNeed := uint64(len(modelA.calls[0].Request().Payload())) + 256 + 4096
	nextNeed := uint64(len(first.NextRequest().Payload())) + 256 + 4096
	if nextNeed <= initialNeed+32 {
		t.Fatal("listing did not create a meaningful larger model request")
	}
	capacity := (initialNeed + nextNeed) / 2
	options, _, a, b, _, _ := upperFixture(t, "", capacity)
	controller, err := model.NewInvestigation(context.Background(), options)
	upperCheck(t, err)
	_, err = controller.Step(context.Background())
	upperCheck(t, err)
	step, err := controller.Step(context.Background())
	if err == nil || step.NextRequest().Identity() != "" || a.count() != 1 || b.count() != 0 {
		t.Fatal("larger context rerouted away from fixed generation record")
	}
}

func TestInvestigationUpperForgedOpaqueReferenceRefusesBeforeFileGet(t *testing.T) {
	options, store, a, b, _, _ := upperFixture(t, "forged ref")
	controller, err := model.NewInvestigation(context.Background(), options)
	upperCheck(t, err)
	_, err = controller.Step(context.Background())
	upperCheck(t, err)
	before := store.fileGets()
	step, err := controller.Step(context.Background())
	if err == nil || step.NextRequest().Identity() != "" || store.fileGets() != before || a.count() != 2 || b.count() != 0 {
		t.Fatal("well-shaped forged reference gained file access or next authority")
	}
	if _, err := controller.Generate(context.Background()); err == nil || a.count() != 2 {
		t.Fatal("failed proposal was relabeled into new model work")
	}
}
