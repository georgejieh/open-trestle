package runtimecatalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/worker"
)

const bridgeNotes = "deployment notes\r\nConsume is enabled for zero-valued requests.\r\nnot selected by symbol analysis\n"
const bridgeLine = "Consume is enabled for zero-valued requests.\r\n"

var errBridgeInjected = errors.New("injected operation failure")

type bridgeClock struct{}

func (bridgeClock) Now() time.Time { return time.Now().UTC() }

type bridgeRunKey struct{}

type bridgeGate struct {
	entered, canceled, release         chan struct{}
	enterOnce, cancelOnce, releaseOnce sync.Once
}

func newBridgeGate() *bridgeGate {
	return &bridgeGate{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{})}
}
func (g *bridgeGate) wait(ctx context.Context, uncooperative bool) {
	g.enterOnce.Do(func() { close(g.entered) })
	select {
	case <-ctx.Done():
		g.cancelOnce.Do(func() { close(g.canceled) })
		if uncooperative {
			<-g.release
		}
	case <-g.release:
	}
}
func (g *bridgeGate) unblock() { g.releaseOnce.Do(func() { close(g.release) }) }

type bridgeGet struct {
	phase, identity string
	kind            artifact.Kind
}
type bridgeTrace struct {
	mu                                       sync.Mutex
	events                                   []string
	phase                                    string
	contexts                                 map[string]context.Context
	requests                                 map[string]controlplane.TaskExecutionRequest
	completions                              map[string]controlplane.TaskCompletion
	canceledBefore                           map[string]bool
	gets                                     []bridgeGet
	puts                                     []artifact.Artifact
	sourceActive, sourceMaximum, sourceCalls int
}

func newBridgeTrace() *bridgeTrace {
	return &bridgeTrace{contexts: map[string]context.Context{}, requests: map[string]controlplane.TaskExecutionRequest{}, completions: map[string]controlplane.TaskCompletion{}, canceledBefore: map[string]bool{}}
}
func (tr *bridgeTrace) eventLocked(value string) {
	if len(tr.events) >= 256 {
		panic("bounded engine trace exceeded")
	}
	tr.events = append(tr.events, value)
}
func (tr *bridgeTrace) eventsCopy() []string {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]string(nil), tr.events...)
}

type bridgeObservedHandler struct {
	controlplane.TaskHandler
	trace *bridgeTrace
}

func (h *bridgeObservedHandler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	key := request.Task().Key()
	h.trace.mu.Lock()
	for prior, previous := range h.trace.contexts {
		h.trace.canceledBefore[prior+"->"+key] = previous.Err() != nil
	}
	h.trace.phase = key
	h.trace.contexts[key], h.trace.requests[key] = ctx, request
	h.trace.eventLocked("execute:" + key)
	h.trace.mu.Unlock()
	completion := h.TaskHandler.Execute(ctx, request)
	h.trace.mu.Lock()
	h.trace.completions[key] = completion
	h.trace.eventLocked("returned:" + key)
	h.trace.mu.Unlock()
	return completion
}

type bridgeControl struct {
	worker.Control
	trace         *bridgeTrace
	failKey       string
	commitUnknown bool
	faults        int
}

func (c *bridgeControl) CompleteTask(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskLease, completion controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error) {
	key := lease.TaskKey()
	c.trace.mu.Lock()
	c.trace.eventLocked("complete-attempt:" + key)
	c.trace.mu.Unlock()
	fault := key == c.failKey && completion.Status() == controlplane.TaskCompletionSucceeded
	if fault && !c.commitUnknown {
		c.faults++
		return controlplane.ReviewRunReceipt{}, errBridgeInjected
	}
	receipt, err := c.Control.CompleteTask(ctx, scope, lease, completion)
	if err != nil {
		return receipt, err
	}
	c.trace.mu.Lock()
	c.trace.eventLocked("complete-recorded:" + key)
	c.trace.mu.Unlock()
	if fault {
		c.faults++
		return controlplane.ReviewRunReceipt{}, errBridgeInjected
	}
	return receipt, nil
}

type bridgeSource struct {
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
	keys     map[string]string
	trace    *bridgeTrace
	gate     *bridgeGate
	mode     string
}

func (s *bridgeSource) Identity() evidence.SourceAdapterIdentity { return s.identity }
func (s *bridgeSource) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	key := s.keys[request.Revision().Identity()]
	s.trace.mu.Lock()
	s.trace.sourceActive++
	s.trace.sourceCalls++
	s.trace.sourceMaximum = max(s.trace.sourceMaximum, s.trace.sourceActive)
	s.trace.eventLocked("acquire:" + key)
	s.trace.mu.Unlock()
	defer func() {
		s.trace.mu.Lock()
		defer s.trace.mu.Unlock()
		s.trace.sourceActive--
		s.trace.eventLocked("acquire-return:" + key)
	}()
	if s.mode == "source-wait" && key == "source-head" {
		s.gate.wait(ctx, false)
	}
	if ctx.Err() != nil {
		return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonAdapterFailure}
	}
	if result, ok := s.results[request.Revision().Identity()]; ok {
		return result
	}
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeBlocked, Reason: evidence.AcquisitionReasonPolicyBlocked}
}

type bridgeStore struct {
	artifact.Store
	trace                  *bridgeTrace
	gate                   *bridgeGate
	mode                   string
	mu                     sync.Mutex
	turnPuts, injected     int
	attempted, substituted artifact.Artifact
}

func bridgeIsIntent(value artifact.Artifact) bool {
	if value.Kind() != artifact.KindTaskInput {
		return false
	}
	var wire struct {
		Contract string `json:"contract"`
	}
	return json.Unmarshal(value.Payload(), &wire) == nil && wire.Contract == "open-trestle/investigation-context-intent"
}
func (s *bridgeStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	s.mu.Lock()
	if value.Kind() == artifact.KindInvestigationTurn {
		s.turnPuts++
	}
	fault := value.Kind() == artifact.KindInvestigationTurn && s.turnPuts == 2 && (s.mode == "turn-put-refused" || s.mode == "turn-put-unknown")
	if fault {
		s.injected++
		s.attempted = value
	}
	s.mu.Unlock()
	if fault && s.mode == "turn-put-refused" {
		return false, errBridgeInjected
	}
	stored, err := s.Store.Put(ctx, value, at)
	if err != nil {
		return stored, err
	}
	s.trace.mu.Lock()
	if len(s.trace.puts) >= 256 {
		s.trace.mu.Unlock()
		panic("bounded Put trace exceeded")
	}
	s.trace.puts = append(s.trace.puts, value)
	s.trace.mu.Unlock()
	if fault {
		return false, errBridgeInjected
	}
	return stored, nil
}
func (s *bridgeStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	value, err := s.Store.Get(ctx, scope, id, at)
	if err != nil {
		return value, err
	}
	s.trace.mu.Lock()
	phase := s.trace.phase
	if len(s.trace.gets) >= 512 {
		s.trace.mu.Unlock()
		panic("bounded Get trace exceeded")
	}
	s.trace.gets = append(s.trace.gets, bridgeGet{phase, id, value.Kind()})
	s.trace.mu.Unlock()
	if s.mode == "bootstrap-wait" && phase == "candidates" && (value.Kind() == artifact.KindSourceFile || value.Kind() == artifact.KindSourceSnapshot) {
		s.gate.wait(ctx, false)
		if ctx.Err() != nil {
			return artifact.Artifact{}, artifact.ErrStoreContextDone
		}
	}
	if s.mode == "rehashed-intent" && phase == "candidates" && bridgeIsIntent(value) {
		parents := append(value.Provenance(), requiredDigest("wrong-intent-parent"))
		replacement, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), parents, value.Payload(), value.CreatedAt(), value.ExpiresAt())
		if err != nil {
			return artifact.Artifact{}, err
		}
		s.mu.Lock()
		s.injected++
		s.attempted, s.substituted = value, replacement
		s.mu.Unlock()
		return replacement, nil
	}
	return value, nil
}

type bridgeTool struct {
	Identity  string `json:"identity"`
	Artifact  string `json:"artifact_identity"`
	Operation string `json:"operation_identity"`
	Tool      string `json:"tool"`
	Files     []struct {
		Ref  string `json:"ref"`
		Path string `json:"path"`
	} `json:"files"`
	Sources []struct {
		requiredRequestSource
		Binding string `json:"binding_identity"`
		Digest  string `json:"repository_file_digest"`
	} `json:"sources"`
}
type bridgePacket struct {
	Version           int                     `json:"schema_version"`
	Task              string                  `json:"task"`
	Scope             string                  `json:"review_scope_identity"`
	GenerationContext string                  `json:"generation_context_identity"`
	CandidateBatch    string                  `json:"candidate_batch_identity"`
	Sources           []requiredRequestSource `json:"sources"`
	Candidates        []struct {
		ID       string   `json:"candidate_id"`
		Evidence []string `json:"evidence_ids"`
	} `json:"candidates"`
	Investigation struct {
		Session         string       `json:"session_identity"`
		Policy          string       `json:"policy_identity"`
		SnapshotRef     string       `json:"snapshot_ref"`
		Turn            uint32       `json:"turn"`
		PreviousRequest string       `json:"previous_request_identity"`
		PreviousOutcome string       `json:"previous_outcome_identity"`
		PreviousResults []string     `json:"previous_tool_result_identities"`
		MemoryState     string       `json:"memory_state"`
		Results         []bridgeTool `json:"tool_results"`
	} `json:"investigation"`
}
type bridgeCapture struct {
	request gateway.RouteDispatchRequest
	packet  bridgePacket
}
type bridgeModels struct {
	t        *testing.T
	mu       sync.Mutex
	captures []bridgeCapture
	mode     string
	gate     *bridgeGate
}

func (m *bridgeModels) snapshot() []bridgeCapture {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]bridgeCapture(nil), m.captures...)
}

type bridgeDispatcher struct {
	models  *bridgeModels
	adapter string
}

func (d *bridgeDispatcher) AdapterID() string { return d.adapter }
func (d *bridgeDispatcher) ConfigurationIdentity() string {
	return requiredDigest("investigation-" + d.adapter)
}
func bridgeFailedDispatch() gateway.RouteDispatchResult {
	result, _ := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureCancelled, gateway.RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage(), 0)
	return result
}
func (d *bridgeDispatcher) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	m := d.models
	var packet bridgePacket
	if request.Validate() != nil || json.Unmarshal(request.Request().Payload(), &packet) != nil || ctx.Value(bridgeRunKey{}) != "foreground" || ctx.Err() != nil {
		m.t.Error("provider lost actual request or foreground run context")
		return bridgeFailedDispatch()
	}
	m.mu.Lock()
	m.captures = append(m.captures, bridgeCapture{request, packet})
	count := len(m.captures)
	m.mu.Unlock()
	if count > 5 {
		m.t.Error("unexpected extra external model call")
		return bridgeFailedDispatch()
	}
	verifying := packet.Task == "candidate_verification"
	if (m.mode == "generation-wait" || m.mode == "generation-uncooperative") && !verifying && packet.Investigation.Turn == 2 || m.mode == "verification-wait" && verifying {
		m.gate.wait(ctx, m.mode == "generation-uncooperative")
		return bridgeFailedDispatch()
	}
	document, err := d.document(packet)
	if err != nil {
		m.t.Error(err)
		return bridgeFailedDispatch()
	}
	payload, err := json.Marshal(document)
	if err != nil {
		m.t.Error(err)
		return bridgeFailedDispatch()
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", payload)
	if err != nil {
		m.t.Error(err)
		return bridgeFailedDispatch()
	}
	usage, err := provider.NewRouteTokenUsage(100, 100, 0)
	if err != nil {
		m.t.Error(err)
		return bridgeFailedDispatch()
	}
	if m.mode == "unknown-usage" && !verifying && packet.Investigation.Turn == 2 {
		usage = provider.NewUnknownRouteTokenUsage()
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	if err != nil {
		m.t.Error(err)
		return bridgeFailedDispatch()
	}
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		m.t.Error(err)
		return bridgeFailedDispatch()
	}
	return result
}
func (d *bridgeDispatcher) document(p bridgePacket) (map[string]any, error) {
	fail := func() (map[string]any, error) {
		return nil, fmt.Errorf("actual investigation request lost source or turn lineage")
	}
	var changed requiredRequestSource
	ids := []string{}
	for _, s := range p.Sources {
		if s.Path == "a.go" {
			changed = s
			ids = append(ids, s.ID)
		}
		if s.Path == "notes.txt" {
			if s.Content != bridgeLine || s.StartLine != 2 || s.EndLine != 2 {
				return fail()
			}
			ids = append(ids, s.ID)
		}
	}
	if changed.ID == "" || !strings.Contains(changed.Content, "return 10 / x") {
		return fail()
	}
	if p.Task == "candidate_verification" {
		if d.adapter != "adapter-b" || p.Version != 3 || p.GenerationContext == "" || p.CandidateBatch == "" || len(ids) != 2 || len(p.Candidates) != 1 {
			return fail()
		}
		return map[string]any{"schema_version": 1, "verdicts": []any{map[string]any{"candidate_id": p.Candidates[0].ID, "outcome": "verified", "severity": "high", "rationale": "The division guard is absent and the cited deployment text enables zero requests.", "evidence_ids": ids}}}, nil
	}
	s := p.Investigation
	if d.adapter != "adapter-a" || p.Task != "candidate_generation" || p.Version != 4 || s.MemoryState != "empty_not_ingested" || s.Session == "" || s.Policy == "" {
		return fail()
	}
	var ref string
	read, searched := false, false
	for _, result := range s.Results {
		if result.Identity == "" || result.Artifact == "" || result.Identity == result.Artifact {
			return fail()
		}
		for _, file := range result.Files {
			if file.Path == "notes.txt" {
				ref = file.Ref
			}
		}
		for _, source := range result.Sources {
			if source.Path == "notes.txt" && source.Content == bridgeLine && source.StartLine == 2 && source.EndLine == 2 && source.Binding != "" && source.Digest == requiredDigest(bridgeNotes) {
				if result.Tool == "snapshot.read" {
					read = true
				}
				if result.Tool == "snapshot.search" {
					searched = true
				}
			}
		}
	}
	call := map[string]any{"call_id": "list-1", "tool": "snapshot.list", "snapshot_ref": s.SnapshotRef}
	switch s.Turn {
	case 1:
		if len(ids) != 1 || len(s.Results) != 0 || s.PreviousRequest != "" || s.PreviousOutcome != "" {
			return fail()
		}
	case 2:
		if ref == "" {
			return fail()
		}
		call = map[string]any{"call_id": "read-1", "tool": "snapshot.read", "snapshot_ref": s.SnapshotRef, "file_ref": ref, "start_line": 2, "end_line": 2}
	case 3:
		if ref == "" || !read {
			return fail()
		}
		call = map[string]any{"call_id": "search-1", "tool": "snapshot.search", "snapshot_ref": s.SnapshotRef, "file_refs": []string{ref}, "literal": "zero-valued"}
	case 4:
		if !searched || len(ids) != 2 {
			return fail()
		}
		return map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Enabled zero requests panic", "claim": "Deployment enables zero requests while Changed divides without a guard.", "severity_hint": "high", "source_range": map[string]any{"source_id": changed.ID, "start_line": 2, "end_line": 2}, "evidence_ids": ids}}}, nil
	default:
		return fail()
	}
	return map[string]any{"schema_version": 1, "tool_calls": []any{call}}, nil
}

func bridgePricedRuntime(t *testing.T) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	baseline, original := requiredRuntimePolicy(t, true)
	price, err := provider.NewRoutePricing(1000000, 1000000)
	requiredCheck(t, err)
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	requiredCheck(t, err)
	definitions := []runtimeconfig.RouteDefinition{}
	for _, candidate := range original.Candidates() {
		route := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		definitions = append(definitions, runtimeconfig.RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: price, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"fixture":"priced investigation contract"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100})
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	requiredCheck(t, err)
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		r := candidate.ResolvedRecord().RouteRegistryRecord()
		records[r.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = r.Identity()
	}
	payload, err := json.Marshal(map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": baseline.ReviewPolicyIdentity(),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000, "pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]}, "verification_independence": "distinct_provider",
		"publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "https://provider-a.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"}, {"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "https://provider-b.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"}},
	})
	requiredCheck(t, err)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(payload), inventory)
	requiredCheck(t, err)
	return configuration, inventory
}

type bridgeFixture struct {
	t             *testing.T
	ctx           context.Context
	cancel        context.CancelFunc
	clock         bridgeClock
	trace         *bridgeTrace
	gate          *bridgeGate
	underlying    *artifact.MemoryStore
	store         *bridgeStore
	diagnostics   diagnostics.Store
	ledger        audit.Ledger
	journal       controlplane.RunJournal
	coordinator   *controlplane.Coordinator
	finalizer     *controlplane.RunFinalizer
	configuration runtimeconfig.RuntimePolicy
	prepared      runtimecatalog.PreparedReviewRun
	catalog       runtimecatalog.PipelineCatalog
	bridge        *modelhandler.InvestigationPipeline
	control       *bridgeControl
	runner        *worker.Runner
	models        *bridgeModels
}

func newBridgeFixture(t *testing.T, mode string) *bridgeFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), bridgeRunKey{}, "foreground"), 30*time.Second)
	f := &bridgeFixture{t: t, ctx: ctx, cancel: cancel, trace: newBridgeTrace(), gate: newBridgeGate(), clock: bridgeClock{}}
	t.Cleanup(func() {
		f.cancel()
		f.gate.unblock()
		cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
		defer stop()
		if f.runner != nil {
			if err := f.runner.Wait(cleanup); err != nil {
				t.Error(err)
			}
		}
		if f.bridge != nil {
			if err := f.bridge.Close(cleanup); err != nil {
				t.Error(err)
			}
		}
	})
	var err error
	f.underlying, err = artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 512)
	requiredCheck(t, err)
	f.store = &bridgeStore{Store: f.underlying, trace: f.trace, gate: f.gate, mode: mode}
	f.ledger, f.journal, f.diagnostics = audit.NewMemoryLedger(), controlplane.NewMemoryRunJournal(), diagnostics.NewMemoryStore()
	f.coordinator, err = controlplane.NewCoordinator(f.journal)
	requiredCheck(t, err)
	f.finalizer, err = controlplane.NewRunFinalizer(f.journal)
	requiredCheck(t, err)
	configuration, inventory := bridgePricedRuntime(t)
	f.configuration = configuration
	identity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	requiredCheck(t, err)
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	requiredCheck(t, err)
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	requiredCheck(t, err)
	acquired := func(body string) scm.SourceAdapterResult {
		contents := map[string][]byte{"a.go": []byte(body), "notes.txt": []byte(bridgeNotes)}
		files := []evidence.RepositoryFile{}
		for _, path := range []string{"a.go", "notes.txt"} {
			file, err := evidence.NewRepositoryFile(path, contents[path])
			requiredCheck(t, err)
			files = append(files, file)
		}
		manifest, err := evidence.NewRepositoryManifest(files)
		requiredCheck(t, err)
		return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
	}
	source := &bridgeSource{identity: identity, trace: f.trace, gate: f.gate, mode: mode, keys: map[string]string{base.Identity(): "source-base", head.Identity(): "source-head"}, results: map[string]scm.SourceAdapterResult{base.Identity(): acquired("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n"), head.Identity(): acquired("package p\nfunc Changed(x int) int { return 10 / x }\n")}}
	f.models = &bridgeModels{t: t, gate: f.gate, mode: mode}
	dispatchers, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{&bridgeDispatcher{f.models, "adapter-a"}, &bridgeDispatcher{f.models, "adapter-b"}})
	requiredCheck(t, err)
	policyBytes, err := json.Marshal(map[string]any{"contract": "open-trestle/investigation-policy", "schema_version": 1, "profile": "snapshot-read-v1", "max_model_turns": 5, "max_tool_calls": 3, "max_returned_bytes": 32768, "max_scanned_bytes": 65536, "max_files": 16, "max_lines_per_read": 20, "max_matches": 8, "max_result_bytes": 8192, "max_cost_micro_usd": 1000000, "timeout_milliseconds": 10000})
	requiredCheck(t, err)
	policy, err := review.ParseInvestigationPolicy(policyBytes)
	requiredCheck(t, err)
	profile, err := runtimecatalog.NewInvestigationProfileFromRuntimePolicy(configuration, inventory, policy, dispatchers.Identity())
	requiredCheck(t, err)
	f.catalog, f.bridge, err = runtimecatalog.NewInvestigationPipelineCatalog(profile, runtimecatalog.InvestigationCatalogOptions{Store: f.store, Diagnostics: f.diagnostics, Ledger: f.ledger, Journal: f.journal, Clock: f.clock, Dispatchers: dispatchers, Source: source})
	requiredCheck(t, err)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "bridge-run")
	requiredCheck(t, err)
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	requiredCheck(t, err)
	request, err := runtimecatalog.NewPreparedReviewRequest(runtimecatalog.PreparedReviewRequestOptions{Scope: scope, HostRequestIdentity: requiredDigest("host"), Repository: repository, BaseRevision: base, HeadRevision: head, SourceAdapter: identity, SourceRootIdentity: requiredDigest("fixture-source-root"), InventoryIdentity: inventory.Identity(), RuntimePolicyIdentity: configuration.Identity(), ReviewPolicyIdentity: configuration.ReviewPolicyIdentity(), Classification: artifact.ClassificationConfidential, Protection: artifact.ProtectionProcessPrivate, CreatedAt: f.clock.Now(), Retention: time.Hour, Catalog: f.catalog})
	requiredCheck(t, err)
	f.prepared, err = runtimecatalog.PrepareReviewRun(ctx, request)
	requiredCheck(t, err)
	for _, value := range f.prepared.Inputs() {
		_, err = f.store.Put(ctx, value, f.clock.Now())
		requiredCheck(t, err)
	}
	if f.trace.sourceCalls != 0 || len(f.models.snapshot()) != 0 {
		t.Fatal("inert bridge construction executed externals")
	}
	_, err = f.coordinator.Open(ctx, f.prepared.Plan(), f.clock.Now())
	requiredCheck(t, err)
	local, err := worker.NewLocalControl(f.journal, f.clock, "bridge-worker")
	requiredCheck(t, err)
	f.control = &bridgeControl{Control: local, trace: f.trace}
	switch mode {
	case "head-complete-refused":
		f.control.failKey = "source-head"
	case "head-complete-unknown":
		f.control.failKey, f.control.commitUnknown = "source-head", true
	case "context-complete-refused":
		f.control.failKey = "context"
	}
	handlers := []controlplane.TaskHandler{}
	for _, binding := range f.catalog.Bindings() {
		handler, ok := f.catalog.Catalog().Resolve(binding.HandlerIdentity)
		if !ok {
			t.Fatal("actual catalog handler unavailable")
		}
		handlers = append(handlers, &bridgeObservedHandler{handler, f.trace})
	}
	observed, err := controlplane.NewTaskHandlerCatalog(handlers)
	requiredCheck(t, err)
	f.runner, err = worker.New(f.control, observed, worker.Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: time.Second, ExecutionTimeout: 10 * time.Second})
	requiredCheck(t, err)
	return f
}
func (f *bridgeFixture) start() {
	f.t.Helper()
	requiredCheck(f.t, f.bridge.StartRun(f.ctx, f.prepared.Plan()))
}
func (f *bridgeFixture) settle() controlplane.ReviewRunState {
	f.t.Helper()
	cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	state, _, err := f.finalizer.ReconcileRun(cleanup, f.prepared.Plan().Scope(), f.clock.Now())
	requiredCheck(f.t, err)
	if state.Status() == controlplane.ReviewRunActive {
		state, err = f.coordinator.CancelRun(cleanup, f.prepared.Plan(), f.clock.Now())
		requiredCheck(f.t, err)
	}
	return state
}
func (f *bridgeFixture) output(state controlplane.ReviewRunState, key string) artifact.Artifact {
	f.t.Helper()
	task, ok := state.Task(key)
	if !ok || task.Status() != controlplane.TaskRuntimeSucceeded {
		f.t.Fatalf("actual task %s did not succeed", key)
	}
	value, err := f.underlying.Get(context.Background(), f.prepared.Plan().Scope(), task.OutputIdentity(), f.clock.Now())
	requiredCheck(f.t, err)
	return value
}
func (f *bridgeFixture) events() []audit.Event {
	f.t.Helper()
	scope := f.prepared.Plan().Scope()
	events, err := f.ledger.Read(context.Background(), scope, 0, 1000)
	requiredCheck(f.t, err)
	head, found, err := f.ledger.Head(context.Background(), scope)
	requiredCheck(f.t, err)
	if !found && len(events) != 0 || found && (len(events) == 0 || uint64(len(events)) != head.Sequence() || events[len(events)-1].Identity() != head.Identity()) {
		f.t.Fatal("audit trace is not complete")
	}
	previous := ""
	for i, event := range events {
		requiredCheck(f.t, event.Validate())
		if event.Scope().Identity() != scope.Identity() || event.Sequence() != uint64(i+1) || event.PreviousIdentity() != previous {
			f.t.Fatal("actual audit chain changed")
		}
		previous = event.Identity()
	}
	return events
}
