package model

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

var ErrInvestigation = errors.New("investigation unavailable or progression frozen")
var ErrInvestigationDrain = errors.New("investigation work has not drained")

type InvestigationRoutingOptions struct {
	RegistryRevision, PerformanceRevision uint64
	Generation                            gateway.ObservedRouteCandidate
	Verification                          []gateway.ObservedRouteCandidate
	Observations                          []provider.RoutePerformanceObservation
	VerificationRanking                   gateway.RouteRankingPolicy
	Requirements                          provider.ModelRequirements
	Constraints                           policy.ProviderDataConstraints
	Budget                                provider.ModelCostBudget
	Independence                          gateway.RouteIndependencePolicy
}
type InvestigationOptions struct {
	Scope                        audit.ReviewScope
	MemoryScope                  memory.Scope
	SessionIdentity              string
	Policy                       review.InvestigationPolicy
	Routing                      InvestigationRoutingOptions
	Catalog                      gateway.RouteDispatcherCatalog
	Ledger                       audit.Ledger
	Clock                        artifact.Clock
	Deadline                     time.Time
	Store                        artifact.Store
	Acquisition                  *InvestigationAcquisition
	HeadSnapshotArtifactIdentity string
	InitialContext               review.ContextPacket
	InitialSnapshot              review.ReviewSnapshot
}
type Investigation struct {
	mu                                              sync.Mutex
	options                                         InvestigationOptions
	root                                            context.Context
	cancel                                          context.CancelFunc
	wallDeadline, expires                           time.Time
	closing, closed, failed, active                 bool
	done                                            chan struct{}
	owner                                           *gateway.InvestigationRouteOwner
	ownerIdentity, pin                              string
	binding                                         review.InvestigationContextBinding
	head                                            artifact.Artifact
	snapshot                                        source.Snapshot
	files, retained                                 map[string]artifact.Artifact
	reader, lowerReader                             *source.SnapshotReader
	readerLimits, lowerLimits                       source.SnapshotReadLimits
	capture                                         *investigationCapture
	byPath, byRef                                   map[string]source.SnapshotFileRef
	limits                                          review.ContextLimits
	candidates                                      []review.ContextSource
	tools                                           []investigationHeldTool
	calls, operations                               map[string]bool
	scanned, returned, reservedScan, reservedReturn uint64
	current                                         review.InvestigationGenerationContext
	currentArtifact                                 artifact.Artifact
	last                                            gateway.InvestigationTurnRecord
	finalCustody                                    *InvestigationGenerationCustody
	generation                                      InvestigationGeneration
	verification                                    InvestigationVerification
}
type InvestigationStep struct {
	turn              gateway.InvestigationTurnRecord
	next              provider.Request
	toolArtifact      string
	scanned, returned uint64
}

func (s InvestigationStep) Turn() gateway.InvestigationTurnRecord { return s.turn }
func (s InvestigationStep) NextRequest() provider.Request         { return s.next }
func (s InvestigationStep) ToolResultArtifactIdentity() string    { return s.toolArtifact }
func (s InvestigationStep) ScannedBytes() uint64                  { return s.scanned }
func (s InvestigationStep) ReturnedBytes() uint64                 { return s.returned }

type InvestigationGeneration struct {
	witness *InvestigationGenerationCustody
}

func (g InvestigationGeneration) Custody() *InvestigationGenerationCustody { return g.witness }
func (g InvestigationGeneration) Context() review.InvestigationGenerationContext {
	if g.witness == nil {
		return review.InvestigationGenerationContext{}
	}
	return g.witness.context
}
func (g InvestigationGeneration) ContextIdentity() string         { return g.Context().Identity() }
func (g InvestigationGeneration) Snapshot() review.ReviewSnapshot { return g.Context().Snapshot() }
func (g InvestigationGeneration) EvidenceItems() []evidence.EvidenceItem {
	return g.Context().EvidenceItems()
}
func (g InvestigationGeneration) ContextArtifact() artifact.Artifact {
	if g.witness == nil {
		return artifact.Artifact{}
	}
	return g.witness.contextArtifact
}
func (g InvestigationGeneration) InputArtifact() artifact.Artifact {
	if g.witness == nil {
		return artifact.Artifact{}
	}
	return g.witness.input
}
func (g InvestigationGeneration) ResultArtifact() artifact.Artifact {
	if g.witness == nil {
		return artifact.Artifact{}
	}
	return g.witness.result
}
func (g InvestigationGeneration) TurnArtifact() artifact.Artifact {
	if g.witness == nil {
		return artifact.Artifact{}
	}
	return g.witness.turnArtifact
}
func (g InvestigationGeneration) FinalTurn() gateway.InvestigationTurnRecord {
	if g.witness == nil {
		return gateway.InvestigationTurnRecord{}
	}
	return g.witness.turn
}
func (g InvestigationGeneration) Candidates() review.CandidateBatch {
	if g.witness == nil {
		return review.CandidateBatch{}
	}
	return g.witness.resultValue.candidates
}
func (g InvestigationGeneration) RouteExecution() gateway.RouteExecutionRecord {
	if g.witness == nil {
		return gateway.RouteExecutionRecord{}
	}
	return g.witness.resultValue.execution
}

func investigationSameService(a, b any) bool {
	if nilInterface(a) || nilInterface(b) {
		return false
	}
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	return va.Type() == vb.Type() && va.Comparable() && vb.Comparable() && va.Interface() == vb.Interface()
}
func NewInvestigation(ctx context.Context, o InvestigationOptions) (*Investigation, error) {
	if nilInterface(ctx) || ctx.Err() != nil || o.Scope.Validate() != nil || o.MemoryScope.Validate() != nil || o.MemoryScope.TenantID() != o.Scope.TenantID() || o.MemoryScope.RepositoryID() != o.Scope.RepositoryID() || o.MemoryScope.Identity() != o.InitialContext.MemoryScopeIdentity() || o.InitialContext.Validate() != nil || o.InitialSnapshot.Validate() != nil || o.InitialContext.SnapshotIdentity() != o.InitialSnapshot.Identity() || o.InitialContext.ReviewScopeIdentity() != o.Scope.Identity() || o.InitialContext.SourceSelection().OmittedCount() != 0 || o.InitialContext.MemoryItemCount() != 0 || o.Policy.ValidateRuntimeBudget(o.Routing.Budget) != nil || nilInterface(o.Clock) || nilInterface(o.Store) || nilInterface(o.Ledger) || o.Catalog.Validate() != nil || o.Acquisition == nil || o.Acquisition.owner == nil {
		return nil, ErrInvestigation
	}
	for _, retrieval := range o.InitialContext.Retrievals() {
		if retrieval.Validate() != nil || retrieval.ScopeIdentity() != o.MemoryScope.Identity() || retrieval.Query().ScopeIdentity() != o.MemoryScope.Identity() {
			return nil, ErrInvestigation
		}
	}
	for _, s := range o.InitialContext.Sources() {
		if !s.HasSliceBinding() || !o.MemoryScope.AllowsPath(s.EvidenceItem().SourceRange().Path()) {
			return nil, ErrInvestigation
		}
	}
	at := o.Clock.Now()
	duration := o.Deadline.Sub(at)
	if at.UnixMilli() <= 0 || duration <= 0 {
		return nil, ErrInvestigation
	}
	a := o.Acquisition
	h := a.owner
	h.mu.Lock()
	valid := !h.closed && !h.closing && h.planIdentity == a.planIdentity && a.scopeIdentity == o.Scope.Identity() && a.headIdentity == o.HeadSnapshotArtifactIdentity && investigationSameService(o.Store, h.capture.store)
	found := false
	for _, slot := range h.slots {
		if slot.handle == a && slot.taskIdentity == a.taskIdentity {
			found = true
		}
	}
	head, snapshot, acquired := a.head, a.snapshot, append([]artifact.Artifact(nil), a.files...)
	h.mu.Unlock()
	if !valid || !found || at.Before(a.created) || !at.Before(a.expires) || head.Identity() != o.HeadSnapshotArtifactIdentity || head.Scope() != o.Scope || head.Origin() != artifact.OriginRepository || head.Protection() != artifact.ProtectionProcessPrivate || head.Classification().String() != string(o.Routing.Constraints.Classification()) || len(acquired) > 128 {
		return nil, ErrInvestigation
	}
	o.Routing.Verification = append([]gateway.ObservedRouteCandidate(nil), o.Routing.Verification...)
	o.Routing.Observations = append([]provider.RoutePerformanceObservation(nil), o.Routing.Observations...)
	root, cancel := context.WithTimeout(ctx, min(duration, time.Duration(o.Policy.TimeoutMilliseconds())*time.Millisecond))
	c := &Investigation{options: o, root: root, cancel: cancel, wallDeadline: time.Now().Add(min(duration, time.Duration(o.Policy.TimeoutMilliseconds())*time.Millisecond)), expires: minInvestigationTime(a.expires, minInvestigationTime(head.ExpiresAt(), o.Deadline)), head: head, snapshot: snapshot, files: map[string]artifact.Artifact{}, retained: map[string]artifact.Artifact{}, byPath: map[string]source.SnapshotFileRef{}, byRef: map[string]source.SnapshotFileRef{}, calls: map[string]bool{}, operations: map[string]bool{}}
	ok := false
	defer func() {
		if !ok {
			cancel()
		}
	}()
	allowed := map[string]artifact.Artifact{head.Identity(): head}
	for _, file := range acquired {
		c.files[file.Identity()] = file
		allowed[file.Identity()] = file
	}
	c.capture = &investigationCapture{store: o.Store, scope: o.Scope, allowed: allowed, got: map[string]artifact.Artifact{}}
	p := o.Policy
	c.readerLimits = source.SnapshotReadLimits{MaxFiles: int(p.MaxFiles()), MaxLines: int(p.MaxLinesPerRead()), MaxResultBytes: int(p.MaxResultBytes()), MaxMatches: int(p.MaxMatches()), MaxScannedBytes: p.MaxScannedBytes()}
	if !toolRecordLimits(c.readerLimits, p) {
		return nil, ErrInvestigation
	}
	reader, err := source.NewSnapshotReader(root, c.capture, o.Clock, o.Scope, head.Identity(), snapshot.Identity(), c.readerLimits)
	if err != nil {
		return nil, ErrInvestigation
	}
	c.reader = reader
	listing, err := reader.List(root)
	if err != nil {
		return nil, ErrInvestigation
	}
	for _, ref := range listing.Files() {
		c.byPath[ref.Path()] = ref
		c.byRef[ref.Ref()] = ref
	}
	initial, err := o.InitialContext.ProviderRequest()
	if err != nil {
		return nil, ErrInvestigation
	}
	var packet struct {
		Limits struct {
			Source uint32 `json:"max_source_bytes"`
			Memory uint8  `json:"max_memory_items"`
		} `json:"limits"`
	}
	if json.Unmarshal(initial.Payload(), &packet) != nil {
		return nil, ErrInvestigation
	}
	c.limits, err = review.NewContextLimits(packet.Limits.Source, packet.Limits.Memory)
	if err != nil {
		return nil, ErrInvestigation
	}
	claim := func(route gateway.ObservedRouteCandidate) review.InvestigationRouteContextClaim {
		return review.InvestigationRouteContextClaim{Record: route.ResolvedRecord().RouteRegistryRecord(), ManifestSizeBytes: route.ResolvedRecord().EvidenceManifestSizeBytes(), Operational: route.OperationalState()}
	}
	r := o.Routing
	verifiers := []review.InvestigationRouteContextClaim{}
	for _, route := range r.Verification {
		verifiers = append(verifiers, claim(route))
	}
	c.binding, err = review.NewInvestigationContextBinding(review.InvestigationContextBindingOptions{Scope: o.Scope, HostSessionIdentity: o.SessionIdentity, Policy: p, HeadSnapshotArtifactIdentity: head.Identity(), HeadSnapshotIdentity: snapshot.Identity(), HeadManifestIdentity: snapshot.ManifestIdentity(), HeadRevisionIdentity: snapshot.RevisionIdentity(), InitialContext: o.InitialContext, InitialSnapshot: o.InitialSnapshot, Deadline: o.Deadline, Routing: review.InvestigationContextRouting{RegistryRevision: r.RegistryRevision, PerformanceRevision: r.PerformanceRevision, Generation: claim(r.Generation), Verification: verifiers, Performance: r.Observations, Requirements: r.Requirements, Constraints: r.Constraints, Budget: r.Budget, VerificationRanking: r.VerificationRanking, Independence: r.Independence, CatalogIdentity: o.Catalog.Identity()}})
	if err != nil {
		return nil, ErrInvestigation
	}
	c.pin = r.Generation.ResolvedRecord().RouteRegistryRecord().Identity()
	// Establish independent route possibility with pure UNCLAIMED initial authority.
	initialContext, err := c.rebuildContext(1, gateway.InvestigationTurnRecord{}, nil)
	if err != nil {
		return nil, ErrInvestigation
	}
	request, err := initialContext.ProviderRequest()
	if err != nil {
		return nil, ErrInvestigation
	}
	ranking, err := gateway.NewPinnedRouteRankingPolicy(r.Generation.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	if err != nil {
		return nil, ErrInvestigation
	}
	authorization, err := c.plan(request, []gateway.ObservedRouteCandidate{r.Generation}, ranking, r.Budget.MaxCostMicroUSD())
	if err != nil {
		return nil, ErrInvestigation
	}
	independent := []gateway.ObservedRouteCandidate{}
	for _, route := range r.Verification {
		if gateway.VerifyIndependentRouteCandidate(r.Independence, authorization, route) == nil {
			independent = append(independent, route)
		}
	}
	if len(independent) == 0 {
		return nil, ErrInvestigation
	}
	c.options.Routing.Verification = independent
	generationPlan, err := gateway.NewInvestigationRoutePlan(r.RegistryRevision, []gateway.ObservedRouteCandidate{r.Generation}, ranking, r.PerformanceRevision, c.observations([]gateway.ObservedRouteCandidate{r.Generation}))
	if err != nil {
		return nil, ErrInvestigation
	}
	verificationPlan, err := gateway.NewInvestigationRoutePlan(r.RegistryRevision, independent, r.VerificationRanking, r.PerformanceRevision, c.observations(independent))
	if err != nil {
		return nil, ErrInvestigation
	}
	// ALL initial coverage/retention metadata is checked by readInitial before its first Get.
	if err = c.readInitial(root); err != nil {
		return nil, ErrInvestigation
	}
	// Pre-create the sole alternate projection reservation before any model effect.
	// This is one real head metadata Get, never a source-file prefetch.
	c.lowerLimits = c.readerLimits
	c.lowerLimits.MaxResultBytes = max(1, c.readerLimits.MaxResultBytes/2)
	c.lowerReader = c.reader
	if c.lowerLimits != c.readerLimits {
		c.lowerReader, err = source.NewSnapshotReader(root, c.capture, o.Clock, o.Scope, head.Identity(), snapshot.Identity(), c.lowerLimits)
		if err != nil {
			return nil, ErrInvestigation
		}
	}
	checkSnapshot, err := c.selectedSnapshot(c.candidates)
	if err != nil || checkSnapshot.Identity() != o.InitialSnapshot.Identity() {
		return nil, ErrInvestigation
	}
	c.current, err = c.rebuildContext(1, gateway.InvestigationTurnRecord{}, nil)
	if err != nil {
		return nil, ErrInvestigation
	}
	c.owner, err = gateway.NewInvestigationRouteOwner(gateway.InvestigationRouteOwnerOptions{Scope: o.Scope, SessionIdentity: c.binding.Identity(), PolicyIdentity: p.Identity(), Deadline: o.Deadline, MaxTurns: uint8(p.MaxModelTurns()), Budget: r.Budget, Requirements: r.Requirements, Constraints: r.Constraints, Generation: generationPlan, Verification: verificationPlan, Catalog: o.Catalog, Ledger: o.Ledger, Clock: o.Clock})
	if err != nil {
		return nil, ErrInvestigation
	}
	if c.live(root) != nil {
		return nil, ErrInvestigation
	}
	ok = true
	return c, nil
}
func minInvestigationTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (c *Investigation) observations(routes []gateway.ObservedRouteCandidate) []provider.RoutePerformanceObservation {
	out := []provider.RoutePerformanceObservation{}
	for _, route := range routes {
		for _, o := range c.options.Routing.Observations {
			if o.RecordIdentity() == route.ResolvedRecord().RouteRegistryRecord().Identity() {
				out = append(out, o)
				break
			}
		}
	}
	return out
}
func (c *Investigation) plan(request provider.Request, routes []gateway.ObservedRouteCandidate, rankingPolicy gateway.RouteRankingPolicy, remaining uint64) (gateway.RouteAttemptAuthorization, error) {
	r := c.options.Routing
	budget, err := provider.NewModelCostBudget(max(uint64(r.Budget.EstimatedInputTokens()), uint64(len(request.Payload()))+256), uint64(r.Budget.MaxOutputTokens()), remaining)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	input, err := gateway.NewReviewRoutingInput(c.options.Scope, request, r.Requirements, r.Constraints)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	eligible, err := gateway.FilterEligibleRoutes(input, budget, r.RegistryRevision, routes)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	ranking, err := gateway.RankEligibleRoutes(eligible, rankingPolicy, r.PerformanceRevision, c.observations(eligible.EligibleRoutes()))
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	selection, err := gateway.NewRouteSelectionReceipt(eligible, ranking)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, err
	}
	return gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
}
func (c *Investigation) live(ctx context.Context) error {
	if c == nil || nilInterface(ctx) || nilInterface(c.root) || c.cancel == nil || nilInterface(c.options.Clock) || ctx.Err() != nil || c.root.Err() != nil || !time.Now().Before(c.wallDeadline) {
		return ErrInvestigation
	}
	c.mu.Lock()
	bad := c.closed || c.closing || c.failed
	c.mu.Unlock()
	at := c.options.Clock.Now()
	if !at.Before(c.expires) {
		c.cancel()
		return ErrInvestigation
	}
	if bad || !c.acquisitionLive(at) {
		return ErrInvestigation
	}
	return nil
}
func (c *Investigation) begin(ctx context.Context) (context.Context, func(), error) {
	if c == nil || nilInterface(ctx) || c.live(ctx) != nil {
		return nil, nil, ErrInvestigation
	}
	c.mu.Lock()
	if c.active || c.closed || c.closing || c.failed {
		c.mu.Unlock()
		return nil, nil, ErrInvestigation
	}
	c.active = true
	c.done = make(chan struct{})
	done := c.done
	c.mu.Unlock()
	work, cancel := context.WithDeadline(ctx, c.wallDeadline)
	stop := context.AfterFunc(c.root, cancel)
	return work, func() {
		stop()
		cancel()
		c.mu.Lock()
		c.active = false
		close(done)
		c.mu.Unlock()
	}, nil
}
func (c *Investigation) freeze() { c.mu.Lock(); c.failed = true; c.mu.Unlock(); c.cancel() }
func (c *Investigation) Close(ctx context.Context) error {
	if c == nil || nilInterface(ctx) || c.cancel == nil || nilInterface(c.root) {
		return ErrInvestigationDrain
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closing = true
	c.cancel()
	active, done := c.active, c.done
	c.mu.Unlock()
	if active {
		select {
		case <-done:
		case <-ctx.Done():
			return ErrInvestigationDrain
		}
	}
	c.mu.Lock()
	c.closed = true
	c.closing = false
	// Release controller-owned full-source reference sets only after actual drain.
	// Published immutable context/results remain inspectable data, not live admission.
	c.files = nil
	c.retained = nil
	c.tools = nil
	c.candidates = nil
	c.reader = nil
	c.lowerReader = nil
	if c.finalCustody != nil {
		c.finalCustody.tools = nil
	}
	if c.capture != nil {
		c.capture.mu.Lock()
		c.capture.allowed = nil
		c.capture.got = nil
		c.capture.mu.Unlock()
	}
	c.mu.Unlock()
	return nil
}
func (c *Investigation) newArtifact(kind artifact.Kind, origin artifact.Origin, parents []string, payload []byte) (artifact.Artifact, error) {
	parents = append([]string(nil), parents...)
	sort.Strings(parents)
	parents = slices.Compact(parents)
	return artifact.New(c.options.Scope, kind, "application/json", c.head.Classification(), origin, c.head.Protection(), parents, payload, c.options.Clock.Now(), c.expires)
}
func (c *Investigation) put(ctx context.Context, value artifact.Artifact) error {
	if c.live(ctx) != nil || value.PayloadSizeBytes() > 16<<20 {
		return ErrInvestigation
	}
	wire, err := artifact.Encode(value)
	if err != nil || len(wire) > 22<<20 {
		return ErrInvestigation
	}
	_, err = c.options.Store.Put(ctx, value, c.options.Clock.Now())
	if err != nil {
		return ErrInvestigation
	}
	return c.live(ctx)
}
func (c *Investigation) preflightTurn(request provider.Request) error {
	bound, err := gateway.EstimateInvestigationTurnPayloadBytes(uint64(len(request.Payload())))
	if err != nil || bound > 16<<20 {
		return ErrInvestigation
	}
	// Exact artifact framing vocabulary, worst timestamp widths and provenance32.
	ids := make([]string, 32)
	for i := range ids {
		ids[i] = strings.Repeat("f", 64)
	}
	id := strings.Repeat("f", 64)
	metadata := map[string]any{"contract": "open-trestle/runtime-artifact", "schema_version": 1, "identity": id, "tenant_id": c.options.Scope.TenantID(), "repository_id": c.options.Scope.RepositoryID(), "review_run_id": c.options.Scope.ReviewRunID(), "kind": "investigation_turn", "media_type": "application/json", "classification": c.head.Classification().String(), "origin": artifact.OriginHost.String(), "protection": c.head.Protection().String(), "provenance": ids, "payload_digest": id, "payload": "", "created_at_milliseconds": int64(253402300799999), "expires_at_milliseconds": int64(253402300799999)}
	encoded, err := json.Marshal(metadata)
	if err != nil || uint64(len(encoded))+4*((bound+2)/3) > 22<<20 {
		return ErrInvestigation
	}
	return nil
}
func (c *Investigation) dispatch(ctx context.Context, role gateway.InvestigationTurnRole, request provider.Request) (gateway.InvestigationTurnRecord, artifact.Artifact, error) {
	if c.live(ctx) != nil || c.preflightTurn(request) != nil {
		return gateway.InvestigationTurnRecord{}, artifact.Artifact{}, ErrInvestigation
	}
	turn, err := c.owner.Dispatch(ctx, role, request)
	if err != nil {
		return turn, artifact.Artifact{}, ErrInvestigation
	}
	payload, err := gateway.EncodeInvestigationTurnRecord(turn)
	if err != nil || len(payload) > 16<<20 {
		return turn, artifact.Artifact{}, ErrInvestigation
	}
	var header toolRecordTurnHeader
	if json.Unmarshal(payload, &header) != nil || header.Session != c.binding.Identity() || header.Policy != c.options.Policy.Identity() || header.Scope != c.options.Scope.Identity() || c.ownerIdentity != "" && c.ownerIdentity != header.Owner {
		return turn, artifact.Artifact{}, ErrInvestigation
	}
	c.ownerIdentity = header.Owner
	value, err := c.newArtifact(artifact.KindInvestigationTurn, artifact.OriginHost, []string{c.head.Identity(), c.currentArtifact.Identity(), header.Owner, turn.Identity(), turn.Authorization().Identity(), turn.Outcome().Identity(), turn.Reconciliation().Identity()}, payload)
	if err != nil {
		return turn, artifact.Artifact{}, ErrInvestigation
	}
	if err = c.put(ctx, value); err != nil {
		return turn, artifact.Artifact{}, err
	}
	return turn, value, nil
}
func (c *Investigation) diagnostic(turn gateway.InvestigationTurnRecord) InvestigationStep {
	return InvestigationStep{turn: turn, scanned: c.scanned, returned: c.returned}
}
func (c *Investigation) Step(ctx context.Context) (InvestigationStep, error) {
	work, end, err := c.begin(ctx)
	if err != nil {
		return InvestigationStep{}, err
	}
	defer end()
	step, err := c.step(work)
	if err != nil {
		c.freeze()
	}
	return step, err
}
func (c *Investigation) step(ctx context.Context) (InvestigationStep, error) {
	if c.finalCustody != nil {
		return c.diagnostic(c.last), ErrInvestigation
	}
	request, err := c.current.ProviderRequest()
	if err != nil {
		return c.diagnostic(c.last), err
	}
	if err = c.preflightTurn(request); err != nil {
		return c.diagnostic(c.last), err
	}
	c.currentArtifact, err = c.contextArtifact(c.current, c.options.Clock.Now())
	if err != nil {
		return c.diagnostic(c.last), err
	}
	if err = c.put(ctx, c.currentArtifact); err != nil {
		return c.diagnostic(c.last), err
	}
	turn, turnArtifact, err := c.dispatch(ctx, gateway.InvestigationGenerationTurn, request)
	if err != nil {
		return c.diagnostic(turn), err
	}
	c.last = turn
	response := turn.Dispatch().Response()
	if response.FinishReason() != provider.ResponseFinishStop || response.PartCount() != 1 {
		return c.diagnostic(turn), ErrInvestigation
	}
	part := response.Parts()[0]
	if part.Kind() != provider.ResponsePartStructuredData || part.MediaType() != "application/json" {
		return c.diagnostic(turn), ErrInvestigation
	}
	var shape map[string]json.RawMessage
	if json.Unmarshal(part.Payload(), &shape) != nil {
		return c.diagnostic(turn), ErrInvestigation
	}
	if _, tool := shape["tool_calls"]; !tool {
		generation, err := c.finishGeneration(ctx, turn, turnArtifact)
		if err != nil {
			return c.diagnostic(turn), err
		}
		c.generation = generation
		return c.diagnostic(turn), nil
	}
	proposal, err := review.ParseInvestigationProposal(part.Payload())
	if err != nil {
		return c.diagnostic(turn), err
	}
	result, err := c.tool(ctx, turn, turnArtifact, proposal)
	if err != nil {
		return c.diagnostic(turn), err
	}
	next, err := c.rebuildContext(uint8(len(c.tools)+1), turn, []string{result.Identity()})
	if err != nil {
		return c.diagnostic(turn), err
	}
	c.current = next
	nextRequest, err := next.ProviderRequest()
	if err != nil {
		return c.diagnostic(turn), err
	}
	return InvestigationStep{turn: turn, next: nextRequest, toolArtifact: result.Identity(), scanned: c.scanned, returned: c.returned}, nil
}
func (c *Investigation) Generate(ctx context.Context) (InvestigationGeneration, error) {
	work, end, err := c.begin(ctx)
	if err != nil {
		return InvestigationGeneration{}, err
	}
	defer end()
	for c.finalCustody == nil {
		if _, err = c.step(work); err != nil {
			c.freeze()
			return InvestigationGeneration{}, err
		}
	}
	if c.live(work) != nil {
		return InvestigationGeneration{}, ErrInvestigation
	}
	return c.generation, nil
}

func (c *Investigation) tool(ctx context.Context, turn gateway.InvestigationTurnRecord, turnArtifact artifact.Artifact, proposal review.InvestigationProposal) (artifact.Artifact, error) {
	if uint64(len(c.tools)) >= c.options.Policy.MaxToolCalls() || c.calls[proposal.CallID()] {
		return artifact.Artifact{}, ErrInvestigation
	}
	selected := []source.SnapshotFileRef{}
	switch proposal.Tool() {
	case "snapshot.list":
		for _, ref := range c.byRef {
			selected = append(selected, ref)
		}
	case "snapshot.read":
		ref, ok := c.byRef[proposal.FileRef()]
		if !ok || !c.options.MemoryScope.AllowsPath(ref.Path()) {
			return artifact.Artifact{}, ErrInvestigation
		}
		selected = append(selected, ref)
	case "snapshot.search":
		for _, id := range proposal.FileRefs() {
			ref, ok := c.byRef[id]
			if !ok || !c.options.MemoryScope.AllowsPath(ref.Path()) {
				return artifact.Artifact{}, ErrInvestigation
			}
			selected = append(selected, ref)
		}
	default:
		return artifact.Artifact{}, ErrInvestigation
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Ref() < selected[j].Ref() })
	required := map[string]bool{}
	for _, item := range c.current.EvidenceItems() {
		ref, ok := c.byPath[item.SourceRange().Path()]
		if !ok {
			return artifact.Artifact{}, ErrInvestigation
		}
		required[ref.ArtifactIdentity()] = true
	}
	for _, ref := range selected {
		required[ref.ArtifactIdentity()] = true
	}
	ids := []string{}
	for id := range required {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	values := []artifact.Artifact{}
	for _, id := range ids {
		value, ok := c.files[id]
		if !ok {
			return artifact.Artifact{}, ErrInvestigation
		}
		values = append(values, value)
	}
	b := InvestigationToolEvidence{Policy: c.options.Policy, ReaderLimits: c.readerLimits, Context: c.current, ContextArtifact: c.currentArtifact, HeadArtifact: c.head, TurnArtifact: turnArtifact, SourceArtifacts: values}
	e := InvestigationToolExpectations{Scope: c.options.Scope, Deadline: c.options.Deadline, SessionIdentity: c.binding.Identity(), PolicyIdentity: c.options.Policy.Identity(), OwnerIdentity: c.ownerIdentity, ContextArtifactIdentity: c.currentArtifact.Identity(), ContextIdentity: c.current.Identity(), RequestIdentity: turn.RequestIdentity(), HeadArtifactIdentity: c.head.Identity(), HeadSnapshotIdentity: c.snapshot.Identity(), HeadManifestIdentity: c.snapshot.ManifestIdentity(), TurnArtifactIdentity: turnArtifact.Identity(), TurnIdentity: turn.Identity(), PreviousTurnIdentity: turn.PreviousTurnIdentity(), OutcomeIdentity: turn.Outcome().Identity(), ResponseIdentity: turn.Dispatch().Response().Identity(), SourceArtifactIdentities: ids}
	o, err := NewInvestigationToolOperation(b, e, c.options.Clock.Now())
	if err != nil || c.operations[o.Identity()] {
		return artifact.Artifact{}, ErrInvestigation
	}
	chosenReader, chosenLimits := c.reader, c.readerLimits
	payloadBound, envelopeBound, provenance, err := EstimateInvestigationToolResultArtifactBytes(o)
	if err != nil {
		return artifact.Artifact{}, ErrInvestigation
	}
	// Full-first, at most two metadata candidates. Only raw-payload overflow can
	// select the pre-created lower projection. Never optimize another failed gate.
	if payloadBound > c.options.Policy.MaxResultBytes() {
		if c.lowerLimits == c.readerLimits {
			return artifact.Artifact{}, ErrInvestigation
		}
		b.ReaderLimits = c.lowerLimits
		lower, lowerErr := NewInvestigationToolOperation(b, e, c.options.Clock.Now())
		if lowerErr != nil || lower.Identity() != o.Identity() {
			return artifact.Artifact{}, ErrInvestigation
		}
		o = lower
		chosenReader, chosenLimits = c.lowerReader, c.lowerLimits
		payloadBound, envelopeBound, provenance, err = EstimateInvestigationToolResultArtifactBytes(o)
	}
	if err != nil || payloadBound > c.options.Policy.MaxResultBytes() || envelopeBound > 22<<20 || provenance > 32 || envelopeBound > c.options.Policy.MaxReturnedBytes()-c.returned {
		return artifact.Artifact{}, ErrInvestigation
	}
	physicalIDs := []string{}
	var scan uint64
	if proposal.Tool() != "snapshot.list" {
		for _, ref := range selected {
			physicalIDs = append(physicalIDs, ref.ArtifactIdentity())
			scan += uint64(ref.SizeBytes())
		}
		sort.Strings(physicalIDs)
	}
	if scan > c.options.Policy.MaxScannedBytes()-c.scanned || !c.sourceView(physicalIDs) || len(c.candidates)+c.readerLimits.MaxMatches > 128 {
		return artifact.Artifact{}, ErrInvestigation
	}
	c.calls[proposal.CallID()] = true
	c.operations[o.Identity()] = true
	if err = c.appendToolEvent(ctx, audit.EventInvestigationToolClaimed, o.Identity(), []string{c.binding.Identity(), c.head.Identity(), turn.Identity(), turn.Outcome().Identity(), turn.Dispatch().Response().Identity()}, o.Identity(), c.options.Clock.Now()); err != nil {
		return artifact.Artifact{}, err
	}
	// Reserve before physical work. Unknown work remains reserved and terminal.
	c.reservedScan = scan
	c.reservedReturn = envelopeBound
	started := c.options.Clock.Now()
	var invocation InvestigationToolInvocation
	switch proposal.Tool() {
	case "snapshot.list":
		value, readErr := chosenReader.List(ctx)
		if readErr != nil {
			return artifact.Artifact{}, readErr
		}
		invocation, err = newInvestigationListingInvocation(o, turn, uint64(len(c.tools)+1), chosenLimits, physicalIDs, started, c.options.Clock.Now(), value)
	case "snapshot.read":
		value, readErr := chosenReader.Read(ctx, proposal.FileRef(), proposal.StartLine(), proposal.EndLine())
		if readErr != nil {
			return artifact.Artifact{}, readErr
		}
		c.scanned += value.ScannedBytes()
		c.reservedScan = 0
		invocation, err = newInvestigationReadInvocation(o, turn, uint64(len(c.tools)+1), chosenLimits, physicalIDs, started, c.options.Clock.Now(), value)
	case "snapshot.search":
		value, readErr := chosenReader.Search(ctx, o.FileRefs(), proposal.Literal())
		if readErr != nil {
			return artifact.Artifact{}, readErr
		}
		c.scanned += value.ScannedBytes()
		c.reservedScan = 0
		invocation, err = newInvestigationSearchInvocation(o, turn, uint64(len(c.tools)+1), chosenLimits, physicalIDs, started, c.options.Clock.Now(), selected, value)
	}
	if err != nil || c.live(ctx) != nil {
		return artifact.Artifact{}, ErrInvestigation
	}
	for _, id := range physicalIDs {
		if !c.capture.captured(id) {
			return artifact.Artifact{}, ErrInvestigation
		}
	}
	e.OperationIdentity = o.Identity()
	e.InvocationIdentity = invocation.Identity()
	value, err := newToolResultArtifact(proposal.Tool(), o, b, invocation, e, c.options.Clock.Now())
	if err != nil {
		return artifact.Artifact{}, err
	}
	encoded, err := artifact.Encode(value)
	if err != nil || uint64(len(encoded)) > envelopeBound || uint64(value.PayloadSizeBytes()) > payloadBound {
		return artifact.Artifact{}, ErrInvestigation
	}
	if err = c.put(ctx, value); err != nil {
		return artifact.Artifact{}, err
	}
	c.returned += uint64(len(encoded))
	c.reservedReturn = 0
	result, err := buildToolResult(o, invocation)
	if err != nil {
		return artifact.Artifact{}, err
	}
	for _, source := range result.Sources() {
		ref, ok := c.byPath[source.EvidenceItem().SourceRange().Path()]
		if !ok {
			return artifact.Artifact{}, ErrInvestigation
		}
		if err = c.holdSource(source, ref.ArtifactIdentity()); err != nil {
			return artifact.Artifact{}, err
		}
	}
	if err = c.appendToolEvent(ctx, audit.EventInvestigationToolCompleted, value.Identity(), []string{o.Identity(), turn.Identity(), c.head.Identity()}, o.Identity(), c.options.Clock.Now()); err != nil {
		return artifact.Artifact{}, err
	}
	c.tools = append(c.tools, investigationHeldTool{o, invocation, result, value})
	return value, nil
}
func (c *Investigation) Verify(ctx context.Context) (InvestigationVerification, error) {
	work, end, err := c.begin(ctx)
	if err != nil {
		return InvestigationVerification{}, err
	}
	defer end()
	if c.finalCustody == nil {
		return InvestigationVerification{}, ErrInvestigation
	}
	if c.verification.result.Identity() != "" {
		return InvestigationVerification{}, ErrInvestigation
	}
	result, err := c.verify(work)
	if err != nil {
		c.freeze()
		return InvestigationVerification{}, err
	}
	c.verification = result
	return result, nil
}
func (c *Investigation) verify(ctx context.Context) (InvestigationVerification, error) {
	g := c.generation
	if g.witness == nil || !g.witness.live(c.options.Clock.Now()) || g.FinalTurn().Authorization().RouteRecordIdentity() != c.pin {
		return InvestigationVerification{}, ErrInvestigation
	}
	verificationContext, err := review.NewInvestigationVerificationRequestContext(g.Context(), g.Candidates())
	if err != nil {
		return InvestigationVerification{}, err
	}
	request, err := verificationContext.ProviderRequest()
	if err != nil {
		return InvestigationVerification{}, err
	}
	for _, route := range c.options.Routing.Verification {
		if gateway.VerifyIndependentRouteCandidate(c.options.Routing.Independence, g.FinalTurn().Authorization(), route) != nil {
			return InvestigationVerification{}, ErrInvestigation
		}
	}
	authorization, err := c.plan(request, c.options.Routing.Verification, c.options.Routing.VerificationRanking, c.owner.State().RemainingCostMicroUSD())
	if err != nil || gateway.VerifyIndependentRouteAuthorizations(c.options.Routing.Independence, g.FinalTurn().Authorization(), authorization) != nil {
		return InvestigationVerification{}, ErrInvestigation
	}
	turn, _, err := c.dispatch(ctx, gateway.InvestigationVerificationTurn, request)
	if err != nil {
		return InvestigationVerification{}, err
	}
	if turn.Authorization().Identity() != authorization.Identity() {
		return InvestigationVerification{}, ErrInvestigation
	}
	verification, err := review.ParseVerificationBatch(turn.Dispatch().Response(), g.Candidates(), verificationContext.EvidenceItems())
	if err != nil {
		return InvestigationVerification{}, err
	}
	output, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputVerificationBatch, verificationContext.Identity(), verification.Identity(), request, turn.Authorization(), turn.Outcome())
	if err != nil {
		return InvestigationVerification{}, err
	}
	execution, err := gateway.NewRouteExecutionRecord(turn.Authorization(), turn.Outcome(), turn.Reconciliation(), output)
	if err != nil {
		return InvestigationVerification{}, err
	}
	independence, err := gateway.VerifyIndependentRouteAttempts(c.options.Routing.Independence, g.FinalTurn().Authorization(), g.FinalTurn().Outcome(), turn.Authorization(), turn.Outcome())
	if err != nil {
		return InvestigationVerification{}, err
	}
	independent, err := review.NewIndependentVerificationReceiptFromRecords(review.IndependentVerificationRecords{ReviewScopeIdentity: c.options.Scope.Identity(), SnapshotIdentity: g.Candidates().SnapshotIdentity(), GenerationContextIdentity: g.ContextIdentity(), VerificationContextIdentity: verificationContext.Identity(), GenerationRequestIdentity: g.FinalTurn().RequestIdentity(), VerificationRequestIdentity: request.Identity(), Candidates: g.Candidates(), CandidateOutput: g.RouteExecution().Output(), Verification: verification, VerificationOutput: output, RouteIndependence: independence})
	if err != nil {
		return InvestigationVerification{}, err
	}
	findings, err := review.PromoteVerifiedCandidates(independent, g.Candidates(), verification)
	if err != nil {
		return InvestigationVerification{}, err
	}
	result, err := newVerificationResult(g.ResultArtifact().Identity(), verificationContext, verification, execution, independence, independent, findings)
	if err != nil {
		return InvestigationVerification{}, err
	}
	payload, err := encodeVerificationResult(result)
	if err != nil {
		return InvestigationVerification{}, err
	}
	value, err := c.newArtifact(artifact.KindVerifiedFindingSet, artifact.OriginIndependentVerifier, []string{g.ResultArtifact().Identity(), g.InputArtifact().Identity(), g.ContextArtifact().Identity(), verification.Identity(), execution.Identity(), turn.Authorization().Identity(), turn.Outcome().Identity(), turn.Reconciliation().Identity(), output.Identity(), independence.Identity(), independent.Identity(), findings.Identity()}, payload)
	if err != nil {
		return InvestigationVerification{}, err
	}
	if err = c.put(ctx, value); err != nil {
		return InvestigationVerification{}, err
	}
	result.artifactIdentity = value.Identity()
	return InvestigationVerification{result: result, turn: turn, artifact: value}, nil
}
func (c *Investigation) String() string          { return "bounded investigation controller" }
func (c *Investigation) GoString() string        { return "model.Investigation{<redacted>}" }
func (g InvestigationGeneration) String() string { return "owned investigation generation" }
func (g InvestigationGeneration) GoString() string {
	return "model.InvestigationGeneration{<redacted>}"
}
func (s InvestigationStep) String() string   { return "investigation step" }
func (s InvestigationStep) GoString() string { return "model.InvestigationStep{<redacted>}" }

type InvestigationVerification struct {
	result   VerificationResult
	turn     gateway.InvestigationTurnRecord
	artifact artifact.Artifact
}

func (v InvestigationVerification) Context() review.VerificationRequestContext {
	return v.result.VerificationContext()
}
func (v InvestigationVerification) FinalTurn() gateway.InvestigationTurnRecord { return v.turn }
func (v InvestigationVerification) IndependentReceipt() review.IndependentVerificationReceipt {
	return v.result.IndependentReceipt()
}
func (v InvestigationVerification) VerifiedFindings() review.VerifiedFindingSet {
	return v.result.VerifiedFindings()
}
func (v InvestigationVerification) ResultArtifact() artifact.Artifact { return v.artifact }
func (v InvestigationVerification) RouteExecution() gateway.RouteExecutionRecord {
	return v.result.RouteExecution()
}
func (v InvestigationVerification) String() string { return "owned investigation verification" }
func (v InvestigationVerification) GoString() string {
	return "model.InvestigationVerification{<redacted>}"
}
