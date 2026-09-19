package model

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	analysis "github.com/georgejieh/open-trestle/handlers/analysis"
	change "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
)

var ErrInvestigationPipeline = errors.New("investigation pipeline unavailable or inconsistent")
var ErrInvestigationPipelineDrain = errors.New("investigation pipeline work has not drained")

type InvestigationPipelineProfileOptions struct {
	RuntimePolicyIdentity, InventoryIdentity        string
	ReviewPolicyIdentity, PublicationPolicyIdentity string
	PublicationPolicy                               review.PublicationPolicy
	DispatcherCatalogIdentity                       string
	Policy                                          review.InvestigationPolicy
	Routing                                         InvestigationRoutingOptions
}
type InvestigationPipelineProfile struct {
	identity string
	options  InvestigationPipelineProfileOptions
}

func pipelineObservations(r InvestigationRoutingOptions, routes []gateway.ObservedRouteCandidate) []provider.RoutePerformanceObservation {
	out := []provider.RoutePerformanceObservation{}
	for _, route := range routes {
		for _, o := range r.Observations {
			if o.RecordIdentity() == route.ResolvedRecord().RouteRegistryRecord().Identity() {
				out = append(out, o)
				break
			}
		}
	}
	return out
}
func pipelineRoutingCopy(r InvestigationRoutingOptions) InvestigationRoutingOptions {
	r.Verification = append([]gateway.ObservedRouteCandidate(nil), r.Verification...)
	r.Observations = append([]provider.RoutePerformanceObservation(nil), r.Observations...)
	return r
}
func NewInvestigationPipelineProfile(o InvestigationPipelineProfileOptions) (InvestigationPipelineProfile, error) {
	for _, id := range []string{o.RuntimePolicyIdentity, o.InventoryIdentity, o.ReviewPolicyIdentity, o.PublicationPolicyIdentity, o.DispatcherCatalogIdentity} {
		if !validDigest(id) {
			return InvestigationPipelineProfile{}, ErrInvestigationPipeline
		}
	}
	r := o.Routing
	if o.PublicationPolicy.Validate() != nil || o.PublicationPolicy.Identity() != o.PublicationPolicyIdentity {
		return InvestigationPipelineProfile{}, ErrInvestigationPipeline
	}
	if o.Policy.ValidateRuntimeBudget(r.Budget) != nil || r.Budget.MaxCostMicroUSD() != o.Policy.MaxCostMicroUSD() || r.Generation.Validate() != nil || r.Requirements.Validate() != nil || r.Constraints.Validate() != nil || r.Independence.Validate() != nil || r.VerificationRanking.Validate() != nil || len(r.Verification) == 0 || len(r.Verification) > 64 {
		return InvestigationPipelineProfile{}, ErrInvestigationPipeline
	}
	pin, err := gateway.NewPinnedRouteRankingPolicy(r.Generation.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	if err != nil {
		return InvestigationPipelineProfile{}, err
	}
	gp, err := gateway.NewInvestigationRoutePlan(r.RegistryRevision, []gateway.ObservedRouteCandidate{r.Generation}, pin, r.PerformanceRevision, pipelineObservations(r, []gateway.ObservedRouteCandidate{r.Generation}))
	if err != nil {
		return InvestigationPipelineProfile{}, err
	}
	vp, err := gateway.NewInvestigationRoutePlan(r.RegistryRevision, r.Verification, r.VerificationRanking, r.PerformanceRevision, pipelineObservations(r, r.Verification))
	if err != nil {
		return InvestigationPipelineProfile{}, err
	}
	seen := map[string]bool{r.Generation.ResolvedRecord().RouteRegistryRecord().Identity(): true}
	for _, v := range r.Verification {
		id := v.ResolvedRecord().RouteRegistryRecord().Identity()
		if seen[id] {
			return InvestigationPipelineProfile{}, ErrInvestigationPipeline
		}
		seen[id] = true
	}
	if len(r.Observations) != len(seen) {
		return InvestigationPipelineProfile{}, ErrInvestigationPipeline
	}
	observed := map[string]bool{}
	for _, v := range r.Observations {
		if !seen[v.RecordIdentity()] || observed[v.RecordIdentity()] || v.Validate() != nil || v.ObservationRevision() != r.PerformanceRevision {
			return InvestigationPipelineProfile{}, ErrInvestigationPipeline
		}
		observed[v.RecordIdentity()] = true
	}
	features := []string{}
	for _, f := range r.Requirements.RequiredFeatures() {
		features = append(features, f.String())
	}
	sort.Strings(features)
	zones := []string{}
	for z := provider.ProviderZoneLocal; z <= provider.ProviderZoneSubscriptionOAuth; z++ {
		if r.Constraints.AllowedProviderZones().Allows(z) {
			zones = append(zones, z.String())
		}
	}
	id := toolRecordIdentity([]any{"open-trestle/investigation-pipeline-profile", 1, o.RuntimePolicyIdentity, o.InventoryIdentity, o.ReviewPolicyIdentity, o.PublicationPolicyIdentity, o.Policy.Identity(), o.DispatcherCatalogIdentity, gp.Identity(), vp.Identity(), []any{r.Requirements.MinContextTokens(), r.Requirements.MinOutputTokens(), features}, []any{string(r.Constraints.Classification()), zones, r.Constraints.ContentLoggingAllowed()}, []any{r.Budget.EstimatedInputTokens(), r.Budget.MaxOutputTokens(), r.Budget.MaxCostMicroUSD()}, r.Independence.Identity(), "fixed_generation_route_v1", "foreground_single_runner_v1", "initial_selected_only_v1", "full_then_half_raw_overflow_v1", "live_journal_custody_v1"})
	o.Routing = pipelineRoutingCopy(r)
	return InvestigationPipelineProfile{id, o}, nil
}
func (p InvestigationPipelineProfile) Identity() string { return p.identity }
func (p InvestigationPipelineProfile) Validate() error {
	q, err := NewInvestigationPipelineProfile(p.options)
	if err != nil || p.identity == "" || q.identity != p.identity {
		return ErrInvestigationPipeline
	}
	return nil
}
func (p InvestigationPipelineProfile) Policy() review.InvestigationPolicy { return p.options.Policy }
func (p InvestigationPipelineProfile) Routing() InvestigationRoutingOptions {
	return pipelineRoutingCopy(p.options.Routing)
}
func (p InvestigationPipelineProfile) ReviewPolicyIdentity() string {
	return p.options.ReviewPolicyIdentity
}
func (p InvestigationPipelineProfile) PublicationPolicyIdentity() string {
	return p.options.PublicationPolicyIdentity
}
func (p InvestigationPipelineProfile) PublicationPolicy() review.PublicationPolicy {
	return p.options.PublicationPolicy
}
func (p InvestigationPipelineProfile) DispatcherCatalogIdentity() string {
	return p.options.DispatcherCatalogIdentity
}

type InvestigationSupportBindings struct{ Change, Analysis, Memory string }
type InvestigationPipelineOptions struct {
	Profile InvestigationPipelineProfile
	Store   artifact.Store
	Ledger  audit.Ledger
	Journal controlplane.RunJournal
	Clock   artifact.Clock
	Catalog gateway.RouteDispatcherCatalog
	Source  scm.SourceAdapter
	Support InvestigationSupportBindings
}
type InvestigationAssembly struct {
	Packet                                           review.ContextPacket
	Snapshot                                         review.ReviewSnapshot
	MemoryScope                                      memory.Scope
	InitialContextArtifact                           artifact.Artifact
	AnalysisArtifact, MemoryArtifact, ChangeArtifact artifact.Artifact
	BaseSnapshotArtifact, HeadSnapshotArtifact       artifact.Artifact
}
type pipelineOperationKey struct{}
type pipelineOperation struct {
	owner *InvestigationPipeline
	role  string
	done  chan struct{}
}
type pipelineCaptureEntry struct {
	value         artifact.Artifact
	raw, envelope uint64
	known         bool
	role          string
}
type pipelineCaptureStore struct{ owner *InvestigationPipeline }
type InvestigationPipeline struct {
	mu                                                                 sync.Mutex
	options                                                            InvestigationPipelineOptions
	identity                                                           string
	coordinator                                                        *controlplane.Coordinator
	acquisition                                                        *InvestigationAcquisitionHandler
	capture                                                            *pipelineCaptureStore
	started, failed, closing, closed                                   bool
	active                                                             *pipelineOperation
	plan                                                               controlplane.ReviewRunPlan
	root                                                               context.Context
	cancel                                                             context.CancelFunc
	deadline, wallDeadline                                             time.Time
	assembly                                                           InvestigationAssembly
	initialStored, intent                                              artifact.Artifact
	headHandle                                                         *InvestigationAcquisition
	controller                                                         *Investigation
	generation                                                         InvestigationGeneration
	verification                                                       InvestigationVerification
	generationAttempted, verificationAttempted                         bool
	captures                                                           map[string]*pipelineCaptureEntry
	turnCount, toolCount, turnRaw, turnEnvelope, toolRaw, toolEnvelope uint64
	captureUncertain                                                   bool
}

func NewInvestigationPipeline(o InvestigationPipelineOptions) (*InvestigationPipeline, error) {
	if o.Profile.Validate() != nil || nilInterface(o.Store) || nilInterface(o.Ledger) || nilInterface(o.Journal) || nilInterface(o.Clock) || nilInterface(o.Source) || o.Catalog.Validate() != nil || o.Catalog.Identity() != o.Profile.DispatcherCatalogIdentity() {
		return nil, ErrInvestigationPipeline
	}
	for _, id := range []string{o.Support.Change, o.Support.Analysis, o.Support.Memory} {
		if !validDigest(id) {
			return nil, ErrInvestigationPipeline
		}
	}
	co, err := controlplane.NewCoordinator(o.Journal)
	if err != nil {
		return nil, ErrInvestigationPipeline
	}
	p := &InvestigationPipeline{options: o, coordinator: co, identity: toolRecordIdentity([]any{"open-trestle/investigation-pipeline", 1, o.Profile.Identity()}), captures: map[string]*pipelineCaptureEntry{}}
	p.capture = &pipelineCaptureStore{p}
	p.acquisition, err = NewInvestigationAcquisitionHandler(p.capture, o.Source, o.Clock)
	if err != nil {
		return nil, err
	}
	return p, nil
}
func (p *InvestigationPipeline) Identity() string {
	if p == nil {
		return ""
	}
	return p.identity
}
func (p *InvestigationPipeline) Profile() InvestigationPipelineProfile {
	if p == nil {
		return InvestigationPipelineProfile{}
	}
	return p.options.Profile
}
func (p *InvestigationPipeline) Validate() error {
	if p == nil || p.options.Profile.Validate() != nil || p.acquisition == nil || p.acquisition.Validate() != nil || p.capture == nil || p.capture.owner != p || p.identity != toolRecordIdentity([]any{"open-trestle/investigation-pipeline", 1, p.options.Profile.Identity()}) || nilInterface(p.options.Store) || nilInterface(p.options.Ledger) || nilInterface(p.options.Journal) || nilInterface(p.options.Clock) || p.options.Catalog.Validate() != nil {
		return ErrInvestigationPipeline
	}
	return nil
}
func (p *InvestigationPipeline) HandlerIdentity(kind controlplane.TaskKind) (string, error) {
	if p == nil {
		return "", ErrInvestigationPipeline
	}
	profile := p.options.Profile
	switch kind {
	case controlplane.TaskAcquireSource:
		return p.acquisition.HandlerIdentity(), nil
	case controlplane.TaskBuildChange:
		return p.options.Support.Change, nil
	case controlplane.TaskInspectDeterministic:
		return p.options.Support.Analysis, nil
	case controlplane.TaskRetrieveContext:
		return p.options.Support.Memory, nil
	case controlplane.TaskAssembleContext:
		return toolRecordIdentity([]any{"open-trestle/investigation-context-task-handler", 1, profile.Identity()}), nil
	case controlplane.TaskGenerateCandidates:
		return toolRecordIdentity([]any{"open-trestle/investigation-generation-task-handler", 1, profile.Identity()}), nil
	case controlplane.TaskVerifyCandidates:
		return toolRecordIdentity([]any{"open-trestle/investigation-verification-task-handler", 1, profile.Identity()}), nil
	case controlplane.TaskEvaluatePublication:
		return toolRecordIdentity([]any{"open-trestle/investigation-readiness-task-handler", 1, profile.Identity(), profile.ReviewPolicyIdentity(), profile.PublicationPolicyIdentity()}), nil
	}
	return "", ErrInvestigationPipeline
}
func (p *InvestigationPipeline) begin(ctx context.Context, role string) (context.Context, func(), error) {
	if p == nil || nilInterface(ctx) || ctx.Err() != nil {
		return nil, nil, ErrInvestigationPipeline
	}
	p.mu.Lock()
	if p.closed || p.closing || p.active != nil || role == "start" && p.started || role != "start" && !p.started || role != "readback" && (p.failed || p.started && p.root.Err() != nil) {
		p.mu.Unlock()
		return nil, nil, ErrInvestigationPipeline
	}
	op := &pipelineOperation{p, role, make(chan struct{})}
	p.active = op
	root, deadline := p.root, p.wallDeadline
	p.mu.Unlock()
	work := ctx
	cancel := func() {}
	stop := func() bool { return true }
	if role != "start" && role != "readback" {
		work, cancel = context.WithDeadline(ctx, deadline)
		stop = context.AfterFunc(root, cancel)
	}
	work = context.WithValue(work, pipelineOperationKey{}, op)
	return work, func() {
		stop()
		cancel()
		p.mu.Lock()
		if p.active == op {
			p.active = nil
			close(op.done)
		}
		p.mu.Unlock()
	}, nil
}
func (p *InvestigationPipeline) fail() {
	p.mu.Lock()
	p.failed = true
	cancel := p.cancel
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
func (p *InvestigationPipeline) checkPlan(plan controlplane.ReviewRunPlan) error {
	if plan.Validate() != nil || plan.Mode() != controlplane.ReviewRunLocal || plan.PolicyIdentity() != p.options.Profile.ReviewPolicyIdentity() || plan.TaskCount() != 9 {
		return ErrInvestigationPipeline
	}
	specs := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}}, {"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}}, {"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}}, {"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}}, {"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}}}
	for _, spec := range specs {
		task, ok := plan.Task(spec.key)
		id, err := p.HandlerIdentity(spec.kind)
		attempt, aerr := controlplane.DefaultTaskAttemptPolicy(spec.kind)
		if !ok || err != nil || aerr != nil || task.Kind() != spec.kind || task.HandlerIdentity() != id || !task.Required() || !slices.Equal(task.Dependencies(), spec.deps) || task.MaxAttempts() != attempt.MaximumAttempts() || task.RetryDelayMilliseconds() != attempt.RetryDelayMilliseconds() || task.LeaseDurationMilliseconds() != attempt.LeaseDurationMilliseconds() {
			return ErrInvestigationPipeline
		}
	}
	return nil
}
func (p *InvestigationPipeline) StartRun(ctx context.Context, plan controlplane.ReviewRunPlan) error {
	work, end, err := p.begin(ctx, "start")
	if err != nil {
		return err
	}
	defer end()
	if p.checkPlan(plan) != nil {
		return ErrInvestigationPipeline
	}
	actual, state, err := p.coordinator.Resume(work, plan.Scope())
	if err != nil || actual.Identity() != plan.Identity() || state.Status() != controlplane.ReviewRunActive {
		return ErrInvestigationPipeline
	}
	for _, task := range plan.Tasks() {
		s, ok := state.Task(task.Key())
		if !ok || s.Attempts() != 0 || s.OutputIdentity() != "" {
			return ErrInvestigationPipeline
		}
	}
	at := p.options.Clock.Now()
	span := time.Duration(p.options.Profile.Policy().TimeoutMilliseconds()) * time.Millisecond
	if d, ok := ctx.Deadline(); ok {
		span = min(span, time.Until(d))
	}
	if at.UnixMilli() <= 0 || span <= 0 {
		return ErrInvestigationPipeline
	}
	root, cancel := context.WithTimeout(ctx, span)
	p.mu.Lock()
	p.plan = plan
	p.root = root
	p.cancel = cancel
	p.deadline = time.UnixMilli(at.Add(span).UnixMilli()).UTC()
	p.wallDeadline = time.Now().Add(span)
	p.started = true
	p.mu.Unlock()
	return nil
}
func (p *InvestigationPipeline) state(ctx context.Context) (controlplane.ReviewRunState, error) {
	plan, state, err := p.coordinator.Resume(ctx, p.plan.Scope())
	if err != nil || plan.Identity() != p.plan.Identity() || state.Validate() != nil {
		return controlplane.ReviewRunState{}, ErrInvestigationPipeline
	}
	return state, nil
}
func (p *InvestigationPipeline) task(ctx context.Context, r controlplane.TaskExecutionRequest, key string) (controlplane.ReviewRunState, error) {
	if r.Validate() != nil || r.Plan().Identity() != p.plan.Identity() || r.Task().Key() != key {
		return controlplane.ReviewRunState{}, ErrInvestigationPipeline
	}
	s, err := p.state(ctx)
	if err != nil || s.Status() != controlplane.ReviewRunActive {
		return controlplane.ReviewRunState{}, ErrInvestigationPipeline
	}
	task, ok := s.Task(key)
	expected, found := p.plan.Task(key)
	lease := r.Lease()
	at := p.options.Clock.Now()
	if !ok || !found || expected.Identity() != r.Task().Identity() || task.Status() != controlplane.TaskRuntimeLeased || !pipelineLeaseMatches(lease, task.LeaseTokenIdentity()) || task.Attempts() != lease.Attempt() || task.WorkerIdentity() != lease.WorkerIdentity() || !at.Before(task.LeaseExpiresAt()) || !at.Before(p.deadline) {
		return controlplane.ReviewRunState{}, ErrInvestigationPipeline
	}
	for _, key := range expected.Dependencies() {
		dep, ok := r.DependencyOutput(key)
		actual, found := s.Task(key)
		if !ok || !found || !dep.Available() || actual.Status() != controlplane.TaskRuntimeSucceeded || dep.TaskIdentity() != actual.Definition().Identity() || dep.OutputIdentity() != actual.OutputIdentity() {
			return controlplane.ReviewRunState{}, ErrInvestigationPipeline
		}
	}
	return s, nil
}
func (p *InvestigationPipeline) get(ctx context.Context, id string, kind artifact.Kind) (artifact.Artifact, error) {
	if !validDigest(id) {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	value, err := p.options.Store.Get(ctx, p.plan.Scope(), id, p.options.Clock.Now())
	if err != nil || value.Identity() != id || value.Kind() != kind || value.Scope() != p.plan.Scope() || value.Protection() != artifact.ProtectionProcessPrivate || value.Validate() != nil {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	return value, nil
}
func pipelineOutput(s controlplane.ReviewRunState, key string) (string, error) {
	v, ok := s.Task(key)
	if !ok || v.Status() != controlplane.TaskRuntimeSucceeded || !validDigest(v.OutputIdentity()) {
		return "", ErrInvestigationPipeline
	}
	return v.OutputIdentity(), nil
}

func pipelineLeaseMatches(l controlplane.TaskLease, tokenIdentity string) bool {
	// Bind the validated secret-bearing capability to the actual replayed token digest.
	// Renewals preserve the token; request lease metadata may precede a renewal.
	value := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Plan     string `json:"plan"`
		Key      string `json:"task_key"`
		Task     string `json:"task"`
		Handler  string `json:"handler"`
		Worker   string `json:"worker"`
		Token    string `json:"token"`
		Event    string `json:"event"`
		Attempt  uint8  `json:"attempt"`
		Expires  int64  `json:"expires"`
	}{"open-trestle/task-lease", 1, l.PlanIdentity(), l.TaskKey(), l.TaskIdentity(), l.HandlerIdentity(), l.WorkerIdentity(), tokenIdentity, l.EventIdentity(), l.Attempt(), l.ExpiresAt().UnixMilli()}
	return l.Validate() == nil && toolRecordIdentity(value) == l.Identity()
}

func (s *pipelineCaptureStore) permit(ctx context.Context, history bool) error {
	if s == nil || s.owner == nil || nilInterface(ctx) || ctx.Err() != nil {
		return ErrInvestigationPipeline
	}
	p := s.owner
	op, ok := ctx.Value(pipelineOperationKey{}).(*pipelineOperation)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !ok || op == nil || op.owner != p || p.active != op || p.closing || p.closed || p.failed || !p.started || p.root.Err() != nil {
		return ErrInvestigationPipeline
	}
	if history && op.role != "generation" && op.role != "verification" {
		return ErrInvestigationPipeline
	}
	return nil
}
func (s *pipelineCaptureStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	if s.permit(ctx, false) != nil || scope != s.owner.plan.Scope() {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	return s.owner.options.Store.Get(ctx, scope, id, at)
}
func (s *pipelineCaptureStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	p := s.owner
	history := value.Kind() == artifact.KindInvestigationTurn || value.Kind() == artifact.KindInvestigationToolResult
	if s.permit(ctx, history) != nil || value.Scope() != p.plan.Scope() {
		return false, ErrInvestigationPipeline
	}
	if !history {
		return p.options.Store.Put(ctx, value, at)
	}
	entry, duplicate, err := p.reserveCapture(value)
	if err != nil {
		p.fail()
		return false, err
	}
	if !duplicate {
		encoded, encodeErr := artifact.Encode(value)
		if encodeErr != nil || len(encoded) > 22<<20 {
			p.captureFailed()
			return false, ErrInvestigationPipeline
		}
		if err = p.reserveEnvelope(entry, uint64(len(encoded))); err != nil {
			p.captureFailed()
			return false, err
		}
	}
	if s.permit(ctx, true) != nil {
		p.captureFailed()
		return false, ErrInvestigationPipeline
	}
	inserted, err := p.options.Store.Put(ctx, value, at)
	p.mu.Lock()
	if err == nil {
		entry.known = true
		entry.value = value
	} else {
		p.captureUncertain = true
	}
	p.mu.Unlock()
	if err != nil {
		p.fail()
		return inserted, err
	}
	return inserted, nil
}
func (p *InvestigationPipeline) captureFailed() {
	p.mu.Lock()
	p.captureUncertain = true
	p.mu.Unlock()
	p.fail()
}
func (p *InvestigationPipeline) reserveCapture(v artifact.Artifact) (*pipelineCaptureEntry, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if prior, ok := p.captures[v.Identity()]; ok {
		if !prior.known || !toolRecordSameArtifact(prior.value, v) {
			return nil, false, ErrInvestigationPipeline
		}
		return prior, true, nil
	}
	raw := v.PayloadSizeBytes()
	policy := p.options.Profile.Policy()
	turn := v.Kind() == artifact.KindInvestigationTurn
	if raw <= 0 || v.MediaType() != "application/json" || v.Protection() != artifact.ProtectionProcessPrivate || v.Origin() != artifact.OriginHost && turn || v.Origin() != artifact.OriginDeterministicTool && !turn {
		return nil, false, ErrInvestigationPipeline
	}
	size := uint64(raw)
	if turn {
		if size > 16<<20 || p.turnCount >= policy.MaxModelTurns() || size > policy.MaxModelTurns()*(16<<20)-p.turnRaw {
			return nil, false, ErrInvestigationPipeline
		}
		p.turnCount++
		p.turnRaw += size
	} else {
		cap := min(policy.MaxToolCalls()*policy.MaxResultBytes(), policy.MaxReturnedBytes())
		if size > policy.MaxResultBytes() || p.toolCount >= policy.MaxToolCalls() || size > cap-p.toolRaw {
			return nil, false, ErrInvestigationPipeline
		}
		p.toolCount++
		p.toolRaw += size
	}
	entry := &pipelineCaptureEntry{value: v, raw: size, role: p.active.role}
	p.captures[v.Identity()] = entry
	return entry, false, nil
}
func (p *InvestigationPipeline) reserveEnvelope(entry *pipelineCaptureEntry, size uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	policy := p.options.Profile.Policy()
	if entry.envelope != 0 || entry.known {
		return ErrInvestigationPipeline
	}
	if entry.value.Kind() == artifact.KindInvestigationTurn {
		if size > policy.MaxModelTurns()*(22<<20)-p.turnEnvelope {
			return ErrInvestigationPipeline
		}
		p.turnEnvelope += size
	} else {
		if size > policy.MaxReturnedBytes()-p.toolEnvelope {
			return ErrInvestigationPipeline
		}
		p.toolEnvelope += size
	}
	entry.envelope = size
	return nil
}
func (p *InvestigationPipeline) Close(ctx context.Context) error {
	if p == nil || nilInterface(ctx) {
		return ErrInvestigationPipelineDrain
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closing = true
	cancel, active := p.cancel, p.active
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if active != nil {
		select {
		case <-active.done:
		case <-ctx.Done():
			return ErrInvestigationPipelineDrain
		}
	}
	p.mu.Lock()
	controller := p.controller
	p.mu.Unlock()
	if controller != nil {
		if err := controller.Close(ctx); err != nil {
			return ErrInvestigationPipelineDrain
		}
	}
	if err := p.acquisition.Close(ctx); err != nil {
		return ErrInvestigationPipelineDrain
	}
	p.mu.Lock()
	p.closed = true
	p.closing = false
	p.captures = nil
	p.assembly = InvestigationAssembly{}
	p.generation = InvestigationGeneration{}
	p.verification = InvestigationVerification{}
	p.headHandle = nil
	p.mu.Unlock()
	return nil
}

type InvestigationSourceTaskHandler struct{ pipeline *InvestigationPipeline }
type InvestigationGenerationTaskHandler struct{ pipeline *InvestigationPipeline }
type InvestigationVerificationTaskHandler struct{ pipeline *InvestigationPipeline }

func NewInvestigationSourceTaskHandler(p *InvestigationPipeline) (*InvestigationSourceTaskHandler, error) {
	if p.Validate() != nil {
		return nil, ErrInvestigationPipeline
	}
	return &InvestigationSourceTaskHandler{p}, nil
}
func NewInvestigationGenerationTaskHandler(p *InvestigationPipeline) (*InvestigationGenerationTaskHandler, error) {
	if p.Validate() != nil {
		return nil, ErrInvestigationPipeline
	}
	return &InvestigationGenerationTaskHandler{p}, nil
}
func NewInvestigationVerificationTaskHandler(p *InvestigationPipeline) (*InvestigationVerificationTaskHandler, error) {
	if p.Validate() != nil {
		return nil, ErrInvestigationPipeline
	}
	return &InvestigationVerificationTaskHandler{p}, nil
}
func (h *InvestigationSourceTaskHandler) Kind() controlplane.TaskKind {
	return controlplane.TaskAcquireSource
}
func (h *InvestigationGenerationTaskHandler) Kind() controlplane.TaskKind {
	return controlplane.TaskGenerateCandidates
}
func (h *InvestigationVerificationTaskHandler) Kind() controlplane.TaskKind {
	return controlplane.TaskVerifyCandidates
}
func (h *InvestigationSourceTaskHandler) HandlerIdentity() string {
	if h == nil || h.pipeline == nil {
		return ""
	}
	id, _ := h.pipeline.HandlerIdentity(h.Kind())
	return id
}
func (h *InvestigationGenerationTaskHandler) HandlerIdentity() string {
	if h == nil || h.pipeline == nil {
		return ""
	}
	id, _ := h.pipeline.HandlerIdentity(h.Kind())
	return id
}
func (h *InvestigationVerificationTaskHandler) HandlerIdentity() string {
	if h == nil || h.pipeline == nil {
		return ""
	}
	id, _ := h.pipeline.HandlerIdentity(h.Kind())
	return id
}
func (h *InvestigationSourceTaskHandler) Validate() error {
	if h == nil {
		return ErrInvestigationPipeline
	}
	return h.pipeline.Validate()
}
func (h *InvestigationGenerationTaskHandler) Validate() error {
	if h == nil {
		return ErrInvestigationPipeline
	}
	return h.pipeline.Validate()
}
func (h *InvestigationVerificationTaskHandler) Validate() error {
	if h == nil {
		return ErrInvestigationPipeline
	}
	return h.pipeline.Validate()
}
func pipelineFailure(ctx context.Context, err error) controlplane.TaskCompletion {
	failure := controlplane.RunFailurePolicy
	if ctx != nil && ctx.Err() != nil {
		failure = controlplane.RunFailureCanceled
	} else if errors.Is(err, artifact.ErrStoreCapacity) {
		failure = controlplane.RunFailureResourceLimit
	}
	return generationFailure(failure)
}
func (h *InvestigationSourceTaskHandler) Execute(ctx context.Context, r controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h.Validate() != nil || r.Task().Kind() != h.Kind() || r.Task().HandlerIdentity() != h.HandlerIdentity() || (r.Task().Key() != "source-base" && r.Task().Key() != "source-head") {
		return pipelineFailure(ctx, ErrInvestigationPipeline)
	}
	p := h.pipeline
	work, end, err := p.begin(ctx, "source")
	if err != nil {
		return pipelineFailure(ctx, err)
	}
	defer end()
	if _, err = p.task(work, r, r.Task().Key()); err != nil {
		return pipelineFailure(ctx, err)
	}
	completion := p.acquisition.Execute(work, r)
	if completion.Status() != controlplane.TaskCompletionSucceeded {
		p.fail()
	}
	return completion
}
func (h *InvestigationGenerationTaskHandler) Execute(ctx context.Context, r controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h.Validate() != nil || r.Task().Kind() != h.Kind() || r.Task().HandlerIdentity() != h.HandlerIdentity() {
		return pipelineFailure(ctx, ErrInvestigationPipeline)
	}
	p := h.pipeline
	work, end, err := p.begin(ctx, "generation")
	if err != nil {
		return pipelineFailure(ctx, err)
	}
	defer end()
	output, err := p.generate(work, r)
	if err != nil {
		p.fail()
		return pipelineFailure(ctx, err)
	}
	result, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		p.fail()
		return pipelineFailure(ctx, err)
	}
	return result
}
func (h *InvestigationVerificationTaskHandler) Execute(ctx context.Context, r controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h.Validate() != nil || r.Task().Kind() != h.Kind() || r.Task().HandlerIdentity() != h.HandlerIdentity() {
		return pipelineFailure(ctx, ErrInvestigationPipeline)
	}
	p := h.pipeline
	work, end, err := p.begin(ctx, "verification")
	if err != nil {
		return pipelineFailure(ctx, err)
	}
	defer end()
	output, err := p.verify(work, r)
	if err != nil {
		p.fail()
		return pipelineFailure(ctx, err)
	}
	result, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		p.fail()
		return pipelineFailure(ctx, err)
	}
	return result
}

func (p *InvestigationPipeline) headSlot(s controlplane.ReviewRunState) (*InvestigationAcquisition, error) {
	id, err := pipelineOutput(s, "source-head")
	if err != nil {
		return nil, err
	}
	task, ok := p.plan.Task("source-head")
	if !ok {
		return nil, ErrInvestigationPipeline
	}
	at := p.options.Clock.Now()
	h := p.acquisition
	h.mu.Lock()
	defer h.mu.Unlock()
	inv := h.slots[task.Identity()]
	if h.closed || h.closing || h.planIdentity != p.plan.Identity() || inv == nil || inv.handle == nil || inv.failed || h.active == inv || inv.planIdentity != p.plan.Identity() || inv.scopeIdentity != p.plan.Scope().Identity() || inv.taskIdentity != task.Identity() || inv.inputIdentity != task.InputIdentity() || inv.request.Plan().Identity() != p.plan.Identity() || inv.request.Task().Identity() != task.Identity() {
		return nil, ErrInvestigationPipeline
	}
	a := inv.handle
	if a.owner != h || a.taskIdentity != task.Identity() || a.planIdentity != p.plan.Identity() || a.scopeIdentity != p.plan.Scope().Identity() || a.headIdentity != id || a.head.Identity() != id || a.snapshot.ArtifactIdentity() != id || at.Before(a.created) || !at.Before(a.expires) {
		return nil, ErrInvestigationPipeline
	}
	return a, nil
}
func (p *InvestigationPipeline) validateAssembly(ctx context.Context, s controlplane.ReviewRunState, a InvestigationAssembly) (*InvestigationAcquisition, error) {
	pairs := []struct {
		key   string
		kind  artifact.Kind
		value artifact.Artifact
	}{{"source-base", artifact.KindSourceSnapshot, a.BaseSnapshotArtifact}, {"source-head", artifact.KindSourceSnapshot, a.HeadSnapshotArtifact}, {"change", artifact.KindChangeModel, a.ChangeArtifact}, {"analysis", artifact.KindDeterministicEvidence, a.AnalysisArtifact}, {"memory", artifact.KindRetrievalResult, a.MemoryArtifact}}
	for _, pair := range pairs {
		id, err := pipelineOutput(s, pair.key)
		if err != nil {
			return nil, err
		}
		actual, err := p.get(ctx, id, pair.kind)
		if err != nil || !toolRecordSameArtifact(actual, pair.value) {
			return nil, ErrInvestigationPipeline
		}
	}
	changed, err := change.ParseResultArtifact(a.ChangeArtifact, a.BaseSnapshotArtifact, a.HeadSnapshotArtifact)
	if err != nil {
		return nil, ErrInvestigationPipeline
	}
	analyzed, err := analysis.ParseResultArtifact(a.AnalysisArtifact, a.ChangeArtifact, a.BaseSnapshotArtifact, a.HeadSnapshotArtifact)
	if err != nil || analyzed.ChangeIdentity() != changed.Identity() {
		return nil, ErrInvestigationPipeline
	}
	mem, err := memoryhandler.ParseResultArtifact(a.MemoryArtifact, a.ChangeArtifact, a.BaseSnapshotArtifact, a.HeadSnapshotArtifact)
	if err != nil || mem.PolicyIdentity() != p.plan.PolicyIdentity() {
		return nil, ErrInvestigationPipeline
	}
	scope, err := mem.MemoryScope()
	if err != nil || scope.Identity() != a.MemoryScope.Identity() || a.MemoryScope.Validate() != nil || a.MemoryScope.TenantID() != p.plan.Scope().TenantID() || a.MemoryScope.RepositoryID() != p.plan.Scope().RepositoryID() {
		return nil, ErrInvestigationPipeline
	}
	actualRetrievals := []string{}
	for _, q := range mem.Queries() {
		r, err := q.Retrieval(scope, mem.AsOf())
		if err != nil {
			return nil, ErrInvestigationPipeline
		}
		actualRetrievals = append(actualRetrievals, r.Identity())
	}
	claimedRetrievals := []string{}
	for _, r := range a.Packet.Retrievals() {
		if r.Validate() != nil || r.ScopeIdentity() != scope.Identity() {
			return nil, ErrInvestigationPipeline
		}
		claimedRetrievals = append(claimedRetrievals, r.Identity())
	}
	sort.Strings(actualRetrievals)
	sort.Strings(claimedRetrievals)
	if !slices.Equal(actualRetrievals, claimedRetrievals) {
		return nil, ErrInvestigationPipeline
	}
	handle, err := p.headSlot(s)
	if err != nil {
		return nil, err
	}
	head := handle.snapshot
	headTask, _ := p.plan.Task("source-head")
	headInput, err := p.get(ctx, headTask.InputIdentity(), artifact.KindTaskInput)
	if err != nil {
		return nil, err
	}
	in, err := source.ParseInput(headInput.Payload())
	if err != nil || in.Revision().Identity() != head.RevisionIdentity() || changed.HeadRevision().Identity() != head.RevisionIdentity() || changed.HeadSnapshotArtifactIdentity() != a.HeadSnapshotArtifact.Identity() || analyzed.HeadSnapshotIdentity() != head.Identity() {
		return nil, ErrInvestigationPipeline
	}
	if a.Packet.Validate() != nil || a.Snapshot.Validate() != nil || a.Packet.SnapshotIdentity() != a.Snapshot.Identity() || a.Packet.ReviewScopeIdentity() != p.plan.Scope().Identity() || a.Packet.MemoryScopeIdentity() != scope.Identity() || a.Packet.Task() != review.ContextTaskCandidateGeneration || a.Packet.MemoryItemCount() != 0 {
		return nil, ErrInvestigationPipeline
	}
	request, err := a.Packet.ProviderRequest()
	if err != nil {
		return nil, err
	}
	initial := a.InitialContextArtifact
	now := p.options.Clock.Now()
	if initial.PayloadSizeBytes() > 8<<20 || initial.Validate() != nil || initial.Scope() != p.plan.Scope() || initial.Kind() != artifact.KindContextPacket || initial.Origin() != artifact.OriginHost || initial.Protection() != artifact.ProtectionProcessPrivate || initial.Classification() != a.HeadSnapshotArtifact.Classification() || initial.MediaType() != "application/json" || initial.PayloadDigest() != a.Packet.Identity() || !bytes.Equal(initial.Payload(), request.Payload()) || now.Before(initial.CreatedAt()) || !now.Before(initial.ExpiresAt()) {
		return nil, ErrInvestigationPipeline
	}
	for _, id := range []string{a.AnalysisArtifact.Identity(), a.MemoryArtifact.Identity(), a.ChangeArtifact.Identity(), a.HeadSnapshotArtifact.Identity()} {
		if !slices.Contains(initial.Provenance(), id) {
			return nil, ErrInvestigationPipeline
		}
	}
	for _, src := range a.Packet.Sources() {
		if !src.HasSliceBinding() || !scope.AllowsPath(src.EvidenceItem().SourceRange().Path()) {
			return nil, ErrInvestigationPipeline
		}
		if src.Stage() == review.ContextStageChangedHunk {
			found := false
			for _, item := range analyzed.Items() {
				if src.ReferenceID() == item.EvidenceID() && src.SliceBindingIdentity() == item.BindingIdentity() {
					found = true
					break
				}
			}
			if !found {
				return nil, ErrInvestigationPipeline
			}
		}
	}
	return handle, nil
}
func (p *InvestigationPipeline) intentPayload(a InvestigationAssembly) ([]byte, error) {
	task := func(key string) string { v, _ := p.plan.Task(key); return v.Identity() }
	headTask, _ := p.plan.Task("source-head")
	contextID, _ := p.HandlerIdentity(controlplane.TaskAssembleContext)
	values := map[string]any{"contract": "open-trestle/investigation-context-intent", "schema_version": 1, "profile_identity": p.options.Profile.Identity(), "scope_identity": p.plan.Scope().Identity(), "plan_identity": p.plan.Identity(), "context_task_identity": task("context"), "context_handler_identity": contextID, "initial_context_artifact_identity": a.InitialContextArtifact.Identity(), "initial_context_identity": a.Packet.Identity(), "initial_snapshot_identity": a.Snapshot.Identity(), "memory_scope_identity": a.MemoryScope.Identity(), "memory_identity": a.Packet.MemoryIdentity(), "analysis_task_identity": task("analysis"), "analysis_artifact_identity": a.AnalysisArtifact.Identity(), "memory_task_identity": task("memory"), "memory_artifact_identity": a.MemoryArtifact.Identity(), "change_task_identity": task("change"), "change_artifact_identity": a.ChangeArtifact.Identity(), "source_head_task_identity": headTask.Identity(), "source_head_input_artifact_identity": headTask.InputIdentity(), "head_snapshot_artifact_identity": a.HeadSnapshotArtifact.Identity(), "head_snapshot_identity": p.headHandle.snapshot.Identity(), "head_manifest_identity": p.headHandle.snapshot.ManifestIdentity(), "deadline_milliseconds": p.deadline.UnixMilli()}
	values["identity"] = toolRecordIdentity(values)
	wire, err := json.Marshal(values)
	if err != nil || len(wire) > 64<<10 {
		return nil, ErrInvestigationPipeline
	}
	return wire, nil
}
func (p *InvestigationPipeline) PrepareContext(ctx context.Context, r controlplane.TaskExecutionRequest, a InvestigationAssembly) (artifact.Artifact, error) {
	work, end, err := p.begin(ctx, "context")
	if err != nil {
		return artifact.Artifact{}, err
	}
	defer end()
	result, err := p.prepareContext(work, r, a)
	if err != nil {
		p.fail()
	}
	return result, err
}
func (p *InvestigationPipeline) prepareContext(ctx context.Context, r controlplane.TaskExecutionRequest, a InvestigationAssembly) (artifact.Artifact, error) {
	s, err := p.task(ctx, r, "context")
	if err != nil || p.intent.Identity() != "" || p.initialStored.Identity() != "" {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	handle, err := p.validateAssembly(ctx, s, a)
	if err != nil {
		return artifact.Artifact{}, err
	}
	encoded, err := artifact.Encode(a.InitialContextArtifact)
	if err != nil || len(encoded) > 22<<20 {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	if _, err = p.capture.Put(ctx, a.InitialContextArtifact, p.options.Clock.Now()); err != nil {
		return artifact.Artifact{}, err
	}
	p.initialStored = a.InitialContextArtifact
	if ctx.Err() != nil || p.root.Err() != nil {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	p.headHandle = handle
	expiry := p.deadline
	for _, v := range []artifact.Artifact{a.InitialContextArtifact, a.AnalysisArtifact, a.MemoryArtifact, a.ChangeArtifact, a.BaseSnapshotArtifact, a.HeadSnapshotArtifact} {
		expiry = minInvestigationTime(expiry, v.ExpiresAt())
	}
	p.deadline = expiry
	raw, err := p.intentPayload(a)
	if err != nil {
		return artifact.Artifact{}, err
	}
	contextTask, _ := p.plan.Task("context")
	headTask, _ := p.plan.Task("source-head")
	provenance := []string{p.options.Profile.Identity(), p.plan.Identity(), contextTask.Identity(), a.InitialContextArtifact.Identity(), a.AnalysisArtifact.Identity(), a.MemoryArtifact.Identity(), a.ChangeArtifact.Identity(), a.HeadSnapshotArtifact.Identity(), headTask.Identity(), p.plan.PolicyIdentity()}
	sort.Strings(provenance)
	provenance = slices.Compact(provenance)
	intent, err := artifact.New(p.plan.Scope(), artifact.KindTaskInput, "application/json", a.HeadSnapshotArtifact.Classification(), artifact.OriginHost, artifact.ProtectionProcessPrivate, provenance, raw, p.options.Clock.Now(), expiry)
	if err != nil {
		return artifact.Artifact{}, err
	}
	encoded, err = artifact.Encode(intent)
	if err != nil || len(encoded) > 22<<20 {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	if _, err = p.capture.Put(ctx, intent, p.options.Clock.Now()); err != nil {
		return artifact.Artifact{}, err
	}
	if ctx.Err() != nil || p.root.Err() != nil {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	p.assembly = a
	p.intent = intent
	return intent, nil
}
func (p *InvestigationPipeline) checkIntent(ctx context.Context, s controlplane.ReviewRunState) error {
	id, err := pipelineOutput(s, "context")
	if err != nil || id != p.intent.Identity() || p.initialStored.Identity() != p.assembly.InitialContextArtifact.Identity() {
		return ErrInvestigationPipeline
	}
	value, err := p.get(ctx, id, artifact.KindTaskInput)
	if err != nil || !toolRecordSameArtifact(value, p.intent) {
		return ErrInvestigationPipeline
	}
	raw, err := p.intentPayload(p.assembly)
	if err != nil || !bytes.Equal(value.Payload(), raw) {
		return ErrInvestigationPipeline
	}
	initial, err := p.get(ctx, p.initialStored.Identity(), artifact.KindContextPacket)
	if err != nil || !toolRecordSameArtifact(initial, p.initialStored) {
		return ErrInvestigationPipeline
	}
	handle, err := p.validateAssembly(ctx, s, p.assembly)
	if err != nil || handle != p.headHandle {
		return ErrInvestigationPipeline
	}
	return nil
}
func (p *InvestigationPipeline) generate(ctx context.Context, r controlplane.TaskExecutionRequest) (artifact.Artifact, error) {
	s, err := p.task(ctx, r, "candidates")
	if err != nil || p.generationAttempted {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	p.generationAttempted = true
	if err = p.checkIntent(ctx, s); err != nil {
		return artifact.Artifact{}, err
	}
	contextTask, _ := p.plan.Task("context")
	headTask, _ := p.plan.Task("source-head")
	host := toolRecordIdentity([]any{"open-trestle/investigation-run-host", 1, p.options.Profile.Identity(), p.plan.Identity(), p.plan.RequestIdentity(), headTask.Identity(), p.assembly.HeadSnapshotArtifact.Identity(), contextTask.Identity(), p.intent.Identity()})
	op := ctx.Value(pipelineOperationKey{})
	constructorCtx := context.WithValue(p.root, pipelineOperationKey{}, op)
	stop := context.AfterFunc(ctx, p.fail)
	defer stop()
	c, err := NewInvestigation(constructorCtx, InvestigationOptions{Scope: p.plan.Scope(), MemoryScope: p.assembly.MemoryScope, SessionIdentity: host, Policy: p.options.Profile.Policy(), Routing: p.options.Profile.Routing(), Catalog: p.options.Catalog, Ledger: p.options.Ledger, Clock: p.options.Clock, Deadline: p.deadline, Store: p.capture, Acquisition: p.headHandle, HeadSnapshotArtifactIdentity: p.assembly.HeadSnapshotArtifact.Identity(), InitialContext: p.assembly.Packet, InitialSnapshot: p.assembly.Snapshot})
	if err != nil {
		return artifact.Artifact{}, err
	}
	p.mu.Lock()
	p.controller = c
	p.mu.Unlock()
	generation, err := c.Generate(ctx)
	if err != nil {
		return artifact.Artifact{}, err
	}
	if !stop() || ctx.Err() != nil || p.root.Err() != nil {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	p.generation = generation
	return generation.ResultArtifact(), nil
}
func (p *InvestigationPipeline) verify(ctx context.Context, r controlplane.TaskExecutionRequest) (artifact.Artifact, error) {
	s, err := p.task(ctx, r, "verification")
	if err != nil || p.verificationAttempted || p.controller == nil {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	p.verificationAttempted = true
	if err = p.checkIntent(ctx, s); err != nil {
		return artifact.Artifact{}, err
	}
	id, err := pipelineOutput(s, "candidates")
	if err != nil || id != p.generation.ResultArtifact().Identity() {
		return artifact.Artifact{}, ErrInvestigationPipeline
	}
	if err = p.checkGeneration(ctx); err != nil {
		return artifact.Artifact{}, err
	}
	verification, err := p.controller.Verify(ctx)
	if err != nil {
		return artifact.Artifact{}, err
	}
	p.verification = verification
	return verification.ResultArtifact(), nil
}
func (p *InvestigationPipeline) checkGeneration(ctx context.Context) error {
	g := p.generation
	if g.Custody() == nil {
		return ErrInvestigationPipeline
	}
	for _, v := range []artifact.Artifact{g.InputArtifact(), g.ResultArtifact(), g.TurnArtifact(), g.ContextArtifact()} {
		actual, err := p.get(ctx, v.Identity(), v.Kind())
		if err != nil || !toolRecordSameArtifact(actual, v) {
			return ErrInvestigationPipeline
		}
	}
	if _, err := ParseAdmittedInvestigationGenerationInputArtifact(g.InputArtifact(), g.Custody(), p.options.Clock.Now()); err != nil {
		return ErrInvestigationPipeline
	}
	if _, err := ParseAdmittedInvestigationGenerationResultArtifact(g.ResultArtifact(), g.InputArtifact(), g.TurnArtifact(), g.Custody(), p.options.Clock.Now()); err != nil {
		return ErrInvestigationPipeline
	}
	return nil
}

type InvestigationPipelineTurn struct {
	record   gateway.InvestigationTurnRecord
	artifact artifact.Artifact
	tools    []string
}

func (t InvestigationPipelineTurn) Record() gateway.InvestigationTurnRecord { return t.record }
func (t InvestigationPipelineTurn) Artifact() artifact.Artifact             { return t.artifact }
func (t InvestigationPipelineTurn) ToolResultArtifactIdentities() []string {
	return append([]string{}, t.tools...)
}

type InvestigationPipelineReadback struct {
	plan, scope, output, analysis, change, head, headTask string
	status                                                controlplane.ReviewRunStatus
	intent, initial, verificationArtifact                 artifact.Artifact
	generation                                            InvestigationGeneration
	verification                                          VerificationResult
	generated, verified, usageKnown                       bool
	turns                                                 []InvestigationPipelineTurn
	toolCalls                                             uint8
	scanned, returned, knownCost                          uint64
}

func (v InvestigationPipelineReadback) PlanIdentity() string                      { return v.plan }
func (v InvestigationPipelineReadback) ScopeIdentity() string                     { return v.scope }
func (v InvestigationPipelineReadback) RunStatus() controlplane.ReviewRunStatus   { return v.status }
func (v InvestigationPipelineReadback) OutputIdentity() string                    { return v.output }
func (v InvestigationPipelineReadback) ContextIntentArtifact() artifact.Artifact  { return v.intent }
func (v InvestigationPipelineReadback) InitialContextArtifact() artifact.Artifact { return v.initial }
func (v InvestigationPipelineReadback) AnalysisArtifactIdentity() string          { return v.analysis }
func (v InvestigationPipelineReadback) ChangeArtifactIdentity() string            { return v.change }
func (v InvestigationPipelineReadback) HeadSnapshotArtifactIdentity() string      { return v.head }
func (v InvestigationPipelineReadback) SourceHeadTaskIdentity() string            { return v.headTask }
func (v InvestigationPipelineReadback) Generation() (InvestigationGeneration, bool) {
	return v.generation, v.generated
}
func (v InvestigationPipelineReadback) Verification() (VerificationResult, bool) {
	return v.verification, v.verified
}
func (v InvestigationPipelineReadback) VerificationArtifact() artifact.Artifact {
	return v.verificationArtifact
}
func (v InvestigationPipelineReadback) Turns() []InvestigationPipelineTurn {
	out := append([]InvestigationPipelineTurn{}, v.turns...)
	for i := range out {
		out[i].tools = append([]string{}, out[i].tools...)
	}
	return out
}
func (v InvestigationPipelineReadback) ToolCalls() uint8          { return v.toolCalls }
func (v InvestigationPipelineReadback) ScannedBytes() uint64      { return v.scanned }
func (v InvestigationPipelineReadback) ReturnedBytes() uint64     { return v.returned }
func (v InvestigationPipelineReadback) UsageKnown() bool          { return v.usageKnown }
func (v InvestigationPipelineReadback) KnownCostMicroUSD() uint64 { return v.knownCost }
func (p *InvestigationPipeline) auditEvents(ctx context.Context) ([]audit.Event, error) {
	before, found, err := p.options.Ledger.Head(ctx, p.plan.Scope())
	if err != nil || found && before.Sequence() > 1000 {
		return nil, ErrInvestigationPipeline
	}
	events, err := p.options.Ledger.Read(ctx, p.plan.Scope(), 0, 1000)
	if err != nil {
		return nil, ErrInvestigationPipeline
	}
	after, exists, err := p.options.Ledger.Head(ctx, p.plan.Scope())
	if err != nil || exists != found || found && (after.Identity() != before.Identity() || uint64(len(events)) != before.Sequence()) || !found && len(events) != 0 {
		return nil, ErrInvestigationPipeline
	}
	previous := ""
	for i, event := range events {
		if event.Validate() != nil || event.Scope() != p.plan.Scope() || event.Sequence() != uint64(i+1) || event.PreviousIdentity() != previous {
			return nil, ErrInvestigationPipeline
		}
		previous = event.Identity()
	}
	return events, nil
}
func pipelineEvent(events []audit.Event, kind audit.EventKind, subject string) (audit.Event, bool) {
	var out audit.Event
	count := 0
	for _, e := range events {
		if e.Kind() == kind && e.SubjectIdentity() == subject {
			out = e
			count++
		}
	}
	return out, count == 1
}
func (p *InvestigationPipeline) history(ctx context.Context, events []audit.Event) ([]InvestigationPipelineTurn, bool, error) {
	p.mu.Lock()
	entries := make([]pipelineCaptureEntry, 0, len(p.captures))
	uncertain := p.captureUncertain
	for _, entry := range p.captures {
		entries = append(entries, *entry)
	}
	p.mu.Unlock()
	turns := []InvestigationPipelineTurn{}
	ordinals := map[string]uint8{}
	seenOrdinals := map[uint8]bool{}
	c := p.controller
	for _, entry := range entries {
		if !entry.known {
			uncertain = true
			continue
		}
		if entry.value.Kind() != artifact.KindInvestigationTurn {
			continue
		}
		actual, err := p.get(ctx, entry.value.Identity(), artifact.KindInvestigationTurn)
		if err != nil || !toolRecordSameArtifact(actual, entry.value) {
			return nil, false, ErrInvestigationPipeline
		}
		payload := actual.Payload()
		record, err := gateway.ParseInvestigationTurnRecord(payload)
		if err != nil || c == nil {
			return nil, false, ErrInvestigationPipeline
		}
		canonical, err := gateway.EncodeInvestigationTurnRecord(record)
		if err != nil || !bytes.Equal(canonical, payload) {
			return nil, false, ErrInvestigationPipeline
		}
		var header toolRecordTurnHeader
		if json.Unmarshal(payload, &header) != nil || header.Owner != c.ownerIdentity || header.Session != c.binding.Identity() || header.Policy != p.options.Profile.Policy().Identity() || header.Scope != p.plan.Scope().Identity() || header.Role != entry.role || header.Ordinal == 0 || uint64(header.Ordinal) > p.options.Profile.Policy().MaxModelTurns() || seenOrdinals[header.Ordinal] {
			return nil, false, ErrInvestigationPipeline
		}
		seenOrdinals[header.Ordinal] = true
		ordinals[record.Identity()] = header.Ordinal
		selected, sok := pipelineEvent(events, audit.EventRouteSelected, record.Selection().Identity())
		claimed, cok := pipelineEvent(events, audit.EventRouteAttemptClaimed, record.Authorization().Identity())
		outcome, ook := pipelineEvent(events, audit.EventRouteDispatchCompleted, record.Outcome().Identity())
		cost, kok := pipelineEvent(events, audit.EventRouteCostReconciled, record.Reconciliation().Identity())
		if !sok || !cok || !ook || !kok || selected.Sequence() >= claimed.Sequence() || claimed.Sequence() >= outcome.Sequence() || outcome.Sequence() >= cost.Sequence() {
			return nil, false, ErrInvestigationPipeline
		}
		item := InvestigationPipelineTurn{record: record, artifact: actual, tools: []string{}}
		for _, tool := range c.tools {
			if tool.operation.turn.Identity() != record.Identity() {
				continue
			}
			captured := false
			for _, candidate := range entries {
				if candidate.known && toolRecordSameArtifact(candidate.value, tool.artifact) {
					captured = true
					break
				}
			}
			if !captured || tool.invocation.Validate() != nil || tool.result.Validate() != nil {
				return nil, false, ErrInvestigationPipeline
			}
			completed, ok := pipelineEvent(events, audit.EventInvestigationToolCompleted, tool.artifact.Identity())
			claim, claimed := pipelineEvent(events, audit.EventInvestigationToolClaimed, tool.operation.Identity())
			parents := []string{tool.operation.Identity(), record.Identity(), c.head.Identity()}
			sort.Strings(parents)
			if !ok || !claimed || claim.Sequence() <= cost.Sequence() || completed.Sequence() <= claim.Sequence() || !slices.Equal(completed.CausalParentIdentities(), parents) {
				return nil, false, ErrInvestigationPipeline
			}
			value, err := p.get(ctx, tool.artifact.Identity(), artifact.KindInvestigationToolResult)
			if err != nil || !toolRecordSameArtifact(value, tool.artifact) {
				return nil, false, ErrInvestigationPipeline
			}
			item.tools = append(item.tools, tool.artifact.Identity())
		}
		if len(item.tools) > 1 {
			return nil, false, ErrInvestigationPipeline
		}
		turns = append(turns, item)
	}
	sort.Slice(turns, func(i, j int) bool {
		return ordinals[turns[i].record.Identity()] < ordinals[turns[j].record.Identity()]
	})
	previous := ""
	var sum uint64
	known := !uncertain
	for i, t := range turns {
		if ordinals[t.record.Identity()] != uint8(i+1) || t.record.PreviousTurnIdentity() != previous {
			return nil, false, ErrInvestigationPipeline
		}
		previous = t.record.Identity()
		cost := t.record.Reconciliation().ActualCost()
		if !cost.IsKnown() || cost.TotalCostMicroUSD() > ^uint64(0)-sum {
			known = false
		} else {
			sum += cost.TotalCostMicroUSD()
		}
	}
	claims := 0
	for _, e := range events {
		if e.Kind() == audit.EventRouteAttemptClaimed {
			claims++
		}
	}
	if c == nil {
		known = known && claims == 0 && len(turns) == 0
	} else {
		account := c.owner.State()
		known = known && account.UsageKnown() && !account.InFlight() && len(turns) == int(account.TurnsStarted()) && claims == len(turns) && sum == account.KnownCostMicroUSD()
	}
	return turns, known, nil
}
func (p *InvestigationPipeline) view(ctx context.Context, s controlplane.ReviewRunState, success bool) (InvestigationPipelineReadback, error) {
	headTask, _ := p.plan.Task("source-head")
	v := InvestigationPipelineReadback{plan: p.plan.Identity(), scope: p.plan.Scope().Identity(), status: s.Status(), output: s.OutputIdentity(), intent: p.intent, initial: p.initialStored, analysis: p.assembly.AnalysisArtifact.Identity(), change: p.assembly.ChangeArtifact.Identity(), head: p.assembly.HeadSnapshotArtifact.Identity(), headTask: headTask.Identity()}
	events, err := p.auditEvents(ctx)
	if err != nil {
		return InvestigationPipelineReadback{}, err
	}
	v.turns, v.usageKnown, err = p.history(ctx, events)
	if err != nil {
		return InvestigationPipelineReadback{}, err
	}
	if p.controller != nil {
		v.scanned = p.controller.scanned
		v.returned = p.controller.returned
		v.toolCalls = uint8(len(p.controller.tools))
		v.knownCost = p.controller.owner.State().KnownCostMicroUSD()
	}
	if !success {
		v.usageKnown = false
		return v, nil
	}
	if p.failed || p.root.Err() != nil || p.checkIntent(ctx, s) != nil || p.checkGeneration(ctx) != nil {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	generationID, err := pipelineOutput(s, "candidates")
	if err != nil || generationID != p.generation.ResultArtifact().Identity() {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	verificationID, err := pipelineOutput(s, "verification")
	if err != nil || verificationID != p.verification.ResultArtifact().Identity() {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	actual, err := p.get(ctx, verificationID, artifact.KindVerifiedFindingSet)
	if err != nil || !toolRecordSameArtifact(actual, p.verification.ResultArtifact()) {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	result := p.verification.result
	if result.Validate() != nil || result.GenerationArtifactIdentity() != generationID || result.VerificationContext().GenerationContextIdentity() != p.generation.ContextIdentity() || !v.usageKnown {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	wire, err := encodeVerificationResult(result)
	if err != nil || !bytes.Equal(wire, actual.Payload()) {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	v.generation = p.generation
	v.verification = result
	v.verificationArtifact = actual
	v.generated = true
	v.verified = true
	return v, nil
}
func (p *InvestigationPipeline) ForReadiness(ctx context.Context, r controlplane.TaskExecutionRequest) (InvestigationPipelineReadback, error) {
	work, end, err := p.begin(ctx, "readiness")
	if err != nil {
		return InvestigationPipelineReadback{}, err
	}
	defer end()
	s, err := p.task(work, r, "readiness")
	if err != nil {
		return InvestigationPipelineReadback{}, err
	}
	return p.view(work, s, true)
}
func (p *InvestigationPipeline) ReadResult(ctx context.Context) (InvestigationPipelineReadback, error) {
	work, end, err := p.begin(ctx, "readback")
	if err != nil {
		return InvestigationPipelineReadback{}, err
	}
	defer end()
	s, err := p.state(work)
	if err != nil || s.Status() == controlplane.ReviewRunActive {
		return InvestigationPipelineReadback{}, ErrInvestigationPipeline
	}
	return p.view(work, s, s.Status() == controlplane.ReviewRunSucceeded)
}
func (p InvestigationPipelineProfile) String() string { return "investigation pipeline profile" }
func (p InvestigationPipelineProfile) GoString() string {
	return "model.InvestigationPipelineProfile{<redacted>}"
}
func (p *InvestigationPipeline) String() string        { return "live investigation pipeline" }
func (p *InvestigationPipeline) GoString() string      { return "model.InvestigationPipeline{<redacted>}" }
func (v InvestigationPipelineReadback) String() string { return "investigation pipeline readback" }
func (v InvestigationPipelineReadback) GoString() string {
	return "model.InvestigationPipelineReadback{<redacted>}"
}
func (v InvestigationPipelineTurn) String() string { return "investigation pipeline turn" }
func (v InvestigationPipelineTurn) GoString() string {
	return "model.InvestigationPipelineTurn{<redacted>}"
}
func (h *InvestigationSourceTaskHandler) String() string     { return "investigation source task" }
func (h *InvestigationGenerationTaskHandler) String() string { return "investigation generation task" }
func (h *InvestigationVerificationTaskHandler) String() string {
	return "investigation verification task"
}
func (p *InvestigationPipeline) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("live investigation pipeline"))
}

var _ artifact.Store = (*pipelineCaptureStore)(nil)
var _ controlplane.TaskHandler = (*InvestigationSourceTaskHandler)(nil)
var _ controlplane.TaskHandler = (*InvestigationGenerationTaskHandler)(nil)
var _ controlplane.TaskHandler = (*InvestigationVerificationTaskHandler)(nil)
