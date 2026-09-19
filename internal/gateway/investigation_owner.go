package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const InvestigationBudgetEstimateVersion = 1

var ErrInvestigationRouteOwner = errors.New("investigation route owner refused operation")

type InvestigationTurnRole uint8

const (
	InvestigationGenerationTurn InvestigationTurnRole = iota + 1
	InvestigationVerificationTurn
)

func (r InvestigationTurnRole) String() string {
	switch r {
	case InvestigationGenerationTurn:
		return "generation"
	case InvestigationVerificationTurn:
		return "verification"
	}
	return ""
}

type InvestigationRoutePlan struct {
	identity                              string
	registryRevision, performanceRevision uint64
	routes                                []ObservedRouteCandidate
	ranking                               RouteRankingPolicy
	observations                          []provider.RoutePerformanceObservation
}

func NewInvestigationRoutePlan(registryRevision uint64, routes []ObservedRouteCandidate, ranking RouteRankingPolicy, performanceRevision uint64, observations []provider.RoutePerformanceObservation) (InvestigationRoutePlan, error) {
	if registryRevision == 0 || performanceRevision == 0 || len(routes) == 0 || len(routes) > maxRouteFilterCandidates || len(observations) != len(routes) || ranking.Validate() != nil {
		return InvestigationRoutePlan{}, ErrInvestigationRouteOwner
	}
	copied := append([]ObservedRouteCandidate(nil), routes...)
	sort.Slice(copied, func(i, j int) bool { return observedRouteIdentity(copied[i]) < observedRouteIdentity(copied[j]) })
	seen := make(map[provider.RouteReference]bool, len(copied))
	for i, route := range copied {
		if route.Validate() != nil || route.ResolvedRecord().RouteRegistryRecord().RegistryRevision() != registryRevision || i > 0 && observedRouteIdentity(copied[i-1]) == observedRouteIdentity(route) || seen[observedRouteReference(route)] {
			return InvestigationRoutePlan{}, ErrInvestigationRouteOwner
		}
		seen[observedRouteReference(route)] = true
	}
	measured := append([]provider.RoutePerformanceObservation(nil), observations...)
	sort.Slice(measured, func(i, j int) bool { return measured[i].RecordIdentity() < measured[j].RecordIdentity() })
	for i, observation := range measured {
		if observation.Validate() != nil || observation.ObservationRevision() != performanceRevision || observation.RecordIdentity() != observedRouteIdentity(copied[i]) {
			return InvestigationRoutePlan{}, ErrInvestigationRouteOwner
		}
	}
	var canonicalRanking RouteRankingPolicy
	var err error
	if pinned, ok := ranking.PinnedRoute(); ok {
		canonicalRanking, err = NewPinnedRouteRankingPolicy(pinned, ranking.PreferredRoutes())
	} else {
		canonicalRanking, err = NewRouteRankingPolicy(ranking.PreferredRoutes())
	}
	if err != nil {
		return InvestigationRoutePlan{}, ErrInvestigationRouteOwner
	}
	plan := InvestigationRoutePlan{registryRevision: registryRevision, performanceRevision: performanceRevision, routes: copied, ranking: canonicalRanking, observations: measured}
	entries := make([]any, len(copied))
	for i, route := range copied {
		state, observation := route.OperationalState(), measured[i]
		entries[i] = []any{observedRouteIdentity(route), route.ResolvedRecord().EvidenceManifestSizeBytes(), state.ObservationRevision(), state.Health().String(), state.Quota().String(), observation.LatencyKnown(), observation.P95LatencyMilliseconds(), observation.SampleCount()}
	}
	plan.identity = investigationIdentity([]any{"open-trestle/investigation-route-plan", 1, registryRevision, performanceRevision, canonicalRanking.Identity(), entries})
	return plan, nil
}
func (p InvestigationRoutePlan) Identity() string { return p.identity }
func (p InvestigationRoutePlan) Validate() error {
	canonical, err := NewInvestigationRoutePlan(p.registryRevision, p.routes, p.ranking, p.performanceRevision, p.observations)
	if err != nil || p.identity == "" || p.identity != canonical.identity {
		return ErrInvestigationRouteOwner
	}
	return nil
}

type InvestigationRouteOwnerOptions struct {
	Scope                           audit.ReviewScope
	SessionIdentity, PolicyIdentity string
	Deadline                        time.Time
	MaxTurns                        uint8
	Budget                          provider.ModelCostBudget
	Requirements                    provider.ModelRequirements
	Constraints                     policy.ProviderDataConstraints
	Generation, Verification        InvestigationRoutePlan
	Catalog                         RouteDispatcherCatalog
	Ledger                          audit.Ledger
	Clock                           artifact.Clock
}

type InvestigationAccountState struct {
	remaining, knownCost         uint64
	turns                        uint8
	frozen, inFlight, usageKnown bool
}

func (s InvestigationAccountState) RemainingCostMicroUSD() uint64 { return s.remaining }
func (s InvestigationAccountState) KnownCostMicroUSD() uint64     { return s.knownCost }
func (s InvestigationAccountState) TurnsStarted() uint8           { return s.turns }
func (s InvestigationAccountState) Frozen() bool                  { return s.frozen }
func (s InvestigationAccountState) InFlight() bool                { return s.inFlight }
func (s InvestigationAccountState) UsageKnown() bool              { return s.usageKnown }

// InvestigationRouteOwner owns one live monetary account. It has no restore API.
type InvestigationRouteOwner struct {
	mu                             sync.Mutex
	options                        InvestigationRouteOwnerOptions
	identity                       string
	wallDeadline, lastProtocolTime time.Time
	state                          InvestigationAccountState
	seen                           map[string]bool
	previous                       string
}

func NewInvestigationRouteOwner(o InvestigationRouteOwnerOptions) (*InvestigationRouteOwner, error) {
	if o.Scope.Validate() != nil || !validInvestigationIdentity(o.SessionIdentity) || !validInvestigationIdentity(o.PolicyIdentity) || o.MaxTurns == 0 || o.MaxTurns > 8 || o.Budget.Validate() != nil || o.Requirements.Validate() != nil || o.Constraints.Validate() != nil || o.Generation.Validate() != nil || o.Verification.Validate() != nil || o.Catalog.Validate() != nil || isNilInterfaceValue(o.Ledger) || isNilInterfaceValue(o.Clock) || o.Budget.MaxOutputTokens() < o.Requirements.MinOutputTokens() {
		return nil, ErrInvestigationRouteOwner
	}
	at := investigationProtocolTime(o.Clock.Now())
	deadline := investigationProtocolTime(o.Deadline)
	if at.UnixMilli() <= 0 || at.UnixMilli() > 253402300799999 || deadline.UnixMilli() > 253402300799999 || !deadline.After(at) || deadline.Sub(at) > 15*time.Minute {
		return nil, ErrInvestigationRouteOwner
	}
	for _, plan := range []InvestigationRoutePlan{o.Generation, o.Verification} {
		for _, route := range plan.routes {
			if _, exists := o.Catalog.Resolve(observedRouteReference(route).AdapterID()); !exists {
				return nil, ErrInvestigationRouteOwner
			}
		}
	}
	o.Deadline = deadline
	var err error
	o.Generation, err = NewInvestigationRoutePlan(o.Generation.registryRevision, o.Generation.routes, o.Generation.ranking, o.Generation.performanceRevision, o.Generation.observations)
	if err != nil {
		return nil, ErrInvestigationRouteOwner
	}
	o.Verification, err = NewInvestigationRoutePlan(o.Verification.registryRevision, o.Verification.routes, o.Verification.ranking, o.Verification.performanceRevision, o.Verification.observations)
	if err != nil {
		return nil, ErrInvestigationRouteOwner
	}
	o.Requirements, err = provider.NewModelRequirements(uint64(o.Requirements.MinContextTokens()), uint64(o.Requirements.MinOutputTokens()), o.Requirements.RequiredFeatures())
	if err != nil {
		return nil, ErrInvestigationRouteOwner
	}
	dispatchers := make([]RouteDispatcher, 0, o.Catalog.Len())
	for _, id := range o.Catalog.AdapterIDs() {
		dispatcher, _ := o.Catalog.Resolve(id)
		dispatchers = append(dispatchers, dispatcher)
	}
	o.Catalog, err = NewRouteDispatcherCatalog(dispatchers)
	if err != nil || o.Catalog.Validate() != nil {
		return nil, ErrInvestigationRouteOwner
	}
	zones := []string{}
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if o.Constraints.AllowedProviderZones().Allows(zone) {
			zones = append(zones, zone.String())
		}
	}
	features := []string{}
	for _, feature := range o.Requirements.RequiredFeatures() {
		features = append(features, feature.String())
	}
	identity := investigationIdentity([]any{"open-trestle/investigation-route-owner", 1, o.Scope.Identity(), o.SessionIdentity, o.PolicyIdentity, o.Deadline.UnixMilli(), o.MaxTurns, InvestigationBudgetEstimateVersion, o.Budget.EstimatedInputTokens(), o.Budget.MaxOutputTokens(), o.Budget.MaxCostMicroUSD(), o.Requirements.MinContextTokens(), o.Requirements.MinOutputTokens(), features, string(o.Constraints.Classification()), zones, o.Constraints.ContentLoggingAllowed(), o.Generation.Identity(), o.Verification.Identity(), o.Catalog.Identity()})
	return &InvestigationRouteOwner{options: o, identity: identity, lastProtocolTime: at, wallDeadline: time.Now().Add(deadline.Sub(at)), state: InvestigationAccountState{remaining: o.Budget.MaxCostMicroUSD(), usageKnown: true}, seen: make(map[string]bool)}, nil
}

func (o *InvestigationRouteOwner) State() InvestigationAccountState {
	if o == nil {
		return InvestigationAccountState{frozen: true}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.identity == "" {
		return InvestigationAccountState{frozen: true}
	}
	return o.state
}

func (o *InvestigationRouteOwner) planning(request provider.Request, role InvestigationTurnRole) (RouteSelectionReceipt, RouteRankingResult, RouteAttemptAuthorization, error) {
	budget, err := provider.NewModelCostBudget(max(uint64(o.options.Budget.EstimatedInputTokens()), uint64(len(request.Payload()))+256), uint64(o.options.Budget.MaxOutputTokens()), o.state.remaining)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, err
	}
	input, err := NewReviewRoutingInput(o.options.Scope, request, o.options.Requirements, o.options.Constraints)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, err
	}
	plan := o.options.Generation
	if role == InvestigationVerificationTurn {
		plan = o.options.Verification
	}
	eligible, err := FilterEligibleRoutes(input, budget, plan.registryRevision, plan.routes)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, err
	}
	observations := make([]provider.RoutePerformanceObservation, 0, len(plan.observations))
	for _, route := range eligible.EligibleRoutes() {
		for _, observed := range plan.observations {
			if observed.RecordIdentity() == observedRouteIdentity(route) {
				observations = append(observations, observed)
				break
			}
		}
	}
	ranking, err := RankEligibleRoutes(eligible, plan.ranking, plan.performanceRevision, observations)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, err
	}
	selection, err := NewRouteSelectionReceipt(eligible, ranking)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, err
	}
	authority, err := NewInitialRouteAttemptAuthorization(request, selection, ranking)
	return selection, ranking, authority, err
}

func (o *InvestigationRouteOwner) current(ctx context.Context, earliest time.Time) bool {
	at := investigationProtocolTime(o.options.Clock.Now())
	return ctx.Err() == nil && !at.Before(earliest) && at.Before(o.options.Deadline) && time.Now().Before(o.wallDeadline)
}

// Dispatch makes at most one model effect and settles only its own actual result.
func (o *InvestigationRouteOwner) Dispatch(ctx context.Context, role InvestigationTurnRole, request provider.Request) (InvestigationTurnRecord, error) {
	if o == nil || isNilInterfaceValue(ctx) || ctx.Err() != nil || role.String() == "" || request.Validate() != nil {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	o.mu.Lock()
	if o.state.frozen || o.state.inFlight || o.state.turns >= o.options.MaxTurns || o.seen[request.Identity()] || !o.current(ctx, o.lastProtocolTime) {
		o.mu.Unlock()
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	selection, ranking, authority, err := o.planning(request, role)
	if err != nil || authority.ReservedCostMicroUSD() > o.state.remaining || !o.current(ctx, o.lastProtocolTime) {
		o.mu.Unlock()
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	started := investigationProtocolTime(o.options.Clock.Now())
	deadline := time.Now().Add(o.options.Deadline.Sub(started))
	if o.wallDeadline.Before(deadline) {
		deadline = o.wallDeadline
	}
	execution, cancel := context.WithDeadline(ctx, deadline)
	o.state.inFlight = true
	o.state.usageKnown = false
	o.state.turns++
	o.state.remaining -= authority.ReservedCostMicroUSD()
	o.seen[request.Identity()] = true
	ordinal, previous := o.state.turns, o.previous
	o.mu.Unlock()
	defer cancel()
	completed := false
	defer func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.state.inFlight = false
		if !completed {
			o.state.frozen = true
			o.state.usageKnown = false
		}
	}()
	if !o.current(execution, started) {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if _, err := RecordRouteSelection(execution, o.options.Ledger, o.options.Scope, selection, started); err != nil {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if !o.current(execution, started) {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if _, acquired, err := ClaimRouteAttempt(execution, o.options.Ledger, o.options.Scope, authority, investigationProtocolTime(o.options.Clock.Now())); err != nil || !acquired {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if !o.current(execution, started) {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	dispatch, err := DispatchAuthorizedRouteFromCatalog(execution, o.options.Catalog, authority, request)
	if err != nil || !o.current(execution, started) {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	finished := investigationProtocolTime(o.options.Clock.Now())
	duration := finished.Sub(started).Milliseconds()
	if duration < 0 || uint64(duration) > maxRouteAttemptDurationMilliseconds {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	outcome, err := NewRouteAttemptOutcomeFromDispatch(authority, dispatch, uint64(duration))
	if err != nil {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if _, err := RecordRouteDispatchCompleted(execution, o.options.Ledger, o.options.Scope, authority, dispatch, outcome, finished); err != nil {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authority, outcome)
	if err != nil || !o.current(execution, finished) {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if _, err := RecordRouteCostReconciliation(execution, o.options.Ledger, o.options.Scope, authority, outcome, reconciliation, finished); err != nil {
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	o.mu.Lock()
	actual := reconciliation.ActualCost()
	if !actual.IsKnown() || actual.TotalCostMicroUSD() > math.MaxUint64-o.state.knownCost {
		o.mu.Unlock()
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	o.state.knownCost += actual.TotalCostMicroUSD()
	o.state.remaining = reconciliation.RemainingCostMicroUSD()
	o.lastProtocolTime = finished
	completed = true
	o.state.usageKnown = true
	if reconciliation.Status() == RouteCostBudgetExceeded || dispatch.Status() != RouteDispatchSucceeded {
		o.state.frozen = true
		o.mu.Unlock()
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	if !o.current(execution, finished) {
		o.state.frozen = true
		o.mu.Unlock()
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	record, err := newInvestigationTurnRecord(o, ordinal, role, previous, request, selection, ranking, authority, dispatch, outcome, reconciliation, started, finished)
	if err != nil || !o.current(execution, finished) {
		o.state.frozen = true
		o.mu.Unlock()
		return InvestigationTurnRecord{}, ErrInvestigationRouteOwner
	}
	o.previous = record.Identity()
	o.mu.Unlock()
	return record, nil
}

func investigationProtocolTime(at time.Time) time.Time { return time.UnixMilli(at.UnixMilli()).UTC() }
func validInvestigationIdentity(id string) bool {
	return validRequestIdentity(id) && strings.Trim(id, "0") != ""
}
func investigationIdentity(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func (p InvestigationRoutePlan) String() string { return "investigation route plan" }
func (p InvestigationRoutePlan) GoString() string {
	return "gateway.InvestigationRoutePlan{<redacted>}"
}
func (p InvestigationRoutePlan) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation route plan"))
}
func (o *InvestigationRouteOwner) String() string { return "investigation route owner" }
func (o *InvestigationRouteOwner) GoString() string {
	return "gateway.InvestigationRouteOwner{<redacted>}"
}
func (o *InvestigationRouteOwner) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation route owner"))
}
