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

// InvestigationBudgetEstimateVersion identifies the per-turn input estimate
// that new turns use and record. Version 2 reserves the declared input
// estimate or, when larger, the request payload bytes plus the trusted system
// channel bytes plus a 256-byte framing reserve, which equals
// review.ModelRequestBudget for every investigation request. A turn whose
// routes use the local structured-output transport also counts, and records,
// the serialized response_format bytes, which equals
// review.ModelRequestBudgetForTransport for that transport. Version 1 counted
// the payload and the reserve only; it is recorded readback only.
const InvestigationBudgetEstimateVersion = 2

const (
	investigationBudgetEstimateVersionV1 = 1
	investigationEstimateFramingReserve  = 256
)

var ErrInvestigationRouteOwner = errors.New("investigation route owner refused operation")

// InvestigationTurnCostBudget returns the estimate version 2 reservation for one
// investigation turn. systemChannelBytes must be the trusted system channel the
// adapter sends with request (review.ModelRequestSystemChannelBytes), and
// responseFormatBytes the serialized response_format a local structured-output
// route sends with it (review.ModelRequestResponseFormatBytes), or 0 for the
// standard transport. The owner plans and records each turn with this
// function, so a caller that pre-plans a turn obtains the same budget and
// authorization.
func InvestigationTurnCostBudget(declared provider.ModelCostBudget, request provider.Request, systemChannelBytes, responseFormatBytes uint32, remainingCostMicroUSD uint64) (provider.ModelCostBudget, error) {
	if declared.Validate() != nil || request.Validate() != nil {
		return provider.ModelCostBudget{}, ErrInvestigationRouteOwner
	}
	return investigationTurnEstimate(InvestigationBudgetEstimateVersion, declared.EstimatedInputTokens(), declared.MaxOutputTokens(), request, systemChannelBytes, responseFormatBytes, remainingCostMicroUSD)
}

// investigationTurnEstimate applies the recorded estimate version exactly. A
// version 1 turn never counts system channel or response_format bytes, so its
// recorded budget is never re-derived with the version 2 formula.
func investigationTurnEstimate(version uint8, declaredInput, maxOutput uint32, request provider.Request, systemChannelBytes, responseFormatBytes uint32, remainingCostMicroUSD uint64) (provider.ModelCostBudget, error) {
	estimated := uint64(len(request.Payload())) + investigationEstimateFramingReserve
	switch version {
	case investigationBudgetEstimateVersionV1:
		if systemChannelBytes != 0 || responseFormatBytes != 0 {
			return provider.ModelCostBudget{}, ErrInvestigationRouteOwner
		}
	case InvestigationBudgetEstimateVersion:
		estimated += uint64(systemChannelBytes) + uint64(responseFormatBytes)
	default:
		return provider.ModelCostBudget{}, ErrInvestigationRouteOwner
	}
	return provider.NewModelCostBudget(max(uint64(declaredInput), estimated), uint64(maxOutput), remainingCostMicroUSD)
}

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
	// SystemChannelBytes returns the trusted system channel bytes an adapter
	// sends with a turn request; it is required. Production passes
	// review.ModelRequestSystemChannelBytes, which this package cannot import.
	// Each turn records the value it reserved.
	SystemChannelBytes func(provider.Request) uint32
	// GenerationResponseFormatBytes and VerificationResponseFormatBytes are set
	// for a turn role whose routes use the local structured-output transport.
	// They return the serialized response_format bytes that transport sends
	// with a turn request; production passes
	// review.ModelRequestResponseFormatBytes. Nil selects the standard
	// transport. Each structured turn records the value it reserved.
	GenerationResponseFormatBytes, VerificationResponseFormatBytes func(provider.Request) uint32
	// PlanningRefusals, when set, receives each turn's eligibility refusal,
	// such as a *RouteContextShortfall. It observes only and is not bound into
	// the owner identity, since it never changes a decision.
	PlanningRefusals func(error)
}

// investigationTurnTransport is what one turn reserved beyond its payload.
type investigationTurnTransport struct {
	systemBytes, responseFormatBytes uint32
	structured                       bool
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
	if o.Scope.Validate() != nil || !validInvestigationIdentity(o.SessionIdentity) || !validInvestigationIdentity(o.PolicyIdentity) || o.MaxTurns == 0 || o.MaxTurns > 8 || o.Budget.Validate() != nil || o.Requirements.Validate() != nil || o.Constraints.Validate() != nil || o.Generation.Validate() != nil || o.Verification.Validate() != nil || o.Catalog.Validate() != nil || isNilInterfaceValue(o.Ledger) || isNilInterfaceValue(o.Clock) || o.SystemChannelBytes == nil || o.Budget.MaxOutputTokens() < o.Requirements.MinOutputTokens() {
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
	preimage := []any{"open-trestle/investigation-route-owner", 1, o.Scope.Identity(), o.SessionIdentity, o.PolicyIdentity, o.Deadline.UnixMilli(), o.MaxTurns, InvestigationBudgetEstimateVersion, o.Budget.EstimatedInputTokens(), o.Budget.MaxOutputTokens(), o.Budget.MaxCostMicroUSD(), o.Requirements.MinContextTokens(), o.Requirements.MinOutputTokens(), features, string(o.Constraints.Classification()), zones, o.Constraints.ContentLoggingAllowed(), o.Generation.Identity(), o.Verification.Identity(), o.Catalog.Identity()}
	// An owner that reserves structured-output framing for either role plans
	// different budgets, so it binds which roles do under version 2. Version 1
	// identities are unchanged.
	if structured := []bool{o.GenerationResponseFormatBytes != nil, o.VerificationResponseFormatBytes != nil}; structured[0] || structured[1] {
		preimage[1] = 2
		preimage = append(preimage, structured)
	}
	identity := investigationIdentity(preimage)
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

func (o *InvestigationRouteOwner) planning(request provider.Request, role InvestigationTurnRole) (RouteSelectionReceipt, RouteRankingResult, RouteAttemptAuthorization, investigationTurnTransport, error) {
	transport := investigationTurnTransport{systemBytes: o.options.SystemChannelBytes(request)}
	responseFormat := o.options.GenerationResponseFormatBytes
	if role == InvestigationVerificationTurn {
		responseFormat = o.options.VerificationResponseFormatBytes
	}
	if responseFormat != nil {
		transport.responseFormatBytes, transport.structured = responseFormat(request), true
	}
	budget, err := InvestigationTurnCostBudget(o.options.Budget, request, transport.systemBytes, transport.responseFormatBytes, o.state.remaining)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, investigationTurnTransport{}, err
	}
	input, err := NewReviewRoutingInput(o.options.Scope, request, o.options.Requirements, o.options.Constraints)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, investigationTurnTransport{}, err
	}
	plan := o.options.Generation
	if role == InvestigationVerificationTurn {
		plan = o.options.Verification
	}
	eligible, err := FilterEligibleRoutes(input, budget, plan.registryRevision, plan.routes)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, investigationTurnTransport{}, err
	}
	if refusal := RouteEligibilityRefusal(eligible, plan.routes); refusal != nil {
		if o.options.PlanningRefusals != nil {
			o.options.PlanningRefusals(refusal)
		}
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, investigationTurnTransport{}, refusal
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
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, investigationTurnTransport{}, err
	}
	selection, err := NewRouteSelectionReceipt(eligible, ranking)
	if err != nil {
		return RouteSelectionReceipt{}, RouteRankingResult{}, RouteAttemptAuthorization{}, investigationTurnTransport{}, err
	}
	authority, err := NewInitialRouteAttemptAuthorization(request, selection, ranking)
	return selection, ranking, authority, transport, err
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
	selection, ranking, authority, transport, err := o.planning(request, role)
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
	record, err := newInvestigationTurnRecord(o, ordinal, role, previous, request, transport, selection, ranking, authority, dispatch, outcome, reconciliation, started, finished)
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
