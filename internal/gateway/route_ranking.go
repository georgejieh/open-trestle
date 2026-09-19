package gateway

import (
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrNoEligibleRoute identifies a ranking request without a dispatchable candidate.
	ErrNoEligibleRoute = errors.New("no eligible route")
	// ErrPinnedRouteNotEligible identifies an exact pin absent from the eligible set.
	ErrPinnedRouteNotEligible = errors.New("pinned route is not eligible")
	// ErrRoutePerformanceSetMismatch identifies missing or extra performance observations.
	ErrRoutePerformanceSetMismatch = errors.New("route performance set mismatch")
	// ErrDuplicateRoutePerformanceObservation identifies repeated measurements for one record.
	ErrDuplicateRoutePerformanceObservation = errors.New("duplicate route performance observation")
	// ErrRoutePerformanceRevisionMismatch identifies an observation from another performance snapshot.
	ErrRoutePerformanceRevisionMismatch = errors.New("route performance revision mismatch")
	// ErrInvalidRouteRankingResult identifies inconsistent ranking scores, bindings, or order.
	ErrInvalidRouteRankingResult = errors.New("invalid route ranking result")
)

// RankedRoute binds an eligible route to every component used by deterministic ranking.
type RankedRoute struct {
	route          ObservedRouteCandidate
	performance    provider.RoutePerformanceObservation
	pinned         bool
	preferenceRank uint8
	maximumCost    provider.RouteCostEstimate
}

// Route returns the eligible route.
func (r RankedRoute) Route() ObservedRouteCandidate { return r.route }

// Performance returns the exact-record latency observation.
func (r RankedRoute) Performance() provider.RoutePerformanceObservation { return r.performance }

// IsPinned reports whether this route matched the explicit exact pin.
func (r RankedRoute) IsPinned() bool { return r.pinned }

// PreferenceRank returns the one-based policy preference position and whether one matched.
func (r RankedRoute) PreferenceRank() (uint8, bool) {
	return r.preferenceRank, r.preferenceRank != 0
}

// QualityTier returns the registry-bound evaluated quality tier.
func (r RankedRoute) QualityTier() provider.RouteQualityTier {
	return r.route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteQualityTier()
}

// MaximumCost returns the pessimistic fixed-price estimate used for ranking.
func (r RankedRoute) MaximumCost() provider.RouteCostEstimate { return r.maximumCost }

// String returns a redacted ranked-route description.
func (r RankedRoute) String() string { return "ranked route" }

// GoString returns a redacted Go-syntax ranked-route description.
func (r RankedRoute) GoString() string { return "gateway.RankedRoute{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RankedRoute) Format(state fmt.State, verb rune) {
	formatted := "ranked route"
	if verb == 'q' {
		formatted = `"ranked route"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RankedRoute{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// RouteRankingResult binds the ordered score list to all decision inputs.
type RouteRankingResult struct {
	requestIdentity       string
	reviewScopeIdentity   string
	routingInputIdentity  string
	registryRevision      uint64
	performanceRevision   uint64
	costBudget            provider.ModelCostBudget
	rankingPolicyIdentity string
	rankedRoutes          []RankedRoute
}

// RequestIdentity returns the request identity.
func (r RouteRankingResult) RequestIdentity() string { return r.requestIdentity }

// ReviewScopeIdentity returns the tenant-owned review scope identity.
func (r RouteRankingResult) ReviewScopeIdentity() string { return r.reviewScopeIdentity }

// RoutingInputIdentity returns the request, requirement, and policy input identity.
func (r RouteRankingResult) RoutingInputIdentity() string { return r.routingInputIdentity }

// RegistryRevision returns the registry snapshot revision.
func (r RouteRankingResult) RegistryRevision() uint64 { return r.registryRevision }

// PerformanceRevision returns the latency snapshot revision.
func (r RouteRankingResult) PerformanceRevision() uint64 { return r.performanceRevision }

// CostBudget returns the hard budget used for estimates.
func (r RouteRankingResult) CostBudget() provider.ModelCostBudget { return r.costBudget }

// RankingPolicyIdentity returns the content-derived pin and preference policy identity.
func (r RouteRankingResult) RankingPolicyIdentity() string { return r.rankingPolicyIdentity }

// RankedRoutes returns a defensive copy in final selection order.
func (r RouteRankingResult) RankedRoutes() []RankedRoute {
	if len(r.rankedRoutes) == 0 {
		return nil
	}
	return append([]RankedRoute(nil), r.rankedRoutes...)
}

// SelectedRoute returns the first ranked route.
func (r RouteRankingResult) SelectedRoute() (RankedRoute, bool) {
	if len(r.rankedRoutes) == 0 {
		return RankedRoute{}, false
	}
	return r.rankedRoutes[0], true
}

// Validate verifies every ranking binding, component score, and ordering invariant.
func (r RouteRankingResult) Validate() error {
	if !validRequestIdentity(r.requestIdentity) {
		return ErrInvalidRequestIdentity
	}
	if !validRequestIdentity(r.reviewScopeIdentity) {
		return ErrInvalidReviewRoutingInputIdentity
	}
	if !validRequestIdentity(r.routingInputIdentity) {
		return ErrInvalidReviewRoutingInputIdentity
	}
	if r.registryRevision == 0 {
		return ErrInvalidRouteFilterRevision
	}
	if r.performanceRevision == 0 {
		return provider.ErrInvalidRoutePerformanceRevision
	}
	if err := r.costBudget.Validate(); err != nil {
		return err
	}
	if !validRequestIdentity(r.rankingPolicyIdentity) {
		return ErrInvalidRouteRankingPolicyIdentity
	}
	if len(r.rankedRoutes) == 0 {
		return ErrNoEligibleRoute
	}
	if len(r.rankedRoutes) > maxRouteFilterCandidates {
		return ErrTooManyRouteCandidates
	}
	seenIdentities := make(map[string]struct{}, len(r.rankedRoutes))
	seenReferences := make(map[provider.RouteReference]struct{}, len(r.rankedRoutes))
	seenPreferenceRanks := make(map[uint8]struct{}, len(r.rankedRoutes))
	pinnedCount := 0
	for index, ranked := range r.rankedRoutes {
		if err := ranked.route.Validate(); err != nil {
			return err
		}
		record := ranked.route.ResolvedRecord().RouteRegistryRecord()
		identity := record.Identity()
		if record.RegistryRevision() != r.registryRevision {
			return ErrRouteCandidateRevisionMismatch
		}
		if _, exists := seenIdentities[identity]; exists {
			return ErrDuplicateRouteCandidate
		}
		seenIdentities[identity] = struct{}{}
		reference := observedRouteReference(ranked.route)
		if _, exists := seenReferences[reference]; exists {
			return ErrDuplicateRouteReference
		}
		seenReferences[reference] = struct{}{}
		if err := CheckRouteOperationalEligibility(ranked.route.ResolvedRecord(), ranked.route.OperationalState()); err != nil {
			return ErrInvalidRouteRankingResult
		}
		if err := ranked.performance.Validate(); err != nil {
			return err
		}
		if ranked.performance.RecordIdentity() != identity {
			return ErrRoutePerformanceSetMismatch
		}
		if ranked.performance.ObservationRevision() != r.performanceRevision {
			return ErrRoutePerformanceRevisionMismatch
		}
		pricing := record.RouteCandidateDeclaration().RoutePricing()
		estimate, err := provider.EstimateMaximumRouteCost(pricing, r.costBudget)
		if err != nil {
			return err
		}
		if estimate != ranked.maximumCost {
			return ErrInvalidRouteRankingResult
		}
		if err := ranked.QualityTier().Validate(); err != nil {
			return err
		}
		if ranked.pinned {
			pinnedCount++
			if ranked.preferenceRank != 0 {
				return ErrInvalidRouteRankingResult
			}
		}
		if ranked.preferenceRank > maxRouteRankingPreferences {
			return ErrInvalidRouteRankingResult
		}
		if ranked.preferenceRank != 0 {
			if _, exists := seenPreferenceRanks[ranked.preferenceRank]; exists {
				return ErrInvalidRouteRankingResult
			}
			seenPreferenceRanks[ranked.preferenceRank] = struct{}{}
		}
		if index > 0 && rankedRouteLess(ranked, r.rankedRoutes[index-1]) {
			return ErrInvalidRouteRankingResult
		}
	}
	if pinnedCount > 1 {
		return ErrInvalidRouteRankingResult
	}
	return nil
}

// String returns a redacted ranking-result description.
func (r RouteRankingResult) String() string { return "route ranking result" }

// GoString returns a redacted Go-syntax ranking-result description.
func (r RouteRankingResult) GoString() string {
	return "gateway.RouteRankingResult{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RouteRankingResult) Format(state fmt.State, verb rune) {
	formatted := "route ranking result"
	if verb == 'q' {
		formatted = `"route ranking result"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteRankingResult{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// RankEligibleRoutes ranks with fixed lexicographic precedence and selects the first route.
func RankEligibleRoutes(eligibility RouteEligibilityResult, policy RouteRankingPolicy, performanceRevision uint64, observations []provider.RoutePerformanceObservation) (RouteRankingResult, error) {
	if err := eligibility.Validate(); err != nil {
		return RouteRankingResult{}, err
	}
	if err := policy.Validate(); err != nil {
		return RouteRankingResult{}, err
	}
	if performanceRevision == 0 {
		return RouteRankingResult{}, provider.ErrInvalidRoutePerformanceRevision
	}
	eligible := eligibility.EligibleRoutes()
	if len(eligible) == 0 {
		return RouteRankingResult{}, ErrNoEligibleRoute
	}
	observationsByIdentity := make(map[string]provider.RoutePerformanceObservation, len(observations))
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return RouteRankingResult{}, err
		}
		if observation.ObservationRevision() != performanceRevision {
			return RouteRankingResult{}, ErrRoutePerformanceRevisionMismatch
		}
		if _, exists := observationsByIdentity[observation.RecordIdentity()]; exists {
			return RouteRankingResult{}, ErrDuplicateRoutePerformanceObservation
		}
		observationsByIdentity[observation.RecordIdentity()] = observation
	}
	if len(observationsByIdentity) != len(eligible) {
		return RouteRankingResult{}, ErrRoutePerformanceSetMismatch
	}
	preferenceRanks := make(map[provider.RouteReference]uint8, len(policy.preferredRoutes))
	for index, reference := range policy.preferredRoutes {
		preferenceRanks[reference] = uint8(index + 1)
	}
	pinnedReference, hasPin := policy.PinnedRoute()
	pinMatched := !hasPin
	ranked := make([]RankedRoute, 0, len(eligible))
	for _, route := range eligible {
		identity := observedRouteIdentity(route)
		observation, exists := observationsByIdentity[identity]
		if !exists {
			return RouteRankingResult{}, ErrRoutePerformanceSetMismatch
		}
		reference := observedRouteReference(route)
		pinned := hasPin && reference == pinnedReference
		pinMatched = pinMatched || pinned
		pricing := route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RoutePricing()
		estimate, err := provider.EstimateMaximumRouteCost(pricing, eligibility.CostBudget())
		if err != nil {
			return RouteRankingResult{}, err
		}
		ranked = append(ranked, RankedRoute{
			route:          route,
			performance:    observation,
			pinned:         pinned,
			preferenceRank: preferenceRanks[reference],
			maximumCost:    estimate,
		})
		delete(observationsByIdentity, identity)
	}
	if len(observationsByIdentity) != 0 {
		return RouteRankingResult{}, ErrRoutePerformanceSetMismatch
	}
	if !pinMatched {
		return RouteRankingResult{}, ErrPinnedRouteNotEligible
	}
	sort.Slice(ranked, func(i, j int) bool { return rankedRouteLess(ranked[i], ranked[j]) })
	return RouteRankingResult{
		requestIdentity:       eligibility.RequestIdentity(),
		reviewScopeIdentity:   eligibility.ReviewScopeIdentity(),
		routingInputIdentity:  eligibility.RoutingInputIdentity(),
		registryRevision:      eligibility.RegistryRevision(),
		performanceRevision:   performanceRevision,
		costBudget:            eligibility.CostBudget(),
		rankingPolicyIdentity: policy.Identity(),
		rankedRoutes:          ranked,
	}, nil
}

func rankedRouteLess(left, right RankedRoute) bool {
	if left.pinned != right.pinned {
		return left.pinned
	}
	leftPreferred := left.preferenceRank != 0
	rightPreferred := right.preferenceRank != 0
	if leftPreferred != rightPreferred {
		return leftPreferred
	}
	if leftPreferred && left.preferenceRank != right.preferenceRank {
		return left.preferenceRank < right.preferenceRank
	}
	if left.QualityTier() != right.QualityTier() {
		return left.QualityTier() > right.QualityTier()
	}
	leftCost := left.maximumCost.MaximumCostMicroUSD()
	rightCost := right.maximumCost.MaximumCostMicroUSD()
	if leftCost != rightCost {
		return leftCost < rightCost
	}
	if left.performance.LatencyKnown() != right.performance.LatencyKnown() {
		return left.performance.LatencyKnown()
	}
	if left.performance.LatencyKnown() && left.performance.P95LatencyMilliseconds() != right.performance.P95LatencyMilliseconds() {
		return left.performance.P95LatencyMilliseconds() < right.performance.P95LatencyMilliseconds()
	}
	return observedRouteIdentity(left.route) < observedRouteIdentity(right.route)
}
