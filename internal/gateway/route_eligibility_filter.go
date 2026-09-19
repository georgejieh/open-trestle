package gateway

import (
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrModelCostBudgetConflictsWithRequirements identifies an output cap below the required model output.
	ErrModelCostBudgetConflictsWithRequirements = errors.New("model cost budget conflicts with model requirements")
	// ErrDuplicateRouteReference identifies conflicting records for one exact route in a registry snapshot.
	ErrDuplicateRouteReference = errors.New("duplicate route reference")
	// ErrInvalidRouteEligibilityResult identifies a structurally inconsistent eligibility result.
	ErrInvalidRouteEligibilityResult = errors.New("invalid route eligibility result")
)

// RouteEligibilityResult contains every fully eligible route and typed rejection in canonical order.
type RouteEligibilityResult struct {
	requestIdentity      string
	reviewScopeIdentity  string
	routingInputIdentity string
	registryRevision     uint64
	costBudget           provider.ModelCostBudget
	eligibleRoutes       []ObservedRouteCandidate
	rejectedRoutes       []RouteRejection
}

// RequestIdentity returns the request identity bound to the eligibility decision.
func (r RouteEligibilityResult) RequestIdentity() string { return r.requestIdentity }

// ReviewScopeIdentity returns the tenant-owned review scope identity.
func (r RouteEligibilityResult) ReviewScopeIdentity() string { return r.reviewScopeIdentity }

// RoutingInputIdentity returns the bound request, requirement, and policy input identity.
func (r RouteEligibilityResult) RoutingInputIdentity() string { return r.routingInputIdentity }

// RegistryRevision returns the registry snapshot revision used by the filter.
func (r RouteEligibilityResult) RegistryRevision() uint64 { return r.registryRevision }

// CostBudget returns the hard cost budget bound to the eligibility decision.
func (r RouteEligibilityResult) CostBudget() provider.ModelCostBudget { return r.costBudget }

// EligibleRoutes returns a defensive copy in canonical record-identity order.
func (r RouteEligibilityResult) EligibleRoutes() []ObservedRouteCandidate {
	if len(r.eligibleRoutes) == 0 {
		return nil
	}
	return append([]ObservedRouteCandidate(nil), r.eligibleRoutes...)
}

// RejectedRoutes returns a defensive copy in canonical record-identity order.
func (r RouteEligibilityResult) RejectedRoutes() []RouteRejection {
	if len(r.rejectedRoutes) == 0 {
		return nil
	}
	return append([]RouteRejection(nil), r.rejectedRoutes...)
}

// Validate verifies the result binding, canonical order, readiness, cost, and uniqueness.
func (r RouteEligibilityResult) Validate() error {
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
	if err := r.costBudget.Validate(); err != nil {
		return err
	}
	if len(r.eligibleRoutes)+len(r.rejectedRoutes) > maxRouteFilterCandidates {
		return ErrTooManyRouteCandidates
	}
	seenIdentities := make(map[string]struct{}, len(r.eligibleRoutes)+len(r.rejectedRoutes))
	seenReferences := make(map[provider.RouteReference]struct{}, len(r.eligibleRoutes))
	previousIdentity := ""
	for _, route := range r.eligibleRoutes {
		if err := route.Validate(); err != nil {
			return err
		}
		record := route.ResolvedRecord().RouteRegistryRecord()
		if record.RegistryRevision() != r.registryRevision {
			return ErrRouteCandidateRevisionMismatch
		}
		identity := record.Identity()
		if previousIdentity != "" && identity <= previousIdentity {
			return ErrInvalidRouteEligibilityResult
		}
		if err := CheckRouteOperationalEligibility(route.ResolvedRecord(), route.OperationalState()); err != nil {
			return ErrInvalidRouteEligibilityResult
		}
		if err := CheckResolvedRouteTokenCapacity(route.ResolvedRecord(), r.costBudget); err != nil {
			return ErrInvalidRouteEligibilityResult
		}
		if err := CheckResolvedRouteCostBudget(route.ResolvedRecord(), r.costBudget); err != nil {
			return ErrInvalidRouteEligibilityResult
		}
		reference := observedRouteReference(route)
		if _, exists := seenReferences[reference]; exists {
			return ErrDuplicateRouteReference
		}
		seenReferences[reference] = struct{}{}
		seenIdentities[identity] = struct{}{}
		previousIdentity = identity
	}
	previousIdentity = ""
	for _, rejection := range r.rejectedRoutes {
		if !validRequestIdentity(rejection.RecordIdentity()) || rejection.OperationalRevision() == 0 || rejection.Reason().Validate() != nil {
			return ErrInvalidRouteEligibilityResult
		}
		if previousIdentity != "" && rejection.RecordIdentity() <= previousIdentity {
			return ErrInvalidRouteEligibilityResult
		}
		if _, exists := seenIdentities[rejection.RecordIdentity()]; exists {
			return ErrDuplicateRouteCandidate
		}
		seenIdentities[rejection.RecordIdentity()] = struct{}{}
		previousIdentity = rejection.RecordIdentity()
	}
	return nil
}

// String returns a redacted eligibility-result description.
func (r RouteEligibilityResult) String() string { return "route eligibility result" }

// GoString returns a redacted Go-syntax eligibility-result description.
func (r RouteEligibilityResult) GoString() string {
	return "gateway.RouteEligibilityResult{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RouteEligibilityResult) Format(state fmt.State, verb rune) {
	formatted := "route eligibility result"
	if verb == 'q' {
		formatted = `"route eligibility result"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteEligibilityResult{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// FilterEligibleRoutes applies policy, readiness, and cost gates in fixed order.
func FilterEligibleRoutes(input ReviewRoutingInput, budget provider.ModelCostBudget, registryRevision uint64, routes []ObservedRouteCandidate) (RouteEligibilityResult, error) {
	if err := input.Validate(); err != nil {
		return RouteEligibilityResult{}, err
	}
	if err := budget.Validate(); err != nil {
		return RouteEligibilityResult{}, err
	}
	if budget.MaxOutputTokens() < input.ModelRequirements().MinOutputTokens() {
		return RouteEligibilityResult{}, ErrModelCostBudgetConflictsWithRequirements
	}
	if registryRevision == 0 {
		return RouteEligibilityResult{}, ErrInvalidRouteFilterRevision
	}
	if len(routes) > maxRouteFilterCandidates {
		return RouteEligibilityResult{}, ErrTooManyRouteCandidates
	}
	canonicalRoutes := append([]ObservedRouteCandidate(nil), routes...)
	for _, route := range canonicalRoutes {
		if err := route.Validate(); err != nil {
			return RouteEligibilityResult{}, err
		}
		if route.ResolvedRecord().RouteRegistryRecord().RegistryRevision() != registryRevision {
			return RouteEligibilityResult{}, ErrRouteCandidateRevisionMismatch
		}
	}
	sort.Slice(canonicalRoutes, func(i, j int) bool {
		return observedRouteIdentity(canonicalRoutes[i]) < observedRouteIdentity(canonicalRoutes[j])
	})
	for index := 1; index < len(canonicalRoutes); index++ {
		if observedRouteIdentity(canonicalRoutes[index-1]) == observedRouteIdentity(canonicalRoutes[index]) {
			return RouteEligibilityResult{}, ErrDuplicateRouteCandidate
		}
	}
	seenReferences := make(map[provider.RouteReference]struct{}, len(canonicalRoutes))
	for _, route := range canonicalRoutes {
		reference := observedRouteReference(route)
		if _, exists := seenReferences[reference]; exists {
			return RouteEligibilityResult{}, ErrDuplicateRouteReference
		}
		seenReferences[reference] = struct{}{}
	}
	result := RouteEligibilityResult{
		requestIdentity: input.RequestIdentity(), reviewScopeIdentity: input.ReviewScopeIdentity(),
		routingInputIdentity: input.Identity(),
		registryRevision:     registryRevision,
		costBudget:           budget,
	}
	for _, route := range canonicalRoutes {
		err := CheckResolvedRouteRegistryRecordCompatibility(input, route.ResolvedRecord())
		if err == nil {
			err = CheckRouteOperationalEligibility(route.ResolvedRecord(), route.OperationalState())
		}
		if err == nil {
			err = CheckResolvedRouteTokenCapacity(route.ResolvedRecord(), budget)
		}
		if err == nil {
			err = CheckResolvedRouteCostBudget(route.ResolvedRecord(), budget)
		}
		if err == nil {
			result.eligibleRoutes = append(result.eligibleRoutes, route)
			continue
		}
		reason, ok := routeRejectionReason(err)
		if !ok {
			return RouteEligibilityResult{}, ErrUnexpectedRouteCompatibilityError
		}
		result.rejectedRoutes = append(result.rejectedRoutes, RouteRejection{
			recordIdentity:      observedRouteIdentity(route),
			operationalRevision: route.OperationalState().ObservationRevision(),
			reason:              reason,
		})
	}
	return result, nil
}

func observedRouteIdentity(route ObservedRouteCandidate) string {
	return route.ResolvedRecord().RouteRegistryRecord().Identity()
}

func observedRouteReference(route ObservedRouteCandidate) provider.RouteReference {
	return route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
}
