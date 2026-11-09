package gateway

import (
	"errors"
	"fmt"
)

// RouteContextShortfall reports that no candidate route was eligible and at
// least one was refused only for context capacity: the request's reservation, a
// byte-based upper bound on its input tokens plus the output allowance, exceeds
// what the route declares. It carries counts only, never request content.
type RouteContextShortfall struct {
	// EstimatedInputTokens and MaxOutputTokens are the reservation's parts;
	// RequiredTokens is their sum.
	EstimatedInputTokens, MaxOutputTokens uint32
	RequiredTokens                        uint64
	// DeclaredContextTokens is the largest max_context_tokens among the routes
	// refused for context.
	DeclaredContextTokens uint32
}

func (s *RouteContextShortfall) Error() string {
	return fmt.Sprintf("no eligible route: the request needs up to %d context tokens, routes declare at most %d", s.RequiredTokens, s.DeclaredContextTokens)
}

// Unwrap keeps errors.Is(err, ErrNoEligibleRoute) true for a shortfall.
func (s *RouteContextShortfall) Unwrap() error { return ErrNoEligibleRoute }

// RouteEligibilityRefusal explains an eligibility result without an eligible
// route. It returns a *RouteContextShortfall when some candidate in routes was
// refused because the reservation exceeds its declared context, and otherwise
// ErrNoEligibleRoute; it returns nil when a route is eligible.
func RouteEligibilityRefusal(eligibility RouteEligibilityResult, routes []ObservedRouteCandidate) error {
	if len(eligibility.EligibleRoutes()) != 0 {
		return nil
	}
	declared := map[string]uint32{}
	for _, route := range routes {
		declared[observedRouteIdentity(route)] = route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().ModelCapabilities().MaxContextTokens()
	}
	budget := eligibility.CostBudget()
	shortfall := &RouteContextShortfall{EstimatedInputTokens: budget.EstimatedInputTokens(), MaxOutputTokens: budget.MaxOutputTokens(), RequiredTokens: uint64(budget.EstimatedInputTokens()) + uint64(budget.MaxOutputTokens())}
	found := false
	for _, rejection := range eligibility.RejectedRoutes() {
		// A route below the policy's minimum context is refused with the same
		// reason; only a route the reservation outgrows is a shortfall.
		context, known := declared[rejection.RecordIdentity()]
		if rejection.Reason() == RouteRejectedInsufficientContext && known && uint64(context) < shortfall.RequiredTokens {
			shortfall.DeclaredContextTokens, found = max(shortfall.DeclaredContextTokens, context), true
		}
	}
	if !found {
		return ErrNoEligibleRoute
	}
	return shortfall
}

// RouteContextShortfallOf returns the shortfall err carries, if any.
func RouteContextShortfallOf(err error) (RouteContextShortfall, bool) {
	var shortfall *RouteContextShortfall
	if errors.As(err, &shortfall) && shortfall != nil {
		return *shortfall, true
	}
	return RouteContextShortfall{}, false
}
