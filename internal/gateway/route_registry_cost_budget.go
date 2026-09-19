package gateway

import "github.com/georgejieh/open-trestle/internal/provider"

// CheckResolvedRouteCostBudget evaluates only the pricing bound to a resolved registry record.
func CheckResolvedRouteCostBudget(resolved ResolvedRouteRegistryRecord, budget provider.ModelCostBudget) error {
	if err := resolved.Validate(); err != nil {
		return err
	}
	if err := budget.Validate(); err != nil {
		return err
	}
	pricing := resolved.RouteRegistryRecord().RouteCandidateDeclaration().RoutePricing()
	return CheckRouteCostBudget(pricing, budget)
}

// CheckResolvedRouteTokenCapacity requires the authorized token envelope to fit the approved capability.
func CheckResolvedRouteTokenCapacity(resolved ResolvedRouteRegistryRecord, budget provider.ModelCostBudget) error {
	if err := resolved.Validate(); err != nil {
		return err
	}
	if err := budget.Validate(); err != nil {
		return err
	}
	capabilities := resolved.RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().ModelCapabilities()
	if budget.MaxOutputTokens() > capabilities.MaxOutputTokens() {
		return provider.ErrInsufficientModelOutput
	}
	if uint64(budget.EstimatedInputTokens())+uint64(budget.MaxOutputTokens()) > uint64(capabilities.MaxContextTokens()) {
		return provider.ErrInsufficientModelContext
	}
	return nil
}
