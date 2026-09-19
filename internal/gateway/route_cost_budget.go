package gateway

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrRouteCostExceedsBudget identifies a pessimistic estimate above the hard request cap.
	ErrRouteCostExceedsBudget = errors.New("route cost exceeds budget")
)

// CheckRouteCostBudget rejects unknown pricing and pessimistic estimates above the hard cap.
func CheckRouteCostBudget(pricing provider.RoutePricing, budget provider.ModelCostBudget) error {
	estimate, err := provider.EstimateMaximumRouteCost(pricing, budget)
	if err != nil {
		return err
	}
	if estimate.MaximumCostMicroUSD() > budget.MaxCostMicroUSD() {
		return ErrRouteCostExceedsBudget
	}
	return nil
}
