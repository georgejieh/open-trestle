package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestCheckRouteCostBudgetAcceptsBelowAndAtHardCap(t *testing.T) {
	pricing, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	for _, test := range []struct {
		name string
		cost uint64
	}{
		{name: "at", cost: 5},
		{name: "above estimate", cost: 6},
	} {
		budget, _ := provider.NewModelCostBudget(2, 3, test.cost)
		if err := CheckRouteCostBudget(pricing, budget); err != nil {
			t.Fatalf("%s CheckRouteCostBudget() = %v", test.name, err)
		}
	}
}

func TestCheckRouteCostBudgetRejectsEstimateAboveHardCap(t *testing.T) {
	pricing, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	budget, _ := provider.NewModelCostBudget(2, 3, 4)
	if err := CheckRouteCostBudget(pricing, budget); err != ErrRouteCostExceedsBudget {
		t.Fatalf("CheckRouteCostBudget() = %v", err)
	}
}

func TestCheckRouteCostBudgetAllowsKnownFreeRouteAtZeroCap(t *testing.T) {
	pricing, _ := provider.NewRoutePricing(0, 0)
	budget, _ := provider.NewModelCostBudget(100, 20, 0)
	if err := CheckRouteCostBudget(pricing, budget); err != nil {
		t.Fatalf("CheckRouteCostBudget() = %v", err)
	}
}

func TestCheckRouteCostBudgetRejectsUnknownAndInvalidValues(t *testing.T) {
	validPricing, _ := provider.NewRoutePricing(1, 1)
	validBudget, _ := provider.NewModelCostBudget(1, 1, 1)
	for _, test := range []struct {
		name    string
		pricing provider.RoutePricing
		budget  provider.ModelCostBudget
		want    error
	}{
		{name: "unknown", pricing: provider.NewUnknownRoutePricing(), budget: validBudget, want: provider.ErrUnknownRoutePricing},
		{name: "pricing", budget: validBudget, want: provider.ErrInvalidRoutePricing},
		{name: "budget", pricing: validPricing, want: provider.ErrInvalidModelCostBudget},
	} {
		if err := CheckRouteCostBudget(test.pricing, test.budget); !errors.Is(err, test.want) {
			t.Fatalf("%s CheckRouteCostBudget() = %v, want %v", test.name, err, test.want)
		}
	}
}
