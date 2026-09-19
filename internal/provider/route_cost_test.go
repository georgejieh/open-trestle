package provider

import (
	"errors"
	"math"
	"testing"
)

func TestRoutePricingKnownAndUnknownStates(t *testing.T) {
	known, err := NewRoutePricing(10, 20)
	if err != nil || !known.IsKnown() || known.InputMicroUSDPerMillionTokens() != 10 || known.OutputMicroUSDPerMillionTokens() != 20 || known.Validate() != nil {
		t.Fatalf("known pricing = (%#v, %v)", known, err)
	}
	unknown := NewUnknownRoutePricing()
	if unknown.IsKnown() || unknown.InputMicroUSDPerMillionTokens() != 0 || unknown.OutputMicroUSDPerMillionTokens() != 0 || unknown.Validate() != nil {
		t.Fatalf("unknown pricing = %#v", unknown)
	}
	if err := (RoutePricing{}).Validate(); !errors.Is(err, ErrInvalidRoutePricing) {
		t.Fatalf("zero pricing Validate() = %v", err)
	}
}

func TestNewRoutePricingAcceptsFreeAndBoundaryPrices(t *testing.T) {
	for _, price := range []uint64{0, maxRoutePriceMicroUSDPerMillionTokens} {
		pricing, err := NewRoutePricing(price, price)
		if err != nil || !pricing.IsKnown() {
			t.Fatalf("NewRoutePricing(%d) = (%#v, %v)", price, pricing, err)
		}
	}
	pricing, err := NewRoutePricing(maxRoutePriceMicroUSDPerMillionTokens+1, 0)
	if !errors.Is(err, ErrRoutePriceTooLarge) || pricing != (RoutePricing{}) {
		t.Fatalf("oversized pricing = (%#v, %v)", pricing, err)
	}
}

func TestNewModelCostBudgetBindsHardLimits(t *testing.T) {
	budget, err := NewModelCostBudget(100, 20, 0)
	if err != nil || budget.EstimatedInputTokens() != 100 || budget.MaxOutputTokens() != 20 || budget.MaxCostMicroUSD() != 0 || budget.Validate() != nil {
		t.Fatalf("budget = (%#v, %v)", budget, err)
	}
	for _, test := range []struct {
		name   string
		input  uint64
		output uint64
		cost   uint64
		want   error
	}{
		{name: "input", input: maxModelCostTokens + 1, output: 1, want: ErrModelCostTokensTooLarge},
		{name: "zero output", want: ErrInvalidModelCostBudget},
		{name: "output", output: maxModelCostTokens + 1, want: ErrModelCostTokensTooLarge},
		{name: "cost", output: 1, cost: maxModelCostMicroUSD + 1, want: ErrModelCostBudgetTooLarge},
	} {
		budget, err := NewModelCostBudget(test.input, test.output, test.cost)
		if !errors.Is(err, test.want) || budget != (ModelCostBudget{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, budget, err, test.want)
		}
	}
}

func TestEstimateMaximumRouteCostRoundsUpEachComponent(t *testing.T) {
	pricing, _ := NewRoutePricing(1, 1)
	budget, _ := NewModelCostBudget(1, 1, 2)
	estimate, err := EstimateMaximumRouteCost(pricing, budget)
	if err != nil || estimate.InputCostMicroUSD() != 1 || estimate.OutputCostMicroUSD() != 1 || estimate.MaximumCostMicroUSD() != 2 || estimate.Validate() != nil {
		t.Fatalf("estimate = (%#v, %v)", estimate, err)
	}
}

func TestEstimateMaximumRouteCostHandlesExactAndFreePricing(t *testing.T) {
	budget, _ := NewModelCostBudget(2, 3, 5)
	pricing, _ := NewRoutePricing(1_000_000, 1_000_000)
	estimate, err := EstimateMaximumRouteCost(pricing, budget)
	if err != nil || estimate.InputCostMicroUSD() != 2 || estimate.OutputCostMicroUSD() != 3 || estimate.MaximumCostMicroUSD() != 5 {
		t.Fatalf("exact estimate = (%#v, %v)", estimate, err)
	}
	free, _ := NewRoutePricing(0, 0)
	zero, err := EstimateMaximumRouteCost(free, budget)
	if err != nil || zero.InputCostMicroUSD() != 0 || zero.OutputCostMicroUSD() != 0 || zero.MaximumCostMicroUSD() != 0 {
		t.Fatalf("free estimate = (%#v, %v)", zero, err)
	}
}

func TestEstimateMaximumRouteCostRejectsUnknownOrInvalidInputs(t *testing.T) {
	validPricing, _ := NewRoutePricing(1, 1)
	validBudget, _ := NewModelCostBudget(1, 1, 1)
	for _, test := range []struct {
		name    string
		pricing RoutePricing
		budget  ModelCostBudget
		want    error
	}{
		{name: "unknown", pricing: NewUnknownRoutePricing(), budget: validBudget, want: ErrUnknownRoutePricing},
		{name: "pricing", budget: validBudget, want: ErrInvalidRoutePricing},
		{name: "budget", pricing: validPricing, want: ErrInvalidModelCostBudget},
	} {
		estimate, err := EstimateMaximumRouteCost(test.pricing, test.budget)
		if !errors.Is(err, test.want) || estimate != (RouteCostEstimate{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, estimate, err, test.want)
		}
	}
}

func TestRouteCostEstimateRejectsForgedOverflow(t *testing.T) {
	for _, estimate := range []RouteCostEstimate{
		{},
		{isValid: true, inputCostMicroUSD: math.MaxUint64, outputCostMicroUSD: 1},
		{isValid: true, inputCostMicroUSD: maxModelCostMicroUSD + 1, maximumCostMicroUSD: maxModelCostMicroUSD + 1},
		{isValid: true, inputCostMicroUSD: 1, outputCostMicroUSD: 1, maximumCostMicroUSD: 1},
	} {
		if err := estimate.Validate(); !errors.Is(err, ErrInvalidRouteCostEstimate) {
			t.Fatalf("Validate() = %v for %#v", err, estimate)
		}
	}
}
