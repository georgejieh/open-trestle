package provider

import (
	"errors"
	"testing"
)

func TestRouteTokenUsageRepresentsKnownAndUnknownStates(t *testing.T) {
	known, err := NewRouteTokenUsage(1_000_001, 500_001, 250_000)
	if err != nil {
		t.Fatal(err)
	}
	if !known.IsKnown() || known.InputTokens() != 1_000_001 || known.OutputTokens() != 500_001 || known.CachedInputTokens() != 250_000 || known.Validate() != nil {
		t.Fatalf("known usage did not round trip: %#v", known)
	}
	unknown := NewUnknownRouteTokenUsage()
	if unknown.IsKnown() || unknown.InputTokens() != 0 || unknown.OutputTokens() != 0 || unknown.CachedInputTokens() != 0 || unknown.Validate() != nil {
		t.Fatalf("unknown usage did not round trip: %#v", unknown)
	}
}

func TestRouteTokenUsageRejectsInvalidValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  uint64
		output uint64
		cached uint64
		want   error
	}{
		{name: "input", input: maxModelCostTokens + 1, want: ErrRouteUsageTokensTooLarge},
		{name: "output", output: maxModelCostTokens + 1, want: ErrRouteUsageTokensTooLarge},
		{name: "cached", input: 1, cached: 2, want: ErrInvalidRouteTokenUsage},
	} {
		t.Run(test.name, func(t *testing.T) {
			usage, err := NewRouteTokenUsage(test.input, test.output, test.cached)
			if !errors.Is(err, test.want) || usage.IsKnown() {
				t.Fatalf("NewRouteTokenUsage() = (%#v, %v), want %v", usage, err, test.want)
			}
		})
	}
	if err := (RouteTokenUsage{}).Validate(); !errors.Is(err, ErrInvalidRouteTokenUsage) {
		t.Fatalf("zero usage Validate() = %v", err)
	}
}

func TestCalculateActualRouteCostUsesCeilingMicroUSDArithmetic(t *testing.T) {
	pricing, _ := NewRoutePricing(3, 7)
	usage, _ := NewRouteTokenUsage(1_000_001, 500_001, 10)
	cost, err := CalculateActualRouteCost(pricing, usage)
	if err != nil {
		t.Fatal(err)
	}
	if !cost.IsKnown() || cost.InputCostMicroUSD() != 4 || cost.OutputCostMicroUSD() != 4 || cost.TotalCostMicroUSD() != 8 || cost.Validate() != nil {
		t.Fatalf("actual cost = %#v", cost)
	}
	free, _ := NewRoutePricing(0, 0)
	zeroUsage, _ := NewRouteTokenUsage(0, 0, 0)
	cost, err = CalculateActualRouteCost(free, zeroUsage)
	if err != nil || !cost.IsKnown() || cost.TotalCostMicroUSD() != 0 {
		t.Fatalf("free actual cost = (%#v, %v)", cost, err)
	}
}

func TestCalculateActualRouteCostKeepsUnknownUsageExplicit(t *testing.T) {
	pricing, _ := NewRoutePricing(3, 7)
	cost, err := CalculateActualRouteCost(pricing, NewUnknownRouteTokenUsage())
	if err != nil || cost.IsKnown() || cost.InputCostMicroUSD() != 0 || cost.OutputCostMicroUSD() != 0 || cost.TotalCostMicroUSD() != 0 || cost.Validate() != nil {
		t.Fatalf("unknown actual cost = (%#v, %v)", cost, err)
	}
	if cost, err = CalculateActualRouteCost(NewUnknownRoutePricing(), NewUnknownRouteTokenUsage()); !errors.Is(err, ErrUnknownRoutePricing) || cost.Validate() == nil {
		t.Fatalf("unknown pricing = (%#v, %v)", cost, err)
	}
}

func TestRouteActualCostRejectsMalformedValues(t *testing.T) {
	for _, cost := range []RouteActualCost{
		{},
		{kind: routeActualCostUnknown, inputCostMicroUSD: 1},
		{kind: routeActualCostKnown, inputCostMicroUSD: 1, outputCostMicroUSD: 2, totalCostMicroUSD: 2},
	} {
		if err := cost.Validate(); !errors.Is(err, ErrInvalidRouteActualCost) {
			t.Fatalf("cost %#v Validate() = %v", cost, err)
		}
	}
}
