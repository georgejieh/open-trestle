package provider

import (
	"errors"
)

const (
	tokensPerMillion                      = 1_000_000
	maxRoutePriceMicroUSDPerMillionTokens = 1 << 30
	maxModelCostTokens                    = maxModelRequirementTokens
	maxModelCostMicroUSD                  = 1 << 62
)

var (
	// ErrInvalidRoutePricing identifies a malformed known or unknown price declaration.
	ErrInvalidRoutePricing = errors.New("invalid route pricing")
	// ErrRoutePriceTooLarge identifies a token price beyond the supported arithmetic bound.
	ErrRoutePriceTooLarge = errors.New("route price too large")
	// ErrUnknownRoutePricing identifies a route without a usable price declaration.
	ErrUnknownRoutePricing = errors.New("unknown route pricing")
	// ErrInvalidModelCostBudget identifies a budget without a positive output-token bound.
	ErrInvalidModelCostBudget = errors.New("invalid model cost budget")
	// ErrModelCostTokensTooLarge identifies token input beyond the supported bound.
	ErrModelCostTokensTooLarge = errors.New("model cost tokens too large")
	// ErrModelCostBudgetTooLarge identifies a cost cap beyond the supported bound.
	ErrModelCostBudgetTooLarge = errors.New("model cost budget too large")
	// ErrInvalidRouteCostEstimate identifies malformed derived cost fields.
	ErrInvalidRouteCostEstimate = errors.New("invalid route cost estimate")
)

type routePricingKind uint8

const (
	routePricingUnknown routePricingKind = iota + 1
	routePricingKnown
)

// RoutePricing declares fixed input and output prices in micro-USD per million tokens.
type RoutePricing struct {
	kind                           routePricingKind
	inputMicroUSDPerMillionTokens  uint64
	outputMicroUSDPerMillionTokens uint64
}

// NewRoutePricing creates a known fixed-price declaration. Zero prices are valid.
func NewRoutePricing(inputMicroUSDPerMillionTokens, outputMicroUSDPerMillionTokens uint64) (RoutePricing, error) {
	pricing := RoutePricing{
		kind:                           routePricingKnown,
		inputMicroUSDPerMillionTokens:  inputMicroUSDPerMillionTokens,
		outputMicroUSDPerMillionTokens: outputMicroUSDPerMillionTokens,
	}
	if err := pricing.Validate(); err != nil {
		return RoutePricing{}, err
	}
	return pricing, nil
}

// NewUnknownRoutePricing creates an explicit unknown-price declaration.
func NewUnknownRoutePricing() RoutePricing { return RoutePricing{kind: routePricingUnknown} }

// IsKnown reports whether exact fixed prices are declared.
func (p RoutePricing) IsKnown() bool { return p.kind == routePricingKnown }

// InputMicroUSDPerMillionTokens returns the fixed input price or zero when unknown.
func (p RoutePricing) InputMicroUSDPerMillionTokens() uint64 {
	return p.inputMicroUSDPerMillionTokens
}

// OutputMicroUSDPerMillionTokens returns the fixed output price or zero when unknown.
func (p RoutePricing) OutputMicroUSDPerMillionTokens() uint64 {
	return p.outputMicroUSDPerMillionTokens
}

// Validate verifies the price state and arithmetic bounds.
func (p RoutePricing) Validate() error {
	switch p.kind {
	case routePricingUnknown:
		if p.inputMicroUSDPerMillionTokens != 0 || p.outputMicroUSDPerMillionTokens != 0 {
			return ErrInvalidRoutePricing
		}
		return nil
	case routePricingKnown:
		if p.inputMicroUSDPerMillionTokens > maxRoutePriceMicroUSDPerMillionTokens || p.outputMicroUSDPerMillionTokens > maxRoutePriceMicroUSDPerMillionTokens {
			return ErrRoutePriceTooLarge
		}
		return nil
	default:
		return ErrInvalidRoutePricing
	}
}

// ModelCostBudget binds the pessimistic token estimates and hard micro-USD cap for one request.
type ModelCostBudget struct {
	estimatedInputTokens uint32
	maxOutputTokens      uint32
	maxCostMicroUSD      uint64
}

// NewModelCostBudget creates a bounded hard request budget.
func NewModelCostBudget(estimatedInputTokens, maxOutputTokens, maxCostMicroUSD uint64) (ModelCostBudget, error) {
	if estimatedInputTokens > maxModelCostTokens || maxOutputTokens > maxModelCostTokens {
		return ModelCostBudget{}, ErrModelCostTokensTooLarge
	}
	if maxOutputTokens == 0 {
		return ModelCostBudget{}, ErrInvalidModelCostBudget
	}
	if maxCostMicroUSD > maxModelCostMicroUSD {
		return ModelCostBudget{}, ErrModelCostBudgetTooLarge
	}
	return ModelCostBudget{
		estimatedInputTokens: uint32(estimatedInputTokens),
		maxOutputTokens:      uint32(maxOutputTokens),
		maxCostMicroUSD:      maxCostMicroUSD,
	}, nil
}

// EstimatedInputTokens returns the pessimistic input-token estimate.
func (b ModelCostBudget) EstimatedInputTokens() uint32 { return b.estimatedInputTokens }

// MaxOutputTokens returns the hard output-token bound.
func (b ModelCostBudget) MaxOutputTokens() uint32 { return b.maxOutputTokens }

// MaxCostMicroUSD returns the inclusive hard cost cap.
func (b ModelCostBudget) MaxCostMicroUSD() uint64 { return b.maxCostMicroUSD }

// Validate verifies token and cost bounds.
func (b ModelCostBudget) Validate() error {
	if b.estimatedInputTokens > maxModelCostTokens || b.maxOutputTokens > maxModelCostTokens {
		return ErrModelCostTokensTooLarge
	}
	if b.maxOutputTokens == 0 {
		return ErrInvalidModelCostBudget
	}
	if b.maxCostMicroUSD > maxModelCostMicroUSD {
		return ErrModelCostBudgetTooLarge
	}
	return nil
}

// RouteCostEstimate records pessimistic input, output, and total costs in micro-USD.
type RouteCostEstimate struct {
	isValid             bool
	inputCostMicroUSD   uint64
	outputCostMicroUSD  uint64
	maximumCostMicroUSD uint64
}

// InputCostMicroUSD returns the rounded-up input cost.
func (e RouteCostEstimate) InputCostMicroUSD() uint64 { return e.inputCostMicroUSD }

// OutputCostMicroUSD returns the rounded-up output cost.
func (e RouteCostEstimate) OutputCostMicroUSD() uint64 { return e.outputCostMicroUSD }

// MaximumCostMicroUSD returns the pessimistic total cost.
func (e RouteCostEstimate) MaximumCostMicroUSD() uint64 { return e.maximumCostMicroUSD }

// Validate verifies that component costs equal the total.
func (e RouteCostEstimate) Validate() error {
	if !e.isValid || e.inputCostMicroUSD > maxModelCostMicroUSD || e.outputCostMicroUSD > maxModelCostMicroUSD {
		return ErrInvalidRouteCostEstimate
	}
	if e.inputCostMicroUSD > maxModelCostMicroUSD-e.outputCostMicroUSD {
		return ErrInvalidRouteCostEstimate
	}
	if e.inputCostMicroUSD+e.outputCostMicroUSD != e.maximumCostMicroUSD {
		return ErrInvalidRouteCostEstimate
	}
	return nil
}

// EstimateMaximumRouteCost computes a pessimistic fixed-price request cost.
func EstimateMaximumRouteCost(pricing RoutePricing, budget ModelCostBudget) (RouteCostEstimate, error) {
	if err := pricing.Validate(); err != nil {
		return RouteCostEstimate{}, err
	}
	if !pricing.IsKnown() {
		return RouteCostEstimate{}, ErrUnknownRoutePricing
	}
	if err := budget.Validate(); err != nil {
		return RouteCostEstimate{}, err
	}
	inputCost := roundedUpTokenCost(budget.EstimatedInputTokens(), pricing.InputMicroUSDPerMillionTokens())
	outputCost := roundedUpTokenCost(budget.MaxOutputTokens(), pricing.OutputMicroUSDPerMillionTokens())
	return RouteCostEstimate{
		isValid:             true,
		inputCostMicroUSD:   inputCost,
		outputCostMicroUSD:  outputCost,
		maximumCostMicroUSD: inputCost + outputCost,
	}, nil
}

func roundedUpTokenCost(tokens uint32, microUSDPerMillionTokens uint64) uint64 {
	if tokens == 0 || microUSDPerMillionTokens == 0 {
		return 0
	}
	product := uint64(tokens) * microUSDPerMillionTokens
	return (product + tokensPerMillion - 1) / tokensPerMillion
}
