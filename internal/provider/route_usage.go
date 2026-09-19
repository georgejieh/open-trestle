package provider

import "errors"

var (
	// ErrInvalidRouteTokenUsage identifies a malformed known or unknown usage report.
	ErrInvalidRouteTokenUsage = errors.New("invalid route token usage")
	// ErrRouteUsageTokensTooLarge identifies usage beyond the supported arithmetic bound.
	ErrRouteUsageTokensTooLarge = errors.New("route usage tokens too large")
	// ErrInvalidRouteActualCost identifies malformed derived actual-cost fields.
	ErrInvalidRouteActualCost = errors.New("invalid route actual cost")
)

type routeTokenUsageKind uint8

const (
	routeTokenUsageUnknown routeTokenUsageKind = iota + 1
	routeTokenUsageKnown
)

// RouteTokenUsage records provider-reported scalar token counts or an explicit unknown state.
type RouteTokenUsage struct {
	kind              routeTokenUsageKind
	inputTokens       uint32
	outputTokens      uint32
	cachedInputTokens uint32
}

// NewRouteTokenUsage creates a bounded known usage report. Cached tokens are included in input tokens.
func NewRouteTokenUsage(inputTokens, outputTokens, cachedInputTokens uint64) (RouteTokenUsage, error) {
	if inputTokens > maxModelCostTokens || outputTokens > maxModelCostTokens || cachedInputTokens > maxModelCostTokens {
		return RouteTokenUsage{}, ErrRouteUsageTokensTooLarge
	}
	usage := RouteTokenUsage{kind: routeTokenUsageKnown, inputTokens: uint32(inputTokens), outputTokens: uint32(outputTokens), cachedInputTokens: uint32(cachedInputTokens)}
	if err := usage.Validate(); err != nil {
		return RouteTokenUsage{}, err
	}
	return usage, nil
}

// NewUnknownRouteTokenUsage creates an explicit unknown usage report.
func NewUnknownRouteTokenUsage() RouteTokenUsage {
	return RouteTokenUsage{kind: routeTokenUsageUnknown}
}

// IsKnown reports whether provider token counts are available.
func (u RouteTokenUsage) IsKnown() bool { return u.kind == routeTokenUsageKnown }

// InputTokens returns billed input tokens, including cached input tokens, or zero when unknown.
func (u RouteTokenUsage) InputTokens() uint32 { return u.inputTokens }

// OutputTokens returns billed output tokens or zero when unknown.
func (u RouteTokenUsage) OutputTokens() uint32 { return u.outputTokens }

// CachedInputTokens returns the subset of input tokens reported as cached or zero when unknown.
func (u RouteTokenUsage) CachedInputTokens() uint32 { return u.cachedInputTokens }

// Validate verifies the explicit state, token bounds, and cached-input subset.
func (u RouteTokenUsage) Validate() error {
	switch u.kind {
	case routeTokenUsageUnknown:
		if u.inputTokens != 0 || u.outputTokens != 0 || u.cachedInputTokens != 0 {
			return ErrInvalidRouteTokenUsage
		}
		return nil
	case routeTokenUsageKnown:
		if u.inputTokens > maxModelCostTokens || u.outputTokens > maxModelCostTokens || u.cachedInputTokens > maxModelCostTokens {
			return ErrRouteUsageTokensTooLarge
		}
		if u.cachedInputTokens > u.inputTokens {
			return ErrInvalidRouteTokenUsage
		}
		return nil
	default:
		return ErrInvalidRouteTokenUsage
	}
}

type routeActualCostKind uint8

const (
	routeActualCostUnknown routeActualCostKind = iota + 1
	routeActualCostKnown
)

// RouteActualCost records fixed-price input, output, and total cost or an explicit unknown state.
type RouteActualCost struct {
	kind               routeActualCostKind
	inputCostMicroUSD  uint64
	outputCostMicroUSD uint64
	totalCostMicroUSD  uint64
}

// IsKnown reports whether actual cost could be derived from provider usage.
func (c RouteActualCost) IsKnown() bool { return c.kind == routeActualCostKnown }

// InputCostMicroUSD returns rounded-up actual input cost or zero when unknown.
func (c RouteActualCost) InputCostMicroUSD() uint64 { return c.inputCostMicroUSD }

// OutputCostMicroUSD returns rounded-up actual output cost or zero when unknown.
func (c RouteActualCost) OutputCostMicroUSD() uint64 { return c.outputCostMicroUSD }

// TotalCostMicroUSD returns actual total cost or zero when unknown.
func (c RouteActualCost) TotalCostMicroUSD() uint64 { return c.totalCostMicroUSD }

// Validate verifies the explicit state and component arithmetic.
func (c RouteActualCost) Validate() error {
	switch c.kind {
	case routeActualCostUnknown:
		if c.inputCostMicroUSD != 0 || c.outputCostMicroUSD != 0 || c.totalCostMicroUSD != 0 {
			return ErrInvalidRouteActualCost
		}
		return nil
	case routeActualCostKnown:
		if c.inputCostMicroUSD > maxModelCostMicroUSD || c.outputCostMicroUSD > maxModelCostMicroUSD || c.inputCostMicroUSD > maxModelCostMicroUSD-c.outputCostMicroUSD || c.totalCostMicroUSD != c.inputCostMicroUSD+c.outputCostMicroUSD {
			return ErrInvalidRouteActualCost
		}
		return nil
	default:
		return ErrInvalidRouteActualCost
	}
}

// CalculateActualRouteCost applies registry-bound fixed prices to provider-reported usage.
func CalculateActualRouteCost(pricing RoutePricing, usage RouteTokenUsage) (RouteActualCost, error) {
	if err := pricing.Validate(); err != nil {
		return RouteActualCost{}, err
	}
	if !pricing.IsKnown() {
		return RouteActualCost{}, ErrUnknownRoutePricing
	}
	if err := usage.Validate(); err != nil {
		return RouteActualCost{}, err
	}
	if !usage.IsKnown() {
		return RouteActualCost{kind: routeActualCostUnknown}, nil
	}
	inputCost := roundedUpTokenCost(usage.InputTokens(), pricing.InputMicroUSDPerMillionTokens())
	outputCost := roundedUpTokenCost(usage.OutputTokens(), pricing.OutputMicroUSDPerMillionTokens())
	cost := RouteActualCost{kind: routeActualCostKnown, inputCostMicroUSD: inputCost, outputCostMicroUSD: outputCost, totalCostMicroUSD: inputCost + outputCost}
	if err := cost.Validate(); err != nil {
		return RouteActualCost{}, err
	}
	return cost, nil
}
