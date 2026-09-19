package provider

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidRouteQualityTier identifies an unknown evaluated quality tier.
	ErrInvalidRouteQualityTier = errors.New("invalid route quality tier")
)

// RouteQualityTier is a closed, evidence-backed relative quality band. Higher tiers rank first.
type RouteQualityTier uint8

const (
	RouteQualityTier1 RouteQualityTier = iota + 1
	RouteQualityTier2
	RouteQualityTier3
	RouteQualityTier4
)

// String returns the stable quality token or an empty string for unknown values.
func (t RouteQualityTier) String() string {
	switch t {
	case RouteQualityTier1:
		return "tier_1"
	case RouteQualityTier2:
		return "tier_2"
	case RouteQualityTier3:
		return "tier_3"
	case RouteQualityTier4:
		return "tier_4"
	default:
		return ""
	}
}

// ParseRouteQualityTier parses one exact stable quality token.
func ParseRouteQualityTier(value string) (RouteQualityTier, error) {
	switch value {
	case "tier_1":
		return RouteQualityTier1, nil
	case "tier_2":
		return RouteQualityTier2, nil
	case "tier_3":
		return RouteQualityTier3, nil
	case "tier_4":
		return RouteQualityTier4, nil
	default:
		return 0, fmt.Errorf("parse route quality tier: %w", ErrInvalidRouteQualityTier)
	}
}

// Validate verifies that the quality tier is recognized.
func (t RouteQualityTier) Validate() error {
	if t.String() == "" {
		return ErrInvalidRouteQualityTier
	}
	return nil
}
