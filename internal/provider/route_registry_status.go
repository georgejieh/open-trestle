package provider

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidRouteRegistryStatus identifies an unknown registry lifecycle state.
	ErrInvalidRouteRegistryStatus = errors.New("invalid route registry status")
)

// RouteRegistryStatus identifies a route record's declared registry lifecycle state.
type RouteRegistryStatus uint8

const (
	RouteRegistryPending RouteRegistryStatus = iota + 1
	RouteRegistryApproved
	RouteRegistryDegraded
	RouteRegistryDisabled
)

// String returns the stable status token or an empty string for unknown values.
func (s RouteRegistryStatus) String() string {
	switch s {
	case RouteRegistryPending:
		return "pending"
	case RouteRegistryApproved:
		return "approved"
	case RouteRegistryDegraded:
		return "degraded"
	case RouteRegistryDisabled:
		return "disabled"
	default:
		return ""
	}
}

// ParseRouteRegistryStatus parses one exact stable registry status token.
func ParseRouteRegistryStatus(value string) (RouteRegistryStatus, error) {
	switch value {
	case "pending":
		return RouteRegistryPending, nil
	case "approved":
		return RouteRegistryApproved, nil
	case "degraded":
		return RouteRegistryDegraded, nil
	case "disabled":
		return RouteRegistryDisabled, nil
	default:
		return 0, fmt.Errorf("parse route registry status: %w", ErrInvalidRouteRegistryStatus)
	}
}

// Validate verifies that the registry status is known.
func (s RouteRegistryStatus) Validate() error {
	if s.String() == "" {
		return fmt.Errorf("validate route registry status: %w", ErrInvalidRouteRegistryStatus)
	}
	return nil
}
