package gateway

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrRouteZoneNotAllowed identifies a route outside the provider data constraints.
	ErrRouteZoneNotAllowed = errors.New("route zone is not allowed by provider data constraints")
)

// ValidateRouteZoneAllowance verifies one route against the routing input's zone constraint.
func ValidateRouteZoneAllowance(input ReviewRoutingInput, route provider.RouteReference) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := route.Validate(); err != nil {
		return err
	}
	if !input.ProviderDataConstraints().AllowedProviderZones().Allows(route.Zone()) {
		return ErrRouteZoneNotAllowed
	}
	return nil
}
