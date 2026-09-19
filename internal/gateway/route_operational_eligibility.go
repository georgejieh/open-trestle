package gateway

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrRouteOperationalIdentityMismatch identifies readiness state for another registry record.
	ErrRouteOperationalIdentityMismatch = errors.New("route operational identity mismatch")
	// ErrRouteUnhealthy identifies a route with an explicit unhealthy observation.
	ErrRouteUnhealthy = errors.New("route is unhealthy")
	// ErrRouteHealthUnknown identifies a route without a current health determination.
	ErrRouteHealthUnknown = errors.New("route health is unknown")
	// ErrRouteQuotaExhausted identifies a route without current request quota.
	ErrRouteQuotaExhausted = errors.New("route quota is exhausted")
	// ErrRouteQuotaUnknown identifies a route without a current quota determination.
	ErrRouteQuotaUnknown = errors.New("route quota is unknown")
)

// CheckRouteOperationalEligibility requires explicit health and quota readiness for one resolved record.
func CheckRouteOperationalEligibility(resolved ResolvedRouteRegistryRecord, state provider.RouteOperationalState) error {
	if err := resolved.Validate(); err != nil {
		return err
	}
	if err := state.Validate(); err != nil {
		return err
	}
	if state.RecordIdentity() != resolved.RouteRegistryRecord().Identity() {
		return ErrRouteOperationalIdentityMismatch
	}
	switch state.Health() {
	case provider.RouteHealthHealthy:
	case provider.RouteHealthUnhealthy:
		return ErrRouteUnhealthy
	case provider.RouteHealthUnknown:
		return ErrRouteHealthUnknown
	}
	switch state.Quota() {
	case provider.RouteQuotaAvailable:
		return nil
	case provider.RouteQuotaExhausted:
		return ErrRouteQuotaExhausted
	case provider.RouteQuotaUnknown:
		return ErrRouteQuotaUnknown
	}
	return provider.ErrInvalidRouteQuota
}
