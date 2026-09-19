package gateway

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/provider"
)

var (
	// ErrRouteRegistryRecordNotApproved identifies a route record that cannot be considered for selection.
	ErrRouteRegistryRecordNotApproved = errors.New("route registry record is not approved")
)

// CheckRouteRegistryRecordCompatibility checks policy, approval state, and model requirements.
// The caller must obtain the record from an authoritative registry and resolve its evidence.
func CheckRouteRegistryRecordCompatibility(input ReviewRoutingInput, record provider.RouteRegistryRecord) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := record.Validate(); err != nil {
		return err
	}
	candidate := record.RouteCandidateDeclaration()
	capability := candidate.RouteCapabilityDeclaration()
	if err := ValidateRouteZoneAllowance(input, capability.RouteReference()); err != nil {
		return err
	}
	if err := CheckRouteContentLogging(input, candidate.ContentLoggingMode()); err != nil {
		return err
	}
	if record.Status() != provider.RouteRegistryApproved {
		return ErrRouteRegistryRecordNotApproved
	}
	return provider.CheckModelRequirements(capability.ModelCapabilities(), input.ModelRequirements())
}
