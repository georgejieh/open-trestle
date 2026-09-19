package gateway

import "github.com/georgejieh/open-trestle/internal/provider"

// CheckRouteCandidateCompatibility applies request policy before model requirements.
// It does not establish registry approval, health, quota, budget, or dispatch authority.
func CheckRouteCandidateCompatibility(input ReviewRoutingInput, candidate provider.RouteCandidateDeclaration) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	capability := candidate.RouteCapabilityDeclaration()
	if err := ValidateRouteZoneAllowance(input, capability.RouteReference()); err != nil {
		return err
	}
	if err := CheckRouteContentLogging(input, candidate.ContentLoggingMode()); err != nil {
		return err
	}
	return provider.CheckModelRequirements(capability.ModelCapabilities(), input.ModelRequirements())
}
