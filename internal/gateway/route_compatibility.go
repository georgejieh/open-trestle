package gateway

import "github.com/georgejieh/open-trestle/internal/provider"

// CheckRouteCompatibility applies structural zone policy before model requirements.
// It does not establish registry approval, route health, budget, or dispatch authority.
func CheckRouteCompatibility(input ReviewRoutingInput, declaration provider.RouteCapabilityDeclaration) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := declaration.Validate(); err != nil {
		return err
	}
	if !input.ProviderDataConstraints().AllowedProviderZones().Allows(declaration.RouteReference().Zone()) {
		return ErrRouteZoneNotAllowed
	}
	return provider.CheckModelRequirements(declaration.ModelCapabilities(), input.ModelRequirements())
}
