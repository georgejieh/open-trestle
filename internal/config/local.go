package config

import (
	"fmt"

	"github.com/georgejieh/open-trestle/internal/policy"
)

// ProviderRoute identifies where review processing may occur.
type ProviderRoute string

const (
	// ProviderRouteLocal keeps review processing within the local runtime.
	ProviderRouteLocal ProviderRoute = "local"
)

// LocalConfig is the fail-closed configuration for local fixture review.
type LocalConfig struct {
	providerRoute ProviderRoute
}

// DefaultLocal returns a local-only configuration with effectful capabilities disabled.
func DefaultLocal() LocalConfig {
	return LocalConfig{providerRoute: ProviderRouteLocal}
}

// ProviderRoute returns the configured processing route.
func (c LocalConfig) ProviderRoute() ProviderRoute {
	return c.providerRoute
}

// Decide rejects every known effectful capability.
func (c LocalConfig) Decide(capability policy.Capability) (policy.PolicyDecision, error) {
	if c.providerRoute != ProviderRouteLocal {
		return policy.PolicyDecision{}, fmt.Errorf("invalid local provider route: %q", c.providerRoute)
	}
	return policy.NewDecision(capability, policy.DecisionDeny, "disabled by local-only configuration")
}
