package provider

import "fmt"

// RouteCandidateDeclaration binds structural model, content-logging, and pricing claims for one route.
// It does not prove registry membership, approval, observed behavior, or availability.
type RouteCandidateDeclaration struct {
	routeCapabilityDeclaration RouteCapabilityDeclaration
	contentLoggingMode         ContentLoggingMode
	routePricing               RoutePricing
	routeQualityTier           RouteQualityTier
}

// NewRouteCandidateDeclaration creates an immutable structural candidate declaration.
func NewRouteCandidateDeclaration(capability RouteCapabilityDeclaration, logging ContentLoggingMode, pricing RoutePricing, quality RouteQualityTier) (RouteCandidateDeclaration, error) {
	candidate := RouteCandidateDeclaration{
		routeCapabilityDeclaration: capability,
		contentLoggingMode:         logging,
		routePricing:               pricing,
		routeQualityTier:           quality,
	}
	if err := candidate.Validate(); err != nil {
		return RouteCandidateDeclaration{}, err
	}
	return candidate, nil
}

// RouteCapabilityDeclaration returns the route and model capability declaration.
func (d RouteCandidateDeclaration) RouteCapabilityDeclaration() RouteCapabilityDeclaration {
	return d.routeCapabilityDeclaration
}

// ContentLoggingMode returns the declared effective content-logging mode.
func (d RouteCandidateDeclaration) ContentLoggingMode() ContentLoggingMode {
	return d.contentLoggingMode
}

// RoutePricing returns the bound fixed-price declaration.
func (d RouteCandidateDeclaration) RoutePricing() RoutePricing { return d.routePricing }

// RouteQualityTier returns the bound evidence-backed quality band.
func (d RouteCandidateDeclaration) RouteQualityTier() RouteQualityTier { return d.routeQualityTier }

// String returns a redacted candidate description.
func (d RouteCandidateDeclaration) String() string { return "route candidate declaration" }

// GoString returns a redacted Go-syntax candidate description.
func (d RouteCandidateDeclaration) GoString() string {
	return "provider.RouteCandidateDeclaration{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (d RouteCandidateDeclaration) Format(state fmt.State, verb rune) {
	formatted := "route candidate declaration"
	if verb == 'q' {
		formatted = `"route candidate declaration"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.RouteCandidateDeclaration{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies capability and content-logging declarations in order.
func (d RouteCandidateDeclaration) Validate() error {
	if err := d.routeCapabilityDeclaration.Validate(); err != nil {
		return fmt.Errorf("validate route candidate capability: %w", err)
	}
	if err := d.contentLoggingMode.Validate(); err != nil {
		return fmt.Errorf("validate route candidate content logging: %w", err)
	}
	if err := d.routePricing.Validate(); err != nil {
		return fmt.Errorf("validate route candidate pricing: %w", err)
	}
	if err := d.routeQualityTier.Validate(); err != nil {
		return fmt.Errorf("validate route candidate quality: %w", err)
	}
	return nil
}
