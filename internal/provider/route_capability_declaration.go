package provider

import "fmt"

// RouteCapabilityDeclaration structurally binds an unresolved route to declared model capabilities.
// It does not prove registry membership or observed capability support.
type RouteCapabilityDeclaration struct {
	routeReference    RouteReference
	modelCapabilities ModelCapabilities
}

// NewRouteCapabilityDeclaration creates an immutable structural declaration.
func NewRouteCapabilityDeclaration(routeReference RouteReference, modelCapabilities ModelCapabilities) (RouteCapabilityDeclaration, error) {
	declaration := RouteCapabilityDeclaration{
		routeReference:    routeReference,
		modelCapabilities: modelCapabilities,
	}
	if err := declaration.Validate(); err != nil {
		return RouteCapabilityDeclaration{}, err
	}
	return declaration, nil
}

// RouteReference returns the unresolved route reference.
func (d RouteCapabilityDeclaration) RouteReference() RouteReference { return d.routeReference }

// ModelCapabilities returns the declared model capabilities.
func (d RouteCapabilityDeclaration) ModelCapabilities() ModelCapabilities { return d.modelCapabilities }

// String returns a redacted declaration description.
func (d RouteCapabilityDeclaration) String() string { return "route capability declaration" }

// GoString returns a redacted Go-syntax declaration description.
func (d RouteCapabilityDeclaration) GoString() string {
	return "provider.RouteCapabilityDeclaration{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (d RouteCapabilityDeclaration) Format(state fmt.State, verb rune) {
	formatted := "route capability declaration"
	if verb == 'q' {
		formatted = `"route capability declaration"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.RouteCapabilityDeclaration{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies the route and capability declarations in order.
func (d RouteCapabilityDeclaration) Validate() error {
	if err := d.routeReference.Validate(); err != nil {
		return fmt.Errorf("validate route capability reference: %w", err)
	}
	if err := d.modelCapabilities.Validate(); err != nil {
		return fmt.Errorf("validate route model capabilities: %w", err)
	}
	return nil
}
