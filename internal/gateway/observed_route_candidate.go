package gateway

import (
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// ObservedRouteCandidate binds a resolved registry record to its dynamic operational state.
type ObservedRouteCandidate struct {
	resolvedRecord   ResolvedRouteRegistryRecord
	operationalState provider.RouteOperationalState
}

// NewObservedRouteCandidate binds matching immutable and dynamic route inputs.
func NewObservedRouteCandidate(resolved ResolvedRouteRegistryRecord, state provider.RouteOperationalState) (ObservedRouteCandidate, error) {
	observed := ObservedRouteCandidate{resolvedRecord: resolved, operationalState: state}
	if err := observed.Validate(); err != nil {
		return ObservedRouteCandidate{}, err
	}
	return observed, nil
}

// ResolvedRecord returns the verified registry record.
func (c ObservedRouteCandidate) ResolvedRecord() ResolvedRouteRegistryRecord {
	return c.resolvedRecord
}

// OperationalState returns the bound health and quota observation.
func (c ObservedRouteCandidate) OperationalState() provider.RouteOperationalState {
	return c.operationalState
}

// String returns a redacted observed-route description.
func (c ObservedRouteCandidate) String() string { return "observed route candidate" }

// GoString returns a redacted Go-syntax observed-route description.
func (c ObservedRouteCandidate) GoString() string {
	return "gateway.ObservedRouteCandidate{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (c ObservedRouteCandidate) Format(state fmt.State, verb rune) {
	formatted := "observed route candidate"
	if verb == 'q' {
		formatted = `"observed route candidate"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.ObservedRouteCandidate{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies both values and their record identity binding.
func (c ObservedRouteCandidate) Validate() error {
	if err := c.resolvedRecord.Validate(); err != nil {
		return err
	}
	if err := c.operationalState.Validate(); err != nil {
		return err
	}
	if c.resolvedRecord.RouteRegistryRecord().Identity() != c.operationalState.RecordIdentity() {
		return ErrRouteOperationalIdentityMismatch
	}
	return nil
}
