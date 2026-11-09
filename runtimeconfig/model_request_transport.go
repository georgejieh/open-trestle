package runtimeconfig

import (
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

// ModelRequestTransport returns the request wire that an input estimate for one
// planning step over routes must count. A step plans one reservation for all
// of its candidate routes, so it uses the local structured-output transport
// when any route's connection enables it: that reservation is exact for those
// routes and covers a standard route in the same step. Otherwise it returns the
// standard transport.
func (p RuntimePolicy) ModelRequestTransport(routes []gateway.ObservedRouteCandidate) review.ModelRequestTransport {
	structured := map[string]bool{}
	for _, connection := range p.connections {
		if connection.localStructuredOutput {
			structured[connection.adapterID] = true
		}
	}
	for _, route := range routes {
		if structured[route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] {
			return review.ModelRequestTransportLocalStructuredOutput
		}
	}
	return review.ModelRequestTransportStandard
}
