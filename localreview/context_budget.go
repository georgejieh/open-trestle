package localreview

import (
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// routeContextBudget derives the packet budget from the smallest context
// window of the inventory's routes, since the generation and the verifier
// request both carry the sources, and from the output tokens the policy
// reserves for the answer. An inventory without routes gives the default.
func routeContextBudget(inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) review.ContextBudget {
	window := uint32(0)
	for _, candidate := range inventory.Candidates() {
		tokens := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().ModelCapabilities().MaxContextTokens()
		if tokens > 0 && (window == 0 || tokens < window) {
			window = tokens
		}
	}
	return review.RouteContextBudget(window, policy.Budget().MaxOutputTokens())
}
