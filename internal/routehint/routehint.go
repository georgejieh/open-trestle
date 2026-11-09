// Package routehint holds the fixed host words that explain a recorded route
// refusal. Every surface that shows one uses this text, so the local review,
// the daemon's CLI, TUI and ACP results, and the web console stay identical.
package routehint

import "fmt"

const (
	// RouteContextInsufficient explains the route_context_insufficient reason.
	RouteContextInsufficient = "the review request needs more context than the route declares"
	// NoEligibleRoute explains the no_eligible_route reason.
	NoEligibleRoute = "no configured route met the runtime policy for this request"
)

// ContextShortfall is the hint for a route_context_insufficient refusal: the
// byte-based reservation, its input and output parts, the route's declared
// context, and the context length to raise. The web console renders the same
// text from the same counts.
func ContextShortfall(required uint64, input, output, declared uint32) string {
	return fmt.Sprintf("the review needs up to %d tokens (a byte-based upper bound: %d input plus %d output) but the route declares max_context_tokens %d; raise max_context_tokens on the route and the model server's context length to at least %d (docs/named-local-runtimes.md#context-length)", required, input, output, declared, required)
}
