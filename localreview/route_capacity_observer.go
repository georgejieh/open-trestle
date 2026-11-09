package localreview

import (
	"context"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// FailureDetailRouteContextInsufficient records that a request's reservation, a
// byte-based upper bound on its input tokens plus the output allowance,
// exceeded every candidate route's declared max_context_tokens.
const FailureDetailRouteContextInsufficient = "route_context_insufficient"

// contextShortfallWire is the JSON detail of FailureDetailRouteContextInsufficient.
type contextShortfallWire struct {
	RequiredTokens        uint64 `json:"required_tokens"`
	EstimatedInputTokens  uint32 `json:"estimated_input_tokens"`
	MaxOutputTokens       uint32 `json:"max_output_tokens"`
	DeclaredContextTokens uint32 `json:"declared_context_tokens"`
}

func contextShortfallHint(s contextShortfallWire) string {
	return fmt.Sprintf("the review needs up to %d tokens (a byte-based upper bound: %d input plus %d output) but the route declares max_context_tokens %d; raise max_context_tokens on the route and the model server's context length to at least %d (docs/named-local-runtimes.md#context-length)", s.RequiredTokens, s.EstimatedInputTokens, s.MaxOutputTokens, s.DeclaredContextTokens, s.RequiredTokens)
}

// refused records the context shortfall a planning refusal carries; it never
// changes the refusal.
func (o *routeFailureObserver) refused(err error) {
	shortfall, ok := gateway.RouteContextShortfallOf(err)
	if !ok {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.shortfall == nil {
		o.shortfall = &shortfall
	}
}

func (o *routeFailureObserver) contextShortfall() (gateway.RouteContextShortfall, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.shortfall == nil {
		return gateway.RouteContextShortfall{}, false
	}
	return *o.shortfall, true
}

// observedGenerationAuthorizer and observedVerificationAuthorizer report their
// authorizer's planning refusals to the observer. They keep its identity and
// its results unchanged.
type observedGenerationAuthorizer struct {
	contexthandler.GenerationAuthorizer
	observer *routeFailureObserver
}

func (a observedGenerationAuthorizer) Authorize(ctx context.Context, scope audit.ReviewScope, request provider.Request, policyIdentity string, at time.Time) (gateway.RouteAttemptAuthorization, error) {
	authorization, err := a.GenerationAuthorizer.Authorize(ctx, scope, request, policyIdentity, at)
	a.observer.refused(err)
	return authorization, err
}

type observedVerificationAuthorizer struct {
	modelhandler.VerificationAuthorizer
	observer *routeFailureObserver
}

func (a observedVerificationAuthorizer) Authorize(ctx context.Context, scope audit.ReviewScope, request provider.Request, generation gateway.RouteExecutionRecord) (modelhandler.VerificationAuthority, error) {
	authority, err := a.VerificationAuthorizer.Authorize(ctx, scope, request, generation)
	a.observer.refused(err)
	return authority, err
}
