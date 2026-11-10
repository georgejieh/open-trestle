package localreview

import (
	"context"
	"sync"

	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// maxObservedRouteUsages bounds the usage records of one run. A direct run
// claims two route attempts and an investigation run at most eight turns.
const maxObservedRouteUsages = 64

// routeFailureObserver records the adapter-classified failure class of each
// failed model dispatch of the session's current run, and the provider-reported
// token usage of every dispatch by its authorization identity. It observes only
// the gateway result the adapter already returned; it never changes the result,
// request, or routing, and it records no content.
type routeFailureObserver struct {
	mu       sync.Mutex
	failures map[gateway.RouteFailureClass]bool
	usages   map[string]provider.RouteTokenUsage
	// shortfall is the first planning refusal of the run that named a route
	// context shortfall.
	shortfall *gateway.RouteContextShortfall
}

// record keeps the usage of one adapter result for its authorization. A result
// the gateway would refuse, or a second result for one authorization, records
// unknown usage rather than a count nothing accepted.
func (o *routeFailureObserver) record(authorization string, capability provider.Capability, result gateway.RouteDispatchResult) {
	usage := provider.NewUnknownRouteTokenUsage()
	if result.Validate() == nil && result.AuthorizationIdentity() == "" && (result.Status() != gateway.RouteDispatchSucceeded || result.Response().Capability() == capability) {
		usage = result.Usage()
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if result.Status() == gateway.RouteDispatchFailed {
		if o.failures == nil {
			o.failures = map[gateway.RouteFailureClass]bool{}
		}
		o.failures[result.Failure()] = true
	}
	if o.usages == nil {
		o.usages = map[string]provider.RouteTokenUsage{}
	}
	if _, repeated := o.usages[authorization]; repeated {
		o.usages[authorization] = provider.NewUnknownRouteTokenUsage()
	} else if len(o.usages) < maxObservedRouteUsages {
		o.usages[authorization] = usage
	}
}

// dispatchedUsage returns the usage observed for an authorization and whether
// an adapter result was observed for it at all.
func (o *routeFailureObserver) dispatchedUsage(authorization string) (provider.RouteTokenUsage, bool) {
	if o == nil {
		return provider.NewUnknownRouteTokenUsage(), false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	usage, ok := o.usages[authorization]
	return usage, ok
}

func (o *routeFailureObserver) reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = nil
	o.usages = nil
	o.shortfall = nil
}

func (o *routeFailureObserver) saw(failure gateway.RouteFailureClass) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.failures[failure]
}

type observedRouteDispatcher struct {
	gateway.RouteDispatcher
	observer *routeFailureObserver
}

func (d observedRouteDispatcher) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	result := d.RouteDispatcher.DispatchRoute(ctx, request)
	d.observer.record(request.Authorization().Identity(), request.Request().Capability(), result)
	return result
}

// observedSanitizedRouteDispatcher keeps the proof-bearing dispatch method of a
// dispatcher that has one, so wrapping never removes a capability the model
// handlers require.
type observedSanitizedRouteDispatcher struct {
	observedRouteDispatcher
	sanitized modelhandler.SanitizedRouteDispatcher
}

func (d observedSanitizedRouteDispatcher) DispatchSanitizedRoute(ctx context.Context, request gateway.RouteDispatchRequest, proof modelhandler.SanitizedDispatchProof) gateway.RouteDispatchResult {
	result := d.sanitized.DispatchSanitizedRoute(ctx, request, proof)
	d.observer.record(request.Authorization().Identity(), request.Request().Capability(), result)
	return result
}

// observeRouteDispatchers wraps every dispatcher of catalog with observer. The
// wrapped catalog keeps each adapter ID and configuration identity, so its
// content-derived identity is unchanged.
func observeRouteDispatchers(catalog gateway.RouteDispatcherCatalog, observer *routeFailureObserver) (gateway.RouteDispatcherCatalog, error) {
	wrapped := make([]gateway.RouteDispatcher, 0, catalog.Len())
	for _, id := range catalog.AdapterIDs() {
		dispatcher, ok := catalog.Resolve(id)
		if !ok {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidSession
		}
		base := observedRouteDispatcher{RouteDispatcher: dispatcher, observer: observer}
		if sanitized, ok := dispatcher.(modelhandler.SanitizedRouteDispatcher); ok {
			wrapped = append(wrapped, observedSanitizedRouteDispatcher{observedRouteDispatcher: base, sanitized: sanitized})
			continue
		}
		wrapped = append(wrapped, base)
	}
	observedCatalog, err := gateway.NewRouteDispatcherCatalog(wrapped)
	if err != nil || observedCatalog.Identity() != catalog.Identity() {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidSession
	}
	return observedCatalog, nil
}
