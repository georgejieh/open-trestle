package localreview

import (
	"context"
	"sync"

	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
)

// routeFailureObserver records the adapter-classified failure class of each
// failed model dispatch of the session's current run. It observes only the
// gateway result the adapter already returned; it never changes the result,
// request, or routing, and it records no content.
type routeFailureObserver struct {
	mu       sync.Mutex
	failures map[gateway.RouteFailureClass]bool
}

func (o *routeFailureObserver) record(result gateway.RouteDispatchResult) {
	if result.Status() != gateway.RouteDispatchFailed {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failures == nil {
		o.failures = map[gateway.RouteFailureClass]bool{}
	}
	o.failures[result.Failure()] = true
}

func (o *routeFailureObserver) reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.failures = nil
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
	d.observer.record(result)
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
	d.observer.record(result)
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
