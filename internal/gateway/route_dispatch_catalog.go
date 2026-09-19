package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxRouteDispatchers = 64

var (
	// ErrInvalidRouteDispatcherCatalog identifies an empty or excessive adapter catalog.
	ErrInvalidRouteDispatcherCatalog = errors.New("invalid route dispatcher catalog")
	// ErrDuplicateRouteDispatcher identifies more than one implementation for an adapter ID.
	ErrDuplicateRouteDispatcher = errors.New("duplicate route dispatcher")
	// ErrRouteDispatcherNotRegistered identifies an authorized adapter absent from the catalog.
	ErrRouteDispatcherNotRegistered = errors.New("route dispatcher not registered")
)

// RouteDispatcherCatalog is an immutable exact-ID map of approved adapter implementations.
type RouteDispatcherCatalog struct {
	identity    string
	dispatchers map[string]RouteDispatcher
}

// NewRouteDispatcherCatalog validates and copies a bounded implementation set.
func NewRouteDispatcherCatalog(dispatchers []RouteDispatcher) (RouteDispatcherCatalog, error) {
	if len(dispatchers) == 0 || len(dispatchers) > maxRouteDispatchers {
		return RouteDispatcherCatalog{}, ErrInvalidRouteDispatcherCatalog
	}
	catalog := RouteDispatcherCatalog{dispatchers: make(map[string]RouteDispatcher, len(dispatchers))}
	for _, dispatcher := range dispatchers {
		if isNilRouteDispatcher(dispatcher) {
			return RouteDispatcherCatalog{}, ErrInvalidRouteDispatcher
		}
		adapterID := dispatcher.AdapterID()
		if err := provider.ValidateAdapterID(adapterID); err != nil {
			return RouteDispatcherCatalog{}, err
		}
		if !validDispatcherConfigurationIdentity(dispatcher.ConfigurationIdentity()) {
			return RouteDispatcherCatalog{}, ErrInvalidRouteDispatcher
		}
		if _, exists := catalog.dispatchers[adapterID]; exists {
			return RouteDispatcherCatalog{}, ErrDuplicateRouteDispatcher
		}
		catalog.dispatchers[adapterID] = dispatcher
	}
	catalog.identity = deriveRouteDispatcherCatalogIdentity(catalog.dispatchers)
	return catalog, nil
}

// Identity returns the content-derived approved adapter-set identity.
func (c RouteDispatcherCatalog) Identity() string { return c.identity }

// AdapterIDs returns the exact adapter IDs in canonical order.
func (c RouteDispatcherCatalog) AdapterIDs() []string {
	values := make([]string, 0, len(c.dispatchers))
	for adapterID := range c.dispatchers {
		values = append(values, adapterID)
	}
	sort.Strings(values)
	return values
}

// Len returns the number of registered adapter implementations.
func (c RouteDispatcherCatalog) Len() int { return len(c.dispatchers) }

// Resolve returns the implementation registered for one exact adapter ID.
func (c RouteDispatcherCatalog) Resolve(adapterID string) (RouteDispatcher, bool) {
	if provider.ValidateAdapterID(adapterID) != nil {
		return nil, false
	}
	dispatcher, exists := c.dispatchers[adapterID]
	return dispatcher, exists && !isNilRouteDispatcher(dispatcher)
}

// Validate verifies catalog bounds, keys, implementation identity, and uniqueness.
func (c RouteDispatcherCatalog) Validate() error {
	if len(c.dispatchers) == 0 || len(c.dispatchers) > maxRouteDispatchers {
		return ErrInvalidRouteDispatcherCatalog
	}
	for adapterID, dispatcher := range c.dispatchers {
		if err := provider.ValidateAdapterID(adapterID); err != nil {
			return err
		}
		if isNilRouteDispatcher(dispatcher) || dispatcher.AdapterID() != adapterID || !validDispatcherConfigurationIdentity(dispatcher.ConfigurationIdentity()) {
			return ErrRouteDispatchAdapterMismatch
		}
	}
	if c.identity != deriveRouteDispatcherCatalogIdentity(c.dispatchers) {
		return ErrInvalidRouteDispatcherCatalog
	}
	return nil
}

func validDispatcherConfigurationIdentity(identity string) bool {
	if !validRequestIdentity(identity) {
		return false
	}
	decoded, err := hex.DecodeString(identity)
	if err != nil {
		return false
	}
	for _, value := range decoded {
		if value != 0 {
			return true
		}
	}
	return false
}

func deriveRouteDispatcherCatalogIdentity(dispatchers map[string]RouteDispatcher) string {
	type entry struct {
		AdapterID     string `json:"adapter_id"`
		Configuration string `json:"configuration"`
	}
	entries := make([]entry, 0, len(dispatchers))
	for adapterID, dispatcher := range dispatchers {
		entries = append(entries, entry{adapterID, dispatcher.ConfigurationIdentity()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].AdapterID < entries[j].AdapterID })
	encoded, err := json.Marshal(struct {
		Contract      string  `json:"contract"`
		SchemaVersion int     `json:"schema_version"`
		Adapters      []entry `json:"adapters"`
	}{"open-trestle/route-dispatcher-catalog", 2, entries})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (c RouteDispatcherCatalog) String() string { return "route dispatcher catalog" }
func (c RouteDispatcherCatalog) GoString() string {
	return "gateway.RouteDispatcherCatalog{<redacted>}"
}
func (c RouteDispatcherCatalog) Format(state fmt.State, verb rune) {
	formatted := "route dispatcher catalog"
	if verb == 'q' {
		formatted = `"route dispatcher catalog"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteDispatcherCatalog{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// DispatchAuthorizedRouteFromCatalog resolves only the adapter named by the authorization.
func DispatchAuthorizedRouteFromCatalog(ctx context.Context, catalog RouteDispatcherCatalog, authorization RouteAttemptAuthorization, request provider.Request) (RouteDispatchResult, error) {
	if err := catalog.Validate(); err != nil {
		return RouteDispatchResult{}, err
	}
	dispatcher, exists := catalog.Resolve(authorization.RouteReference().AdapterID())
	if !exists {
		return RouteDispatchResult{}, ErrRouteDispatcherNotRegistered
	}
	return DispatchAuthorizedRoute(ctx, dispatcher, authorization, request)
}
