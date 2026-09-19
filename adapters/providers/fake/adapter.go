// Package fake provides deterministic provider fixtures for conformance tests and local dry runs.
package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxFixtures = 256

var (
	// ErrInvalidFixture identifies a malformed request-to-result fixture.
	ErrInvalidFixture = errors.New("invalid fake provider fixture")
	// ErrInvalidFixtureSet identifies an empty or excessive fixture collection.
	ErrInvalidFixtureSet = errors.New("invalid fake provider fixture set")
	// ErrDuplicateFixtureRequest identifies competing results for one request identity.
	ErrDuplicateFixtureRequest = errors.New("duplicate fake provider request fixture")
)

// Fixture binds one exact request identity to one unbound adapter result.
type Fixture struct {
	identity        string
	requestIdentity string
	result          gateway.RouteDispatchResult
}

// NewFixture creates one immutable request-to-result mapping without retaining request content.
func NewFixture(request provider.Request, result gateway.RouteDispatchResult) (Fixture, error) {
	if err := request.Validate(); err != nil {
		return Fixture{}, err
	}
	if err := result.Validate(); err != nil {
		return Fixture{}, err
	}
	if result.AuthorizationIdentity() != "" {
		return Fixture{}, ErrInvalidFixture
	}
	fixture := Fixture{requestIdentity: request.Identity(), result: result}
	fixture.identity = deriveFixtureIdentity(fixture)
	return fixture, nil
}

func (f Fixture) Identity() string                    { return f.identity }
func (f Fixture) RequestIdentity() string             { return f.requestIdentity }
func (f Fixture) Result() gateway.RouteDispatchResult { return f.result }
func (f Fixture) Validate() error {
	if len(f.requestIdentity) != sha256.Size*2 || f.requestIdentity != strings.ToLower(f.requestIdentity) || f.result.AuthorizationIdentity() != "" {
		return ErrInvalidFixture
	}
	if _, err := hex.DecodeString(f.requestIdentity); err != nil {
		return ErrInvalidFixture
	}
	if err := f.result.Validate(); err != nil {
		return err
	}
	if f.identity != deriveFixtureIdentity(f) {
		return ErrInvalidFixture
	}
	return nil
}

func deriveFixtureIdentity(fixture Fixture) string {
	preimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Request  string `json:"request"`
		Result   string `json:"result"`
	}{
		Contract: "open-trestle/fake-provider-fixture", Version: 1,
		Request: fixture.requestIdentity, Result: fixture.result.Identity(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// Adapter deterministically returns configured results for exact request identities.
type Adapter struct {
	adapterID string
	fixtures  map[string]Fixture
}

// NewAdapter validates and copies one bounded deterministic fixture set.
func NewAdapter(adapterID string, fixtures []Fixture) (*Adapter, error) {
	if err := provider.ValidateAdapterID(adapterID); err != nil {
		return nil, err
	}
	if len(fixtures) == 0 || len(fixtures) > maxFixtures {
		return nil, ErrInvalidFixtureSet
	}
	adapter := &Adapter{adapterID: adapterID, fixtures: make(map[string]Fixture, len(fixtures))}
	for _, fixture := range fixtures {
		if err := fixture.Validate(); err != nil {
			return nil, err
		}
		if _, exists := adapter.fixtures[fixture.RequestIdentity()]; exists {
			return nil, ErrDuplicateFixtureRequest
		}
		adapter.fixtures[fixture.RequestIdentity()] = fixture
	}
	return adapter, nil
}

func (a *Adapter) AdapterID() string {
	if a == nil {
		return ""
	}
	return a.adapterID
}

func (a *Adapter) ConfigurationIdentity() string {
	if a == nil {
		return ""
	}
	identities := make([]string, 0, len(a.fixtures))
	for _, fixture := range a.fixtures {
		identities = append(identities, fixture.Identity())
	}
	sort.Strings(identities)
	encoded, _ := json.Marshal(struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Adapter  string   `json:"adapter"`
		Fixtures []string `json:"fixtures"`
	}{"open-trestle/fake-provider-adapter", 1, a.adapterID, identities})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (a *Adapter) FixtureCount() int {
	if a == nil {
		return 0
	}
	return len(a.fixtures)
}

func (a *Adapter) Validate() error {
	if a == nil {
		return ErrInvalidFixtureSet
	}
	if err := provider.ValidateAdapterID(a.adapterID); err != nil {
		return err
	}
	if len(a.fixtures) == 0 || len(a.fixtures) > maxFixtures {
		return ErrInvalidFixtureSet
	}
	for requestIdentity, fixture := range a.fixtures {
		if err := fixture.Validate(); err != nil {
			return err
		}
		if requestIdentity != fixture.RequestIdentity() {
			return ErrInvalidFixture
		}
	}
	return nil
}

// DispatchRoute returns a configured result, or a closed non-retryable failure.
func (a *Adapter) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	if isNilContext(ctx) {
		return closedFailure(gateway.RouteFailureInvalidResponse)
	}
	if ctx.Err() != nil {
		return closedFailure(gateway.RouteFailureCancelled)
	}
	if a == nil || request.Validate() != nil || request.Authorization().RouteReference().AdapterID() != a.adapterID {
		return closedFailure(gateway.RouteFailureInvalidResponse)
	}
	fixture, exists := a.fixtures[request.Request().Identity()]
	if !exists {
		return closedFailure(gateway.RouteFailureInvalidResponse)
	}
	return fixture.Result()
}

func isNilContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	value := reflect.ValueOf(ctx)
	return value.Kind() == reflect.Pointer && value.IsNil()
}

func closedFailure(failure gateway.RouteFailureClass) gateway.RouteDispatchResult {
	result, _ := gateway.NewFailedRouteDispatchResult(failure, gateway.RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
	return result
}

func (a *Adapter) String() string   { return "fake provider adapter" }
func (a *Adapter) GoString() string { return "fake.Adapter{<redacted>}" }
func (a *Adapter) Format(state fmt.State, verb rune) {
	formatted := "fake provider adapter"
	if verb == 'q' {
		formatted = `"fake provider adapter"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "fake.Adapter{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
