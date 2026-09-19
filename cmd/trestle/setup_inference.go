package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type setupLocalInferenceFactory struct {
	environment func(string) string
	identity    string
}

func newSetupLocalInferenceFactory(environment func(string) string) (*setupLocalInferenceFactory, error) {
	if environment == nil {
		return nil, errors.New("invalid local inference factory")
	}
	sum := sha256.Sum256([]byte("open-trestle/setup-local-openai-dispatcher-factory/v1"))
	return &setupLocalInferenceFactory{environment, hex.EncodeToString(sum[:])}, nil
}
func (f *setupLocalInferenceFactory) FactoryIdentity() string {
	if f == nil {
		return ""
	}
	return f.identity
}
func (f *setupLocalInferenceFactory) Build(ctx context.Context, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) (gateway.RouteDispatcherCatalog, error) {
	if f == nil || f.environment == nil || ctx == nil || ctx.Err() != nil || inventory.Validate() != nil || policy.Validate() != nil || policy.ValidateAgainstInventory(inventory) != nil || policy.InventoryIdentity() != inventory.Identity() {
		return gateway.RouteDispatcherCatalog{}, errors.New("invalid local inference authority")
	}
	for _, candidate := range inventory.Candidates() {
		if candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().Zone() != provider.ProviderZoneLocal {
			return gateway.RouteDispatcherCatalog{}, errors.New("non-local inference authority")
		}
	}
	for _, connection := range policy.Connections() {
		locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint())
		if err != nil || locality != provider.ServiceEndpointLoopback {
			return gateway.RouteDispatcherCatalog{}, errors.New("non-local inference endpoint")
		}
	}
	resolver, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(f.environment)
	if err != nil {
		return gateway.RouteDispatcherCatalog{}, err
	}
	return runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, resolver)
}
func (f *setupLocalInferenceFactory) String() string {
	return "setup local inference dispatcher factory"
}
func (f *setupLocalInferenceFactory) GoString() string {
	return "main.setupLocalInferenceFactory{<redacted>}"
}
func (f *setupLocalInferenceFactory) Format(state fmt.State, verb rune) {
	value := f.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = f.GoString()
	}
	_, _ = state.Write([]byte(value))
}
