package runtimecatalog

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type OpenAIConnectionDefinition struct {
	AdapterID          string
	Endpoint           string
	CredentialIdentity string
	Credentials        openai.APIKeyProvider
	HTTPClient         *http.Client
	HTTPClientIdentity string
}

func NewOpenAIRouteDispatcherCatalog(inventory runtimeconfig.RouteInventory, connections []OpenAIConnectionDefinition) (gateway.RouteDispatcherCatalog, error) {
	if inventory.Validate() != nil || len(connections) == 0 {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
	}
	namespaces := make(map[string]provider.RouteCandidateDeclaration)
	for _, observed := range inventory.Candidates() {
		candidate := observed.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
		route := candidate.RouteCapabilityDeclaration().RouteReference()
		existing, ok := namespaces[route.AdapterID()]
		if ok {
			prior := existing.RouteCapabilityDeclaration().RouteReference()
			if prior.ProviderID() != route.ProviderID() || prior.ConnectionID() != route.ConnectionID() || prior.Zone() != route.Zone() || existing.ContentLoggingMode() != candidate.ContentLoggingMode() {
				return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
			}
		} else {
			namespaces[route.AdapterID()] = candidate
		}
	}
	seen := make(map[string]struct{}, len(connections))
	dispatchers := make([]gateway.RouteDispatcher, 0, len(connections))
	for _, connection := range connections {
		candidate, ok := namespaces[connection.AdapterID]
		if !ok {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		if _, duplicate := seen[connection.AdapterID]; duplicate {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		seen[connection.AdapterID] = struct{}{}
		route := candidate.RouteCapabilityDeclaration().RouteReference()
		adapter, err := openai.New(openai.Config{AdapterID: connection.AdapterID, ProviderID: route.ProviderID(), ConnectionID: route.ConnectionID(), Zone: route.Zone(), ContentLoggingMode: candidate.ContentLoggingMode(), Endpoint: connection.Endpoint, Credentials: connection.Credentials, CredentialIdentity: connection.CredentialIdentity, HTTPClient: connection.HTTPClient, HTTPClientIdentity: connection.HTTPClientIdentity})
		if err != nil {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		dispatchers = append(dispatchers, adapter)
	}
	if len(seen) != len(namespaces) {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
	}
	catalog, err := gateway.NewRouteDispatcherCatalog(dispatchers)
	if err != nil {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
	}
	return catalog, nil
}

type OpenAICredentialResolver interface {
	ResolveOpenAICredentials(string) (openai.APIKeyProvider, error)
}

func NewOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory runtimeconfig.RouteInventory, configuration runtimeconfig.RuntimePolicy, resolver OpenAICredentialResolver) (gateway.RouteDispatcherCatalog, error) {
	if configuration.Validate() != nil || configuration.ValidateAgainstInventory(inventory) != nil || configuration.InventoryIdentity() != inventory.Identity() || resolver == nil {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
	}
	connections := configuration.Connections()
	definitions := make([]OpenAIConnectionDefinition, len(connections))
	for i, connection := range connections {
		if connection.Implementation() != "openai_responses" {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		credentials, err := resolver.ResolveOpenAICredentials(connection.CredentialEnvironment())
		if err != nil || credentials == nil {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		definitions[i] = OpenAIConnectionDefinition{AdapterID: connection.AdapterID(), Endpoint: connection.Endpoint(), CredentialIdentity: connection.CredentialIdentity(), Credentials: credentials}
	}
	return NewOpenAIRouteDispatcherCatalog(inventory, definitions)
}

// NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy builds adapters whose transport can dial only canonical numeric loopback addresses.
func NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory runtimeconfig.RouteInventory, configuration runtimeconfig.RuntimePolicy, resolver OpenAICredentialResolver) (gateway.RouteDispatcherCatalog, error) {
	if configuration.Validate() != nil || configuration.ValidateAgainstInventory(inventory) != nil || configuration.InventoryIdentity() != inventory.Identity() || resolver == nil {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
	}
	for _, candidate := range inventory.Candidates() {
		route := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if route.Zone() != provider.ProviderZoneLocal {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
	}
	client, clientIdentity := localInferenceHTTPClient()
	connections := configuration.Connections()
	definitions := make([]OpenAIConnectionDefinition, len(connections))
	for i, connection := range connections {
		locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint())
		if err != nil || locality != provider.ServiceEndpointLoopback || connection.Implementation() != "openai_responses" {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		credentials, err := resolver.ResolveOpenAICredentials(connection.CredentialEnvironment())
		if err != nil || credentials == nil {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		definitions[i] = OpenAIConnectionDefinition{AdapterID: connection.AdapterID(), Endpoint: connection.Endpoint(), CredentialIdentity: connection.CredentialIdentity(), Credentials: credentials, HTTPClient: client, HTTPClientIdentity: clientIdentity}
	}
	return NewOpenAIRouteDispatcherCatalog(inventory, definitions)
}
func localInferenceHTTPClient() (*http.Client, string) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if !localInferenceDialAddress(network, address) {
			return nil, ErrInvalidRouteAuthority
		}
		return dialer.DialContext(ctx, network, address)
	}, ForceAttemptHTTP2: false, DisableKeepAlives: true, MaxConnsPerHost: 1, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 85 * time.Second, ExpectContinueTimeout: time.Second, MaxResponseHeaderBytes: 64 << 10}
	sum := sha256.Sum256([]byte("open-trestle/setup-local-inference-http-client/v1;proxy=disabled;numeric-loopback-only;timeout=90s;keepalive=disabled;max-connections=1;tls-min=1.2;headers=65536"))
	return &http.Client{Transport: transport, Timeout: 90 * time.Second}, hex.EncodeToString(sum[:])
}
func localInferenceDialAddress(network, address string) bool {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() || ip.String() != host {
		return false
	}
	value, err := strconv.Atoi(port)
	return err == nil && value >= 1 && value <= 65535 && strconv.Itoa(value) == port && address == net.JoinHostPort(host, port)
}
