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
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type OpenAIConnectionDefinition struct {
	RequestProfile      openai.RequestProfile
	OpenRouterAuthority *openai.OpenRouterRouteAuthority
	OpenCodeGoAuthority *openai.OpenCodeGoRouteAuthority
	Clock               artifact.Clock
	CredentialMode      openai.CredentialMode
	Protocol            openai.Protocol
	AdapterID           string
	Endpoint            string
	CredentialIdentity  string
	Credentials         openai.APIKeyProvider
	HTTPClient          *http.Client
	HTTPClientIdentity  string
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
		adapter, err := openai.New(openai.Config{RequestProfile: connection.RequestProfile, OpenRouterAuthority: connection.OpenRouterAuthority, OpenCodeGoAuthority: connection.OpenCodeGoAuthority, Clock: connection.Clock, CredentialMode: connection.CredentialMode, Protocol: connection.Protocol, AdapterID: connection.AdapterID, ProviderID: route.ProviderID(), ConnectionID: route.ConnectionID(), Zone: route.Zone(), ContentLoggingMode: candidate.ContentLoggingMode(), Endpoint: connection.Endpoint, Credentials: connection.Credentials, CredentialIdentity: connection.CredentialIdentity, HTTPClient: connection.HTTPClient, HTTPClientIdentity: connection.HTTPClientIdentity})
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

type OpenAICatalogOptions struct {
	Clock              artifact.Clock
	HTTPClient         *http.Client
	HTTPClientIdentity string
}

type catalogSystemClock struct{}

func (catalogSystemClock) Now() time.Time { return time.Now().UTC() }

func NewOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory runtimeconfig.RouteInventory, configuration runtimeconfig.RuntimePolicy, resolver OpenAICredentialResolver) (gateway.RouteDispatcherCatalog, error) {
	return NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, resolver, OpenAICatalogOptions{})
}

func NewOpenAIRouteDispatcherCatalogWithOptions(inventory runtimeconfig.RouteInventory, configuration runtimeconfig.RuntimePolicy, resolver OpenAICredentialResolver, options OpenAICatalogOptions) (gateway.RouteDispatcherCatalog, error) {
	if configuration.Validate() != nil || configuration.ValidateAgainstInventory(inventory) != nil || configuration.InventoryIdentity() != inventory.Identity() || resolver == nil {
		return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
	}
	if options.Clock == nil {
		options.Clock = catalogSystemClock{}
	}
	connections := configuration.Connections()
	// Refuse every stale declaration before resolving any credential provider.
	for _, connection := range connections {
		switch connection.RequestProfile() {
		case "":
		case runtimeconfig.OpenRouterZDRChatProfile:
			if !inventory.OpenRouterPrivacyCurrent(connection.BrokeredAuthority().RouteRecordIdentity(), options.Clock.Now()) {
				return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
			}
		case runtimeconfig.OpenCodeGoChatProfile:
			if !inventory.OpenCodeGoPrivacyCurrent(connection.OpenCodeGoAuthority().RouteRecordIdentity(), options.Clock.Now()) {
				return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
			}
		default:
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
	}
	definitions := make([]OpenAIConnectionDefinition, len(connections))
	for i, connection := range connections {
		if connection.Implementation() != string(openai.ProtocolResponses) && connection.Implementation() != string(openai.ProtocolChatCompletions) {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		var credentials openai.APIKeyProvider
		if connection.CredentialMode() == "bearer" {
			var err error
			credentials, err = resolver.ResolveOpenAICredentials(connection.CredentialEnvironment())
			if err != nil || credentials == nil {
				return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
			}
		}
		var profileAuthority *openai.OpenRouterRouteAuthority
		var goAuthority *openai.OpenCodeGoRouteAuthority
		var profileClock artifact.Clock
		if connection.RequestProfile() == runtimeconfig.OpenRouterZDRChatProfile {
			authority := connection.BrokeredAuthority()
			var route provider.RouteReference
			for _, candidate := range inventory.Candidates() {
				record := candidate.ResolvedRecord().RouteRegistryRecord()
				if record.Identity() == authority.RouteRecordIdentity() {
					route = record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
				}
			}
			profileAuthority = &openai.OpenRouterRouteAuthority{Route: route, RouteRecordIdentity: authority.RouteRecordIdentity(), EvidenceIdentity: authority.EvidenceManifestDigest(), AccountPolicyIdentity: authority.AccountPolicyIdentity(), CredentialIdentity: connection.CredentialIdentity(), TenantID: authority.TenantID(), RepositoryID: authority.RepositoryID(), ProviderSlug: authority.ProviderSlug(), ValidFrom: authority.ValidFrom(), ValidUntil: authority.ValidUntil()}
			profileClock = options.Clock
		}
		if connection.RequestProfile() == runtimeconfig.OpenCodeGoChatProfile {
			authority := connection.OpenCodeGoAuthority()
			var route provider.RouteReference
			for _, candidate := range inventory.Candidates() {
				record := candidate.ResolvedRecord().RouteRegistryRecord()
				if record.Identity() == authority.RouteRecordIdentity() {
					route = record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
				}
			}
			goAuthority = &openai.OpenCodeGoRouteAuthority{Route: route, RouteRecordIdentity: authority.RouteRecordIdentity(), EvidenceIdentity: authority.EvidenceManifestDigest(), AccountPolicyIdentity: authority.AccountPolicyIdentity(), CredentialIdentity: connection.CredentialIdentity(), TenantID: authority.TenantID(), RepositoryID: authority.RepositoryID(), ValidFrom: authority.ValidFrom(), ValidUntil: authority.ValidUntil()}
			profileClock = options.Clock
		}
		definitions[i] = OpenAIConnectionDefinition{RequestProfile: openai.RequestProfile(connection.RequestProfile()), OpenRouterAuthority: profileAuthority, OpenCodeGoAuthority: goAuthority, Clock: profileClock, HTTPClient: options.HTTPClient, HTTPClientIdentity: options.HTTPClientIdentity, CredentialMode: openai.CredentialMode(connection.CredentialMode()), Protocol: openai.Protocol(connection.Implementation()), AdapterID: connection.AdapterID(), Endpoint: connection.Endpoint(), CredentialIdentity: connection.CredentialIdentity(), Credentials: credentials}
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
		if err != nil || locality != provider.ServiceEndpointLoopback || (connection.Implementation() != string(openai.ProtocolResponses) && connection.Implementation() != string(openai.ProtocolChatCompletions)) {
			return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
		}
		var credentials openai.APIKeyProvider
		if connection.CredentialMode() == "bearer" {
			var err error
			credentials, err = resolver.ResolveOpenAICredentials(connection.CredentialEnvironment())
			if err != nil || credentials == nil {
				return gateway.RouteDispatcherCatalog{}, ErrInvalidRouteAuthority
			}
		}
		definitions[i] = OpenAIConnectionDefinition{CredentialMode: openai.CredentialMode(connection.CredentialMode()), Protocol: openai.Protocol(connection.Implementation()), AdapterID: connection.AdapterID(), Endpoint: connection.Endpoint(), CredentialIdentity: connection.CredentialIdentity(), Credentials: credentials, HTTPClient: client, HTTPClientIdentity: clientIdentity}
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
