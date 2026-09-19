package runtimecatalog

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type catalogCredentialProvider struct{ key openai.APIKey }

func (p catalogCredentialProvider) Retrieve(context.Context) (openai.APIKey, error) {
	return p.key, nil
}
func openAIInventory(t *testing.T) runtimeconfig.RouteInventory {
	return openAIInventoryInZone(t, provider.ProviderZonePrivateRemote)
}
func openAIInventoryInZone(t *testing.T, zone provider.ProviderZone) runtimeconfig.RouteInventory {
	t.Helper()
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for index, model := range []string{"model-a", "model-b"} {
		route, err := provider.NewRouteReference(zone, "openai", "openai-responses", "primary/openai", model, "2026-01")
		if err != nil {
			t.Fatal(err)
		}
		capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
		if err != nil {
			t.Fatal(err)
		}
		pricing, err := provider.NewRoutePricing(1000, 2000)
		if err != nil {
			t.Fatal(err)
		}
		definitions[index] = runtimeconfig.RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"benchmark":"approved"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}
func TestOpenAIRouteDispatcherCatalogBindsExactConnection(t *testing.T) {
	key, err := openai.NewAPIKey([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	definition := OpenAIConnectionDefinition{AdapterID: "openai-responses", Endpoint: "https://api.openai.com/v1", CredentialIdentity: strings.Repeat("a", 64), Credentials: catalogCredentialProvider{key: key}}
	catalog, err := NewOpenAIRouteDispatcherCatalog(openAIInventory(t), []OpenAIConnectionDefinition{definition})
	if err != nil || catalog.Validate() != nil || catalog.Len() != 1 {
		t.Fatalf("catalog=(%#v,%v)", catalog, err)
	}
	if dispatcher, ok := catalog.Resolve("openai-responses"); !ok || dispatcher.ConfigurationIdentity() == "" {
		t.Fatal("configured dispatcher not resolved")
	}
	definition.AdapterID = "other"
	if catalog, err := NewOpenAIRouteDispatcherCatalog(openAIInventory(t), []OpenAIConnectionDefinition{definition}); err == nil || catalog.Identity() != "" {
		t.Fatal("unbound connection was accepted")
	}
}

func TestOpenAIRouteDispatcherCatalogEnforcesLocalEndpointAuthority(t *testing.T) {
	key, err := openai.NewAPIKey([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	definition := OpenAIConnectionDefinition{AdapterID: "openai-responses", Endpoint: "http://127.0.0.1:11434/v1", CredentialIdentity: strings.Repeat("a", 64), Credentials: catalogCredentialProvider{key: key}}
	catalog, err := NewOpenAIRouteDispatcherCatalog(openAIInventoryInZone(t, provider.ProviderZoneLocal), []OpenAIConnectionDefinition{definition})
	if err != nil || catalog.Validate() != nil || catalog.Len() != 1 {
		t.Fatalf("catalog=(%#v,%v)", catalog, err)
	}
	definition.Endpoint = "https://api.openai.com/v1"
	if catalog, err = NewOpenAIRouteDispatcherCatalog(openAIInventoryInZone(t, provider.ProviderZoneLocal), []OpenAIConnectionDefinition{definition}); err == nil || catalog.Identity() != "" {
		t.Fatal("remote endpoint accepted for local route")
	}
}

func TestEnvironmentOpenAIResolverDefersAndRedactsCredentialRead(t *testing.T) {
	calls := 0
	secret := "local-secret"
	resolver, err := NewEnvironmentOpenAICredentialResolver(func(name string) string {
		calls++
		if name != "OPEN_TRESTLE_PROVIDER_LOCAL_A" {
			t.Fatalf("name=%s", name)
		}
		return secret
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := resolver.ResolveOpenAICredentials("OPEN_TRESTLE_PROVIDER_LOCAL_A")
	if err != nil || calls != 0 {
		t.Fatalf("resolve=%v calls=%d", err, calls)
	}
	key, err := provider.Retrieve(context.Background())
	if err != nil || key.Validate() != nil || calls != 1 {
		t.Fatalf("retrieve=%v calls=%d", err, calls)
	}
	if strings.Contains(fmt.Sprintf("%#v", resolver), secret) || strings.Contains(fmt.Sprintf("%#v", provider), secret) {
		t.Fatal("secret escaped")
	}
	if _, err = resolver.ResolveOpenAICredentials("PATH"); err == nil {
		t.Fatal("invalid reference accepted")
	}
}
func TestEnvironmentOpenAIResolverFailsClosedAtRetrieval(t *testing.T) {
	resolver, _ := NewEnvironmentOpenAICredentialResolver(func(string) string { return "" })
	provider, _ := resolver.ResolveOpenAICredentials("OPEN_TRESTLE_PROVIDER_LOCAL_A")
	if _, err := provider.Retrieve(context.Background()); !errors.Is(err, openai.ErrCredentialsUnavailable) {
		t.Fatalf("empty=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Retrieve(ctx); !errors.Is(err, openai.ErrCredentialsUnavailable) {
		t.Fatalf("canceled=%v", err)
	}
}

func TestLocalInferenceDialAddressRejectsEveryNonLoopbackForm(t *testing.T) {
	for _, value := range []struct {
		network, address string
		want             bool
	}{{"tcp", "127.0.0.1:11434", true}, {"tcp6", "[::1]:11435", true}, {"udp", "127.0.0.1:1", false}, {"tcp", "localhost:1", false}, {"tcp", "127.1:1", false}, {"tcp", "0.0.0.0:1", false}, {"tcp", "[::]:1", false}, {"tcp", "192.0.2.1:1", false}, {"tcp", "127.0.0.1:01", false}} {
		if got := localInferenceDialAddress(value.network, value.address); got != value.want {
			t.Fatalf("%s %s=%v", value.network, value.address, got)
		}
	}
}

func TestLocalInferenceHTTPClientHasNoProxyOrConnectionReuse(t *testing.T) {
	client, identity := localInferenceHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableKeepAlives || transport.MaxConnsPerHost != 1 || transport.MaxResponseHeaderBytes != 64<<10 || client.Timeout != 90*time.Second || identity == "" {
		t.Fatalf("client=%#v identity=%q", client, identity)
	}
}
