package runtimecatalog

import (
	"context"
	"testing"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func TestChatCompletionsRuntimePolicyCatalogCompositionAndLocalPair(t *testing.T) {
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	responses := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", nil)
	chat := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) {
		for _, connection := range doc["connections"].([]map[string]string) {
			connection["implementation"] = "openai_chat_completions"
		}
	})
	pair, err := ResolveLocalGenerationRoutePair(chat, inventory)
	if err != nil || pair.Validate() != nil {
		t.Fatalf("chat local pair: %v", err)
	}
	calls := 0
	resolver, err := NewEnvironmentOpenAICredentialResolver(func(string) string { calls++; return "test-secret" })
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range []bool{false, true} {
		build := NewOpenAIRouteDispatcherCatalogFromRuntimePolicy
		if local {
			build = NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy
		}
		old, err := build(inventory, responses, resolver)
		if err != nil {
			t.Fatal(err)
		}
		catalog, err := build(inventory, chat, resolver)
		if err != nil || catalog.Validate() != nil || catalog.Identity() == old.Identity() {
			t.Fatalf("chat catalog: %v", err)
		}
		for _, connection := range chat.Connections() {
			credentials, err := resolver.ResolveOpenAICredentials(connection.CredentialEnvironment())
			if err != nil {
				t.Fatal(err)
			}
			var config openai.Config
			for _, candidate := range inventory.Candidates() {
				declaration := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
				route := declaration.RouteCapabilityDeclaration().RouteReference()
				if route.AdapterID() == connection.AdapterID() {
					config = openai.Config{Protocol: openai.ProtocolChatCompletions, AdapterID: route.AdapterID(), ProviderID: route.ProviderID(), ConnectionID: route.ConnectionID(), Zone: route.Zone(), ContentLoggingMode: declaration.ContentLoggingMode(), Endpoint: connection.Endpoint(), CredentialIdentity: connection.CredentialIdentity(), Credentials: credentials}
				}
			}
			if local {
				config.HTTPClient, config.HTTPClientIdentity = localInferenceHTTPClient()
			}
			expected, err := openai.New(config)
			if err != nil {
				t.Fatal(err)
			}
			actual, ok := catalog.Resolve(connection.AdapterID())
			if !ok || actual.ConfigurationIdentity() != expected.ConfigurationIdentity() {
				t.Fatal("runtime caller did not bind Chat Completions adapter")
			}
		}
	}
	if calls != 0 {
		t.Fatal("catalog composition retrieved credentials")
	}
}

func TestChatCompletionsCatalogRetainsZoneAndLoopbackRestrictions(t *testing.T) {
	resolver, err := NewEnvironmentOpenAICredentialResolver(func(string) string { t.Fatal("credentials retrieved during construction"); return "" })
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []provider.ProviderZone{provider.ProviderZonePrivateRemote, provider.ProviderZoneBrokeredRemote, provider.ProviderZoneSubscriptionOAuth} {
		definitions := localPairDefinitions(t)
		for i := range definitions {
			prior := definitions[i].Route
			definitions[i].Route, err = provider.NewRouteReference(zone, prior.ProviderID(), prior.AdapterID(), prior.ConnectionID(), prior.ModelID(), prior.ModelVersion())
			if err != nil {
				t.Fatal(err)
			}
		}
		inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
		if err != nil {
			t.Fatal(err)
		}
		policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) {
			doc["allowed_zones"] = []string{zone.String()}
			for _, connection := range doc["connections"].([]map[string]string) {
				connection["implementation"] = "openai_chat_completions"
				connection["endpoint"] = "https://api.example.test/v1"
			}
		}, zone != provider.ProviderZonePrivateRemote)
		if _, err := NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, resolver); err == nil {
			t.Fatalf("local accepted %s", zone.String())
		}
		_, err = NewOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, resolver)
		if zone == provider.ProviderZonePrivateRemote && err != nil {
			t.Fatal(err)
		}
		if zone != provider.ProviderZonePrivateRemote && err == nil {
			t.Fatalf("accepted %s", zone.String())
		}
	}
}
