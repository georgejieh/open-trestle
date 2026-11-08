package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func ollamaSigninFixture(t *testing.T, zone provider.ProviderZone, providerID, model string) (RouteInventory, map[string]any) {
	t.Helper()
	definition := routeDefinition(t, "placeholder")
	route, err := provider.NewRouteReference(zone, providerID, "ollama-signin-generation", "ollama-signin/generation", model, "")
	if err != nil {
		t.Fatal(err)
	}
	definition.Route = route
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{definition})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(runtimePolicyDocument(t, inventory), &doc) != nil {
		t.Fatal("invalid fixture")
	}
	doc["schema_version"] = 7
	doc["verification_route_record_identity"] = inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	doc["allowed_zones"] = []string{zone.String()}
	doc["connections"] = []any{map[string]any{"implementation": "openai_chat_completions", "adapter_id": "ollama-signin-generation", "endpoint": "http://127.0.0.1:11434/v1", "credential_mode": "none", "request_profile": OllamaSigninChatProfile}}
	return inventory, doc
}

func decodeOllamaSigninDoc(inventory RouteInventory, doc map[string]any) (RuntimePolicy, error) {
	encoded, _ := json.Marshal(doc)
	return DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
}

func TestOllamaSigninProfileAdmitsOnlyItsClosedLoopbackRemoteShape(t *testing.T) {
	inventory, doc := ollamaSigninFixture(t, provider.ProviderZonePrivateRemote, OllamaSigninProviderID, "gpt-oss:120b-cloud")
	policy, err := decodeOllamaSigninDoc(inventory, doc)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatalf("closed Ollama sign-in policy refused: %v", err)
	}
	connection := policy.Connections()[0]
	if connection.RequestProfile() != OllamaSigninChatProfile || connection.CredentialMode() != "none" || connection.CredentialEnvironment() != "" || connection.CredentialIdentity() != "" {
		t.Fatalf("profile connection lost its anonymous loopback shape: %+v", connection)
	}
	// An explicit loopback port override is the same closed shape.
	doc["connections"].([]any)[0].(map[string]any)["endpoint"] = "http://127.0.0.1:21434/v1"
	if _, err := decodeOllamaSigninDoc(inventory, doc); err != nil {
		t.Fatalf("explicit loopback port refused: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"bearer credential": func(_, c map[string]any) {
			delete(c, "credential_mode")
			c["credential_environment"] = "OPEN_TRESTLE_PROVIDER_OLLAMA"
		},
		"implicit credential":    func(_, c map[string]any) { delete(c, "credential_mode") },
		"responses protocol":     func(_, c map[string]any) { c["implementation"] = "openai_responses" },
		"remote endpoint":        func(_, c map[string]any) { c["endpoint"] = "https://ollama.com/v1" },
		"ipv6 loopback":          func(_, c map[string]any) { c["endpoint"] = "http://[::1]:11434/v1" },
		"implicit port":          func(_, c map[string]any) { c["endpoint"] = "http://127.0.0.1/v1" },
		"other loopback address": func(_, c map[string]any) { c["endpoint"] = "http://127.0.0.2:11434/v1" },
		"other path":             func(_, c map[string]any) { c["endpoint"] = "http://127.0.0.1:11434/api" },
		"trailing slash":         func(_, c map[string]any) { c["endpoint"] = "http://127.0.0.1:11434/v1/" },
		"structured output":      func(_, c map[string]any) { c["local_structured_output"] = true },
		"alternate profile case": func(_, c map[string]any) {
			delete(c, "request_profile")
			c["Request_Profile"] = OllamaSigninChatProfile
		},
		"authority object":        func(_, c map[string]any) { c["opencode_go_authority"] = map[string]any{} },
		"version 6":               func(d, _ map[string]any) { d["schema_version"] = 6 },
		"version 5":               func(d, _ map[string]any) { d["schema_version"] = 5 },
		"version 2":               func(d, _ map[string]any) { d["schema_version"] = 2 },
		"profile-less connection": func(_, c map[string]any) { delete(c, "request_profile") },
	} {
		t.Run(name, func(t *testing.T) {
			inventory, doc := ollamaSigninFixture(t, provider.ProviderZonePrivateRemote, OllamaSigninProviderID, "gpt-oss:120b-cloud")
			mutate(doc, doc["connections"].([]any)[0].(map[string]any))
			if _, err := decodeOllamaSigninDoc(inventory, doc); err == nil {
				t.Fatal("policy outside the closed Ollama sign-in shape was admitted")
			}
		})
	}
	for _, test := range []struct {
		name, providerID, model string
		zone                    provider.ProviderZone
	}{
		{"local zone", OllamaSigninProviderID, "gpt-oss:120b-cloud", provider.ProviderZoneLocal},
		{"brokered zone", OllamaSigninProviderID, "gpt-oss:120b-cloud", provider.ProviderZoneBrokeredRemote},
		{"other provider", "ollama-cloud", "gpt-oss:120b-cloud", provider.ProviderZonePrivateRemote},
		{"non-cloud model", OllamaSigninProviderID, "gpt-oss:120b", provider.ProviderZonePrivateRemote},
		{"cloud word not tag", OllamaSigninProviderID, "cloud-model:7b", provider.ProviderZonePrivateRemote},
		{"suffix lookalike", OllamaSigninProviderID, "gpt-oss:cloudy", provider.ProviderZonePrivateRemote},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventory, doc := ollamaSigninFixture(t, test.zone, test.providerID, test.model)
			if _, err := decodeOllamaSigninDoc(inventory, doc); err == nil {
				t.Fatal("Ollama sign-in profile admitted a route outside its namespace")
			}
		})
	}
}

// TestLoopbackRemoteZoneRefusedForEveryOtherProfile proves the loopback
// exception belongs to the Ollama sign-in profile alone: the same loopback,
// remote-zone route is refused with no profile and with every other named
// profile, at every policy schema version, whether or not it sends a key.
func TestLoopbackRemoteZoneRefusedForEveryOtherProfile(t *testing.T) {
	for _, zone := range []provider.ProviderZone{provider.ProviderZonePrivateRemote, provider.ProviderZoneBrokeredRemote} {
		for _, profile := range []string{"", OpenRouterZDRChatProfile, OpenCodeGoChatProfile, OpenCodeConsoleChatProfile} {
			for version := 2; version <= 7; version++ {
				for _, mode := range []string{"none", "bearer"} {
					inventory, doc := ollamaSigninFixture(t, zone, OllamaSigninProviderID, "gpt-oss:120b-cloud")
					doc["schema_version"] = version
					c := doc["connections"].([]any)[0].(map[string]any)
					delete(c, "request_profile")
					if profile != "" {
						c["request_profile"] = profile
					}
					if mode == "bearer" {
						c["credential_mode"] = "bearer"
						c["credential_environment"] = "OPEN_TRESTLE_PROVIDER_LOOPBACK"
					}
					if _, err := decodeOllamaSigninDoc(inventory, doc); err == nil {
						t.Fatalf("zone %s profile %q version %d mode %s admitted a loopback endpoint", zone, profile, version, mode)
					}
				}
			}
		}
	}
}

func TestOllamaCloudModelIDAndEndpoint(t *testing.T) {
	for id, want := range map[string]bool{"gpt-oss:20b-cloud": true, "deepseek-v4-pro:cloud": true, "user/model:big-cloud": true, "gpt-oss:20b": false, "model-cloud": false, ":cloud": false, "a:cloudy": false, "a:-cloud": false, "a:x-cloud/b": false} {
		if OllamaCloudModelID(id) != want {
			t.Errorf("OllamaCloudModelID(%q) != %v", id, want)
		}
	}
	for endpoint, want := range map[string]bool{"http://127.0.0.1:11434/v1": true, "http://127.0.0.1:1/v1": true, "http://127.0.0.1/v1": false, "https://127.0.0.1:11434/v1": false, "http://127.0.0.1:011434/v1": false, "http://[::1]:11434/v1": false, "http://127.0.0.1:11434/v1/": false} {
		if ValidOllamaSigninEndpoint(endpoint) != want {
			t.Errorf("ValidOllamaSigninEndpoint(%q) != %v", endpoint, want)
		}
	}
}
