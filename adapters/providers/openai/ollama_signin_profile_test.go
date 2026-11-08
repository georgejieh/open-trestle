package openai

import (
	"context"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type ollamaSigninTestKey struct{}

func (ollamaSigninTestKey) Retrieve(context.Context) (APIKey, error) {
	return NewAPIKey([]byte("synthetic"))
}

func ollamaSigninConfig() Config {
	return Config{RequestProfile: RequestProfileOllamaSigninChatV1, CredentialMode: CredentialModeNone, Protocol: ProtocolChatCompletions, AdapterID: "ollama-signin-generation", ProviderID: "ollama-signin", ConnectionID: "ollama-signin/generation", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:11434/v1"}
}

// TestOllamaSigninProfileIsTheOnlyLoopbackRemoteAdapter proves the adapter
// pairs a loopback endpoint with a non-local zone only under the closed Ollama
// sign-in profile, and that the profile accepts nothing outside its shape.
func TestOllamaSigninProfileIsTheOnlyLoopbackRemoteAdapter(t *testing.T) {
	adapter, err := New(ollamaSigninConfig())
	if err != nil || adapter.Validate() != nil {
		t.Fatalf("closed Ollama sign-in adapter refused: %v", err)
	}
	cloud, _ := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "ollama-signin", "ollama-signin-generation", "ollama-signin/generation", "gpt-oss:120b-cloud", "")
	local, _ := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "ollama-signin", "ollama-signin-generation", "ollama-signin/generation", "gpt-oss:120b", "")
	if !adapter.serviceProfileMatches(cloud) || adapter.serviceProfileMatches(local) {
		t.Fatal("the profile did not bind dispatch to Ollama cloud model selectors")
	}
	for name, mutate := range map[string]func(*Config){
		"no profile":      func(c *Config) { c.RequestProfile = "" },
		"other profile":   func(c *Config) { c.RequestProfile = RequestProfileOpenCodeGoChatV1 },
		"local zone":      func(c *Config) { c.Zone = provider.ProviderZoneLocal },
		"brokered zone":   func(c *Config) { c.Zone = provider.ProviderZoneBrokeredRemote },
		"remote endpoint": func(c *Config) { c.Endpoint = "https://ollama.com/v1" },
		"ipv6 loopback":   func(c *Config) { c.Endpoint = "http://[::1]:11434/v1" },
		"other path":      func(c *Config) { c.Endpoint = "http://127.0.0.1:11434/api" },
		"bearer credential": func(c *Config) {
			c.CredentialMode, c.Credentials, c.CredentialIdentity = CredentialModeBearer, ollamaSigninTestKey{}, "1111111111111111111111111111111111111111111111111111111111111111"
		},
		"responses protocol": func(c *Config) { c.Protocol = ProtocolResponses },
		"other provider":     func(c *Config) { c.ProviderID = "ollama-cloud" },
		"logging enabled":    func(c *Config) { c.ContentLoggingMode = provider.ContentLoggingEnabled },
		"structured output":  func(c *Config) { c.LocalStructuredOutput = true },
	} {
		t.Run(name, func(t *testing.T) {
			config := ollamaSigninConfig()
			mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatal("adapter outside the closed Ollama sign-in shape was constructed")
			}
		})
	}
	// Without the profile, a loopback private_remote adapter is refused in every credential mode.
	for _, mode := range []CredentialMode{CredentialModeNone, CredentialModeBearer} {
		config := ollamaSigninConfig()
		config.RequestProfile, config.CredentialMode = "", mode
		if mode == CredentialModeBearer {
			config.Credentials, config.CredentialIdentity = ollamaSigninTestKey{}, "1111111111111111111111111111111111111111111111111111111111111111"
		}
		if _, err := New(config); err == nil {
			t.Fatalf("loopback private_remote adapter without the profile was constructed (%s)", mode)
		}
	}
}
