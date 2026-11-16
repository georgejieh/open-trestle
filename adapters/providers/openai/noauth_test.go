package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestNoAuthAdapterLocalOnlyWithoutCredentialProviderOrHeader(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolResponses, ProtocolChatCompletions} {
		t.Run(string(protocol), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if _, present := r.Header["Authorization"]; present {
					t.Error("NO_AUTH emitted Authorization")
				}
				response := successfulResponse("model")
				if protocol == ProtocolChatCompletions {
					response = chatResponse("model")
				}
				_, _ = w.Write([]byte(response))
			}))
			defer server.Close()
			config := Config{Protocol: protocol, CredentialMode: CredentialModeNone, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: server.URL + "/v1"}
			a, err := New(config)
			if err != nil || a.Validate() != nil {
				t.Fatalf("NO_AUTH constructor: %v", err)
			}
			result := a.execute(context.Background(), testRoute(t, "model", ""), 100, testRequest(t))
			if result.Status() != gateway.RouteDispatchSucceeded || calls != 1 {
				t.Fatalf("NO_AUTH result=%#v calls=%d", result, calls)
			}
			credentials := &credentialProvider{key: testKey(t)}
			bearer := config
			bearer.CredentialMode = ""
			bearer.Credentials = credentials
			bearer.CredentialIdentity = strings.Repeat("a", 64)
			implicit, err := New(bearer)
			if err != nil {
				t.Fatal(err)
			}
			bearer.CredentialMode = CredentialModeBearer
			explicit, err := New(bearer)
			if err != nil || implicit.ConfigurationIdentity() != explicit.ConfigurationIdentity() || a.ConfigurationIdentity() == implicit.ConfigurationIdentity() || credentials.calls.Load() != 0 {
				t.Fatal("credential mode identity/default changed")
			}
		})
	}
}

func TestNoAuthAdapterRejectsRemoteAndConflictingAuthorityBeforeRetrieval(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	base := Config{CredentialMode: CredentialModeNone, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:1/v1"}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Credentials = credentials },
		func(c *Config) { c.CredentialIdentity = strings.Repeat("a", 64) },
		func(c *Config) { c.Endpoint = "http://localhost:1/v1" },
		func(c *Config) { c.Endpoint = "https://api.example.test/v1" },
		func(c *Config) {
			c.Zone = provider.ProviderZonePrivateRemote
			c.Endpoint = "https://api.example.test/v1"
		},
		func(c *Config) {
			c.Zone = provider.ProviderZoneBrokeredRemote
			c.Endpoint = "https://api.example.test/v1"
		},
		func(c *Config) {
			c.Zone = provider.ProviderZoneSubscriptionOAuth
			c.Endpoint = "https://api.example.test/v1"
		},
		func(c *Config) { c.CredentialMode = "no_auth" },
	} {
		config := base
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatal("NO_AUTH accepted conflicting or remote authority")
		}
	}
	if credentials.calls.Load() != 0 {
		t.Fatal("rejected config retrieved credentials")
	}
}
