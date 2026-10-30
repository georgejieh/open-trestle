package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestExactModelSelectorPreservesHTTPAuthorityForBothProtocols(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolResponses, ProtocolChatCompletions} {
		for _, tc := range []struct{ model, version, selector string }{
			{"qwen2.5-coder:7b", "", "qwen2.5-coder:7b"},
			{"library/llama3.2:3b", "", "library/llama3.2:3b"},
			{"org/Model:exact-q4", "", "org/Model:exact-q4"},
			{"provider/model:free", "", "provider/model:free"},
			{"evil.example:443", "", "evil.example:443"},
			{"127.0.0.1:8080", "", "127.0.0.1:8080"},
			{"https:evil.example", "", "https:evil.example"},
			{"legacy-current", "", "legacy-current"},
			{"legacy-alias", "legacy-pinned", "legacy-pinned"},
		} {
			t.Run(string(protocol)+"/"+tc.model, func(t *testing.T) {
				calls := 0
				path := "/v1/responses"
				response := successfulResponse
				if protocol == ProtocolChatCompletions {
					path, response = "/v1/chat/completions", chatResponse
				}
				var endpoint string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != http.MethodPost || "http://"+r.Host+r.URL.RequestURI() != endpoint+path || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer test-secret" {
						t.Errorf("selector changed HTTP authority: %s %s host=%s", r.Method, r.URL, r.Host)
					}
					var wire struct{ Model string }
					if err := json.NewDecoder(r.Body).Decode(&wire); err != nil || wire.Model != tc.selector {
						t.Errorf("wire model=%q, want %q, decode=%v", wire.Model, tc.selector, err)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(response(tc.selector)))
				}))
				defer server.Close()
				endpoint = server.URL
				credentials := &credentialProvider{key: testKey(t)}
				a, err := New(Config{Protocol: protocol, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: endpoint + "/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)})
				if err != nil {
					t.Fatal(err)
				}
				identity := a.ConfigurationIdentity()
				result := a.execute(context.Background(), testRoute(t, tc.model, tc.version), 100, testRequest(t))
				if result.Status() != gateway.RouteDispatchSucceeded || result.Validate() != nil || credentials.calls.Load() != 1 || calls != 1 || a.ConfigurationIdentity() != identity || a.Validate() != nil {
					t.Fatalf("dispatch=%#v credential calls=%d HTTP calls=%d", result, credentials.calls.Load(), calls)
				}
			})
		}
	}
}

func TestExactTaggedModelSelectorRejectsDifferentHTTPResponseModel(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolResponses, ProtocolChatCompletions} {
		t.Run(string(protocol), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := successfulResponse("qwen2.5-coder:other")
				if protocol == ProtocolChatCompletions {
					body = chatResponse("qwen2.5-coder:other")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			credentials := &credentialProvider{key: testKey(t)}
			a, err := New(Config{Protocol: protocol, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: server.URL + "/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)})
			if err != nil {
				t.Fatal(err)
			}
			result := a.execute(context.Background(), testRoute(t, "qwen2.5-coder:7b", ""), 100, testRequest(t))
			if result.Failure() != gateway.RouteFailureInvalidResponse || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown || credentials.calls.Load() != 1 {
				t.Fatalf("mismatched response=%#v credential calls=%d", result, credentials.calls.Load())
			}
		})
	}
}
