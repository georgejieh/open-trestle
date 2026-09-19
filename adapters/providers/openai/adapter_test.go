package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type credentialProvider struct {
	key   APIKey
	err   error
	calls atomic.Int32
}

func (p *credentialProvider) Retrieve(context.Context) (APIKey, error) {
	p.calls.Add(1)
	return p.key, p.err
}

func testKey(t *testing.T) APIKey {
	t.Helper()
	key, err := NewAPIKey([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testRoute(t *testing.T, model, version string) provider.RouteReference {
	t.Helper()
	route, err := provider.NewRouteReference(
		provider.ProviderZoneLocal,
		"openai",
		"openai-responses",
		"primary/openai",
		model,
		version,
	)
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func testRequest(t *testing.T) provider.Request {
	t.Helper()
	request, err := provider.NewRequest(
		provider.CapabilityReviewV1,
		"application/json",
		[]byte(`{"contract":"review.v1","diff":"safe input"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func newTestAdapter(t *testing.T, endpoint string, credentials APIKeyProvider) *Adapter {
	t.Helper()
	zone := provider.ProviderZonePrivateRemote
	if locality, err := provider.ClassifyServiceEndpoint(endpoint); err == nil && locality == provider.ServiceEndpointLoopback {
		zone = provider.ProviderZoneLocal
	}
	adapter, err := New(Config{
		AdapterID:          "openai-responses",
		ProviderID:         "openai",
		ConnectionID:       "primary/openai",
		Zone:               zone,
		ContentLoggingMode: provider.ContentLoggingDisabled,
		Endpoint:           endpoint,
		Credentials:        credentials,
		CredentialIdentity: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func successfulResponse(model string) string {
	value := map[string]any{
		"id":     "resp_test",
		"object": "response",
		"status": "completed",
		"model":  model,
		"output": []any{map[string]any{
			"type": "reasoning", "id": "rs_test", "summary": []any{},
		}, map[string]any{
			"type": "message", "id": "msg_test", "status": "completed", "role": "assistant",
			"content": []any{map[string]any{
				"type": "output_text", "text": `{"summary":"ok","findings":[]}`, "annotations": []any{},
			}},
		}},
		"usage": map[string]any{
			"input_tokens": 120, "output_tokens": 30, "total_tokens": 150,
			"input_tokens_details": map[string]any{"cached_tokens": 20},
		},
	}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestExecuteSendsBoundedResponsesRequestAndNormalizesOutput(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/responses" || request.URL.RawQuery != "" {
			t.Errorf("request target = %s %s", request.Method, request.URL.String())
		}
		if request.Header.Get("Authorization") != "Bearer test-secret" || request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request headers were not bound")
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(successfulResponse("gpt-5.1-2025-11-13")))
	}))
	defer server.Close()

	credentials := &credentialProvider{key: testKey(t)}
	adapter := newTestAdapter(t, server.URL+"/v1", credentials)
	result := adapter.execute(context.Background(), testRoute(t, "gpt-5.1", "gpt-5.1-2025-11-13"), 4096, testRequest(t))
	if result.Status() != gateway.RouteDispatchSucceeded || result.Validate() != nil {
		t.Fatalf("execute result = %#v", result)
	}
	response := result.Response()
	parts := response.Parts()
	if response.FinishReason() != provider.ResponseFinishStop || len(parts) != 1 || parts[0].Kind() != provider.ResponsePartStructuredData || string(parts[0].Payload()) != `{"summary":"ok","findings":[]}` {
		t.Fatalf("normalized response = %#v", response)
	}
	usage := response.Usage()
	if !usage.IsKnown() || usage.InputTokens() != 120 || usage.OutputTokens() != 30 || usage.CachedInputTokens() != 20 {
		t.Fatalf("usage = %#v", usage)
	}
	if credentials.calls.Load() != 1 || received["model"] != "gpt-5.1-2025-11-13" || received["max_output_tokens"] != float64(4096) || received["store"] != false {
		t.Fatalf("request body = %#v, credential calls = %d", received, credentials.calls.Load())
	}
	input, ok := received["input"].([]any)
	if !ok || len(input) != 1 || !strings.Contains(fmt.Sprint(input[0]), "safe input") {
		t.Fatalf("input body = %#v", received["input"])
	}
}

func TestExecuteNormalizesIncompleteAndRefusalResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{
			"id":"resp_test","object":"response","status":"incomplete",
			"incomplete_details":{"reason":"content_filter"},
			"model":"gpt-safe","output":[{"type":"message","id":"msg_test","status":"incomplete","role":"assistant","content":[{"type":"refusal","refusal":"request blocked"}]}],
			"usage":{"input_tokens":10,"output_tokens":2,"total_tokens":12,"input_tokens_details":{"cached_tokens":0}}
		}`))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL, &credentialProvider{key: testKey(t)})
	result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Status() != gateway.RouteDispatchSucceeded || result.Response().FinishReason() != provider.ResponseFinishContentFilter {
		t.Fatalf("result = %#v", result)
	}
	parts := result.Response().Parts()
	if len(parts) != 1 || parts[0].Kind() != provider.ResponsePartRefusal || string(parts[0].Payload()) != "request blocked" {
		t.Fatalf("parts = %#v", parts)
	}
}

func TestExecuteClassifiesHTTPFailuresWithoutVendorText(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		retryAfter string
		failure    gateway.RouteFailureClass
		safety     gateway.RouteReplaySafety
		retry      uint32
	}{
		{"authentication", http.StatusUnauthorized, "", gateway.RouteFailureAuthentication, gateway.RouteReplayNoSideEffect, 0},
		{"authorization", http.StatusForbidden, "", gateway.RouteFailureAuthorization, gateway.RouteReplayNoSideEffect, 0},
		{"rate limit", http.StatusTooManyRequests, "2", gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 2000},
		{"timeout", http.StatusRequestTimeout, "", gateway.RouteFailureTimeout, gateway.RouteReplayOutcomeUnknown, 0},
		{"server", http.StatusBadGateway, "", gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0},
		{"budget", http.StatusRequestEntityTooLarge, "", gateway.RouteFailureBudgetExhausted, gateway.RouteReplayNoSideEffect, 0},
		{"invalid", http.StatusBadRequest, "", gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Retry-After", test.retryAfter)
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(`{"error":{"message":"must not escape"}}`))
			}))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL, &credentialProvider{key: testKey(t)})
			result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
			if result.Status() != gateway.RouteDispatchFailed || result.Failure() != test.failure || result.ReplaySafety() != test.safety || result.RetryAfterMilliseconds() != test.retry || result.Validate() != nil {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestExecuteFailsClosedBeforeCredentialOrNetwork(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	adapter := newTestAdapter(t, "https://api.openai.com/v1", credentials)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := adapter.execute(ctx, testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureCancelled || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 {
		t.Fatalf("canceled result = %#v, calls = %d", result, credentials.calls.Load())
	}
	badRoute := testRoute(t, "gpt-safe", "")
	otherAdapter, _ := New(Config{
		AdapterID: "different", ProviderID: "openai", ConnectionID: "primary/openai",
		Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://api.openai.com/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64),
	})
	result = otherAdapter.execute(context.Background(), badRoute, 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureInvalidResponse || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 {
		t.Fatalf("cross-wired result = %#v, calls = %d", result, credentials.calls.Load())
	}
}

func TestExecuteRejectsMalformedProviderResponses(t *testing.T) {
	responses := []string{
		strings.Replace(successfulResponse("gpt-safe"), `"model":"gpt-safe"`, `"model":"wrong"`, 1),
		strings.Replace(successfulResponse("gpt-safe"), `"model":"gpt-safe"`, `"Model":"gpt-safe"`, 1),
		`{"object":"response","status":"completed","model":"gpt-safe","output":[{"type":"unknown"}]}`,
		`{"object":"response","status":"completed","status":"incomplete","model":"gpt-safe","output":[]}`,
	}
	for index, body := range responses {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(body))
			}))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL, &credentialProvider{key: testKey(t)})
			result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
			if result.Status() != gateway.RouteDispatchFailed || result.Failure() != gateway.RouteFailureInvalidResponse || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown || result.Validate() != nil {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestExecuteRejectsRedirectAndOversizedResponse(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	adapter := newTestAdapter(t, redirect.URL, &credentialProvider{key: testKey(t)})
	result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureTransport || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown || redirected.Load() != 0 {
		t.Fatalf("redirect result = %#v, target calls = %d", result, redirected.Load())
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(maximumResponseBytes+1))
		_, _ = writer.Write(make([]byte, maximumResponseBytes+1))
	}))
	defer oversized.Close()
	adapter = newTestAdapter(t, oversized.URL, &credentialProvider{key: testKey(t)})
	result = adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureInvalidResponse || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown {
		t.Fatalf("oversized result = %#v", result)
	}
}

func TestConfigurationAndCredentialsFailClosed(t *testing.T) {
	validCredentials := &credentialProvider{key: testKey(t)}
	tests := []Config{
		{},
		{AdapterID: "Bad", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://api.openai.com/v1", Credentials: validCredentials},
		{AdapterID: "openai", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://example.com", Credentials: validCredentials},
		{AdapterID: "openai", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://user@example.com", Credentials: validCredentials},
		{AdapterID: "openai", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://example.com/v1?token=x", Credentials: validCredentials},
	}
	for index, config := range tests {
		if adapter, err := New(config); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
			t.Fatalf("config %d = (%#v, %v)", index, adapter, err)
		}
	}
	for _, raw := range [][]byte{nil, []byte(" key"), []byte("key\nvalue"), make([]byte, maximumAPIKeyBytes+1)} {
		if key, err := NewAPIKey(raw); !errors.Is(err, ErrInvalidAPIKey) || key.Validate() == nil {
			t.Fatalf("NewAPIKey(%d bytes) = (%#v, %v)", len(raw), key, err)
		}
	}
	key := testKey(t)
	if key.Validate() != nil || fmt.Sprint(key) != "OpenAI API key" || fmt.Sprintf("%#v", key) != "openai.APIKey{<redacted>}" {
		t.Fatalf("API key formatting or validation failed: %v / %#v", key, key)
	}

	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("network called when credentials failed")
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL, &credentialProvider{err: errors.New("secret backend unavailable")})
	result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureAuthentication || result.ReplaySafety() != gateway.RouteReplayNotDispatched {
		t.Fatalf("credential failure = %#v", result)
	}
}

func TestClientTimeoutIsBounded(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	if adapter, err := New(Config{
		AdapterID: "openai", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled,
		Endpoint: "https://api.openai.com/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), HTTPClient: &http.Client{Timeout: maximumRequestTimeout + time.Second},
	}); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
		t.Fatalf("unbounded timeout = (%#v, %v)", adapter, err)
	}
}

var _ gateway.RouteDispatcher = (*Adapter)(nil)

func TestAdapterConfigurationIdentityBindsEndpointAndCredentialAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	credentials := &credentialProvider{key: testKey(t)}
	first := newTestAdapter(t, server.URL+"/v1", credentials)
	second := newTestAdapter(t, server.URL+"/v2", credentials)
	if first.ConfigurationIdentity() == second.ConfigurationIdentity() || first.Validate() != nil || second.Validate() != nil {
		t.Fatal("endpoint was not bound to configuration identity")
	}
	third, err := New(Config{AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: server.URL + "/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfigurationIdentity() == third.ConfigurationIdentity() {
		t.Fatal("credential authority was not bound to configuration identity")
	}
	if adapter, err := New(Config{AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: server.URL + "/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("0", 64)}); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
		t.Fatalf("zero credential identity=(%#v,%v)", adapter, err)
	}
}

func TestAdapterRejectsRouteZonesThatCanMisrepresentRemoteDispatch(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	for _, zone := range []provider.ProviderZone{provider.ProviderZoneLocal, provider.ProviderZoneBrokeredRemote, provider.ProviderZoneSubscriptionOAuth} {
		t.Run(zone.String(), func(t *testing.T) {
			adapter, err := New(Config{AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: zone, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://api.openai.com/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)})
			if !errors.Is(err, ErrInvalidConfig) || adapter != nil {
				t.Fatalf("adapter=(%#v,%v)", adapter, err)
			}
		})
	}
}

func TestAdapterConfigurationIdentityBindsHTTPClientAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	credentials := &credentialProvider{key: testKey(t)}
	newAdapter := func(timeout time.Duration, identity string) *Adapter {
		adapter, err := New(Config{AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: server.URL, Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), HTTPClient: &http.Client{Timeout: timeout}, HTTPClientIdentity: identity})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}
	first := newAdapter(time.Second, strings.Repeat("b", 64))
	second := newAdapter(2*time.Second, strings.Repeat("b", 64))
	third := newAdapter(time.Second, strings.Repeat("c", 64))
	if first.ConfigurationIdentity() == second.ConfigurationIdentity() || first.ConfigurationIdentity() == third.ConfigurationIdentity() {
		t.Fatal("HTTP client timeout or authority was omitted from configuration identity")
	}
	if adapter, err := New(Config{AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: server.URL, Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64), HTTPClient: &http.Client{Timeout: time.Second}}); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
		t.Fatalf("unidentified custom client=(%#v,%v)", adapter, err)
	}
}

func TestAdapterEnforcesEndpointZoneLocality(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	valid := []Config{{AdapterID: "openai-responses", ProviderID: "local", ConnectionID: "local-a", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:11434/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)}, {AdapterID: "openai-responses", ProviderID: "remote", ConnectionID: "remote-a", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://api.example.test/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)}}
	for _, config := range valid {
		adapter, err := New(config)
		if err != nil || adapter.Validate() != nil {
			t.Fatalf("valid %s=(%#v,%v)", config.Zone.String(), adapter, err)
		}
	}
	invalid := []Config{valid[0], valid[1], valid[1]}
	invalid[0].Endpoint = "https://api.example.test/v1"
	invalid[1].Endpoint = "https://127.0.0.1/v1"
	invalid[2].Endpoint = "https://localhost/v1"
	for _, config := range invalid {
		if adapter, err := New(config); !errors.Is(err, ErrInvalidConfig) || adapter != nil {
			t.Fatalf("accepted %s %s", config.Zone.String(), config.Endpoint)
		}
	}
}

func TestExecuteUsesModelIDWhenVersionIsUnpinned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body requestWire
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Model != "gpt-current" {
			t.Errorf("model=%q", body.Model)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(successfulResponse(body.Model)))
	}))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL, &credentialProvider{key: testKey(t)})
	result := adapter.execute(context.Background(), testRoute(t, "gpt-current", ""), 4096, testRequest(t))
	if result.Status() != gateway.RouteDispatchSucceeded || result.Validate() != nil {
		t.Fatalf("unpinned dispatch=%#v", result)
	}
}
