package openai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

func chatResponse(model string) string {
	body, _ := json.Marshal(map[string]any{
		"id": "chatcmpl-test", "object": "chat.completion", "created": 1730000000, "model": model,
		"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": `{"summary":"ok","findings":[]}`, "refusal": nil}, "finish_reason": "stop", "logprobs": nil}},
		"usage":   map[string]any{"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150, "prompt_tokens_details": map[string]any{"cached_tokens": 20}, "completion_tokens_details": map[string]any{"reasoning_tokens": 10}},
	})
	return string(body)
}

func useChatProtocol(a *Adapter) {
	a.protocol = ProtocolChatCompletions
	a.configurationIdentity = deriveConfigurationIdentity(a)
}

func TestChatCompletionsSendsBoundedRequestThroughExistingExecution(t *testing.T) {
	var received map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Errorf("unbound request: %s %s", r.Method, r.URL)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(chatResponse("pinned-model")))
	}))
	defer server.Close()
	credentials := &credentialProvider{key: testKey(t)}
	a := newTestAdapter(t, server.URL+"/v1", credentials)
	useChatProtocol(a)
	request, inner := sanitizedRequestWithCanary(t, false, "sk-proj-chat-canary-aaaaaaaaaaaaaaaa")
	result := a.execute(context.Background(), testRoute(t, "alias", "pinned-model"), 100, request)
	if result.Status() != gateway.RouteDispatchSucceeded || result.Validate() != nil || credentials.calls.Load() != 1 {
		t.Fatalf("result=%#v", result)
	}
	if len(received) != 4 || string(received["model"]) != `"pinned-model"` || string(received["max_tokens"]) != "100" || string(received["stream"]) != "false" {
		t.Fatalf("wire=%s", received)
	}
	var messages []struct{ Role, Content string }
	if json.Unmarshal(received["messages"], &messages) != nil || len(messages) != 2 || messages[0].Role != "system" || messages[1].Role != "user" {
		t.Fatalf("messages=%s", received["messages"])
	}
	instructions, err := review.TrustedModelRequestInstructions(inner)
	if err != nil || messages[0].Content != instructions || !bytes.Equal([]byte(messages[1].Content), inner) {
		t.Fatal("instruction or sanitized inner bytes changed")
	}
	response := result.Response()
	if response.FinishReason() != provider.ResponseFinishStop || response.Parts()[0].Kind() != provider.ResponsePartStructuredData || response.Usage().InputTokens() != 120 || response.Usage().OutputTokens() != 30 || response.Usage().CachedInputTokens() != 20 {
		t.Fatalf("response=%#v", response)
	}
}

func TestChatCompletionsProtocolIdentityAndResponsesCompatibility(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	config := Config{AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:11434/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)}
	a, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	// This is the existing Responses configuration preimage, not a new contract.
	encoded, _ := json.Marshal(struct {
		Contract            string `json:"contract"`
		Version             int    `json:"version"`
		Adapter             string `json:"adapter"`
		Provider            string `json:"provider"`
		Connection          string `json:"connection"`
		Zone                string `json:"zone"`
		Logging             string `json:"logging"`
		Endpoint            string `json:"endpoint"`
		Credential          string `json:"credential"`
		HTTPClient          string `json:"http_client"`
		TimeoutMilliseconds int64  `json:"timeout_milliseconds"`
	}{"open-trestle/openai-responses-adapter", 4, config.AdapterID, config.ProviderID, config.ConnectionID, config.Zone.String(), config.ContentLoggingMode.String(), config.Endpoint, config.CredentialIdentity, defaultHTTPClientIdentity(), maximumRequestTimeout.Milliseconds()})
	digest := sha256.Sum256(encoded)
	if a.ConfigurationIdentity() != hex.EncodeToString(digest[:]) {
		t.Fatal("Responses identity changed")
	}
	config.Protocol = ProtocolResponses
	explicit, err := New(config)
	if err != nil || explicit.ConfigurationIdentity() != a.ConfigurationIdentity() {
		t.Fatal("explicit Responses changed identity")
	}
	instructions := "trusted"
	request, err := a.newRequest(context.Background(), testKey(t), "model", 10, instructions, []byte("payload"), false)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := io.ReadAll(request.Body)
	if request.URL.Path != "/v1/responses" || string(wire) != `{"model":"model","instructions":"trusted","input":[{"role":"user","content":[{"type":"input_text","text":"payload"}]}],"max_output_tokens":10,"store":false}` {
		t.Fatalf("Responses wire changed: %s", wire)
	}
	config.Protocol = ProtocolChatCompletions
	chat, err := New(config)
	if err != nil || chat.Validate() != nil || chat.ConfigurationIdentity() == a.ConfigurationIdentity() {
		t.Fatal("Chat protocol omitted from identity")
	}
	chat.protocol = ProtocolResponses
	if chat.Validate() == nil {
		t.Fatal("protocol mutation retained valid identity")
	}
	config.Protocol = Protocol("chat")
	if _, err := New(config); err == nil {
		t.Fatal("unknown protocol accepted")
	}
}

func TestChatCompletionsPreservesLengthAndRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, content, refusal, finish string
		want                           provider.ResponseFinishReason
		kind                           provider.ResponsePartKind
	}{
		// Partial text at a length stop is an exhausted allowance
		// (length_stop_partial_test.go); a complete JSON answer keeps it.
		{"length", `{"ok":true}`, "", "length", provider.ResponseFinishLength, provider.ResponsePartStructuredData},
		{"refusal", "", "blocked", "stop", provider.ResponseFinishStop, provider.ResponsePartRefusal},
		{"filter", "", "blocked", "content_filter", provider.ResponseFinishContentFilter, provider.ResponsePartRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			_ = json.Unmarshal([]byte(chatResponse("model")), &body)
			choice := body["choices"].([]any)[0].(map[string]any)
			choice["finish_reason"] = tc.finish
			choice["message"] = map[string]any{"role": "assistant", "content": tc.content, "refusal": tc.refusal}
			encoded, _ := json.Marshal(body)
			response, err := normalizeChatResponse(encoded, testRoute(t, "model", ""))
			if err != nil || response.FinishReason() != tc.want || response.Parts()[0].Kind() != tc.kind {
				t.Fatalf("response=%#v err=%v", response, err)
			}
		})
	}
}

func TestChatCompletionsRejectsAmbiguousModelChoiceFinishAndUsage(t *testing.T) {
	valid := chatResponse("model")
	cases := map[string]string{
		"wrong model":          strings.Replace(valid, `"model":"model"`, `"model":"alias"`, 1),
		"unicode choice alias": strings.Replace(valid, `"choices":`, `"choiceſ":`, 1),
		"unknown field":        strings.Replace(valid, `"object":"chat.completion"`, `"object":"chat.completion","extra":true`, 1),
		"wrong case":           strings.Replace(valid, `"model":"model"`, `"Model":"model"`, 1),
		"duplicate":            strings.Replace(valid, `"model":"model"`, `"model":"model","model":"model"`, 1),
		"tool finish":          strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"tool_calls"`, 1),
		"unknown finish":       strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"unknown"`, 1),
		"null finish":          strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":null`, 1),
		"wrong role":           strings.Replace(valid, `"role":"assistant"`, `"role":"user"`, 1),
		"wrong index":          strings.Replace(valid, `"index":0`, `"index":1`, 1),
		"missing index":        strings.Replace(valid, `"index":0,`, "", 1),
		"wrong total":          strings.Replace(valid, `"total_tokens":150`, `"total_tokens":149`, 1),
		"missing count":        strings.Replace(valid, `"completion_tokens":30,`, "", 1),
		"cached overflow":      strings.Replace(valid, `"cached_tokens":20`, `"cached_tokens":121`, 1),
		"reasoning overflow":   strings.Replace(valid, `"reasoning_tokens":10`, `"reasoning_tokens":31`, 1),
		"integer overflow":     strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":18446744073709551615`, 1),
		"null count":           strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":null`, 1),
		"tool payload":         strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","tool_calls":[{"id":"call"}]`, 1),
		"trailing":             valid + ` {}`,
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"multiple choices", func(m map[string]any) { choices := m["choices"].([]any); m["choices"] = append(choices, choices[0]) }},
		{"no choices", func(m map[string]any) { m["choices"] = []any{} }},
		{"empty message", func(m map[string]any) {
			m["choices"].([]any)[0].(map[string]any)["message"] = map[string]any{"role": "assistant", "content": nil, "refusal": nil}
		}},
		{"mixed refusal", func(m map[string]any) {
			m["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["refusal"] = "blocked"
		}},
	} {
		var m map[string]any
		_ = json.Unmarshal([]byte(valid), &m)
		tc.mutate(m)
		encoded, _ := json.Marshal(m)
		cases[tc.name] = string(encoded)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeChatResponse([]byte(body), testRoute(t, "model", "")); err == nil {
				t.Fatalf("accepted %s", body)
			}
		})
	}
	for _, usage := range []string{"null", ""} {
		var m map[string]any
		_ = json.Unmarshal([]byte(valid), &m)
		if usage == "" {
			delete(m, "usage")
		} else {
			m["usage"] = nil
		}
		encoded, _ := json.Marshal(m)
		response, err := normalizeChatResponse(encoded, testRoute(t, "model", ""))
		if err != nil || response.Usage().IsKnown() {
			t.Fatalf("missing usage must stay unknown: %v", err)
		}
	}
}

func TestChatCompletionsRemoteSanitizedGateAndBounds(t *testing.T) {
	request, inner := sanitizedRequestWithCanary(t, false, "sk-proj-chat-remote-canary-aaaaaaaa")
	route := remoteTestRoute(t, "openai-responses", "openai", "primary/openai", "model")
	var received []byte
	credentials := &credentialProvider{key: testKey(t)}
	a, _ := newRemoteTLSTestAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("path=%s", r.URL.Path)
		}
		received, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(chatResponse("model")))
	}), credentials)
	useChatProtocol(a)
	for _, denied := range []struct {
		request provider.Request
		receipt string
	}{{request, ""}, {testRawModelRequest(t), strings.Repeat("c", 64)}} {
		result := a.executeWithSanitizedReceipt(context.Background(), route, 100, denied.request, denied.receipt)
		if result.Failure() != gateway.RouteFailurePolicyDenied || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 || len(received) != 0 {
			t.Fatalf("remote gate=%#v", result)
		}
	}
	result := a.executeWithSanitizedReceipt(context.Background(), route, 100, request, strings.Repeat("c", 64))
	if result.Status() != gateway.RouteDispatchSucceeded {
		t.Fatalf("remote=%#v", result)
	}
	var wire struct {
		Messages []struct{ Role, Content string }
	}
	if json.Unmarshal(received, &wire) != nil || len(wire.Messages) != 2 || !bytes.Equal([]byte(wire.Messages[1].Content), inner) {
		t.Fatal("remote inner payload changed")
	}
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		failure gateway.RouteFailureClass
		safety  gateway.RouteReplaySafety
	}{
		{"vendor error", 429, `{"error":"must not escape"}`, gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect},
		{"invalid", 200, chatResponse("wrong"), gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown},
		{"oversized", 200, strings.Repeat("x", maximumResponseBytes+1), gateway.RouteFailureInvalidResponse, gateway.RouteReplayOutcomeUnknown},
		{"redirect", 307, "", gateway.RouteFailureTransport, gateway.RouteReplayOutcomeUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _ := newRemoteTLSTestAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == 307 {
					w.Header().Set("Location", "https://redirect.example.test/escape")
				}
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			}), credentials)
			useChatProtocol(a)
			result := a.executeWithSanitizedReceipt(context.Background(), route, 100, request, strings.Repeat("c", 64))
			if result.Failure() != tc.failure || result.ReplaySafety() != tc.safety {
				t.Fatalf("bounded failure=%#v", result)
			}
		})
	}
}

func TestChatCompletionsStillDeniesBeforeCredentialsAndNetwork(t *testing.T) {
	credentials := &credentialProvider{key: testKey(t)}
	config := Config{Protocol: ProtocolChatCompletions, AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZonePrivateRemote, ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://api.example.test/v1", Credentials: credentials, CredentialIdentity: strings.Repeat("a", 64)}
	for _, zone := range []provider.ProviderZone{provider.ProviderZoneLocal, provider.ProviderZoneBrokeredRemote, provider.ProviderZoneSubscriptionOAuth} {
		config.Zone = zone
		if _, err := New(config); err == nil {
			t.Fatalf("Chat admitted remote endpoint in %s", zone.String())
		}
	}
	a := newTestAdapter(t, "http://127.0.0.1:1/v1", credentials)
	useChatProtocol(a)
	result := a.execute(context.Background(), testRoute(t, "model", ""), 100, testRawVerificationRequest(t, "sk-proj-raw-chat-canary-aaaaaaaa"))
	if result.Failure() != gateway.RouteFailurePolicyDenied || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 {
		t.Fatalf("raw verifier=%#v", result)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = a.execute(ctx, testRoute(t, "model", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureCancelled || result.ReplaySafety() != gateway.RouteReplayNotDispatched || credentials.calls.Load() != 0 {
		t.Fatalf("cancelled=%#v", result)
	}
}

func TestChatCompletionsRemoteVerificationUsesExactSanitizedInner(t *testing.T) {
	request, inner := sanitizedRequestWithCanary(t, true, "sk-proj-chat-verification-canary-aaaaaaaa")
	var received []byte
	credentials := &credentialProvider{key: testKey(t)}
	a, _ := newRemoteTLSTestAdapter(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(chatResponse("model")))
	}), credentials)
	useChatProtocol(a)
	route := remoteTestRoute(t, "openai-responses", "openai", "primary/openai", "model")
	result := a.executeWithSanitizedReceipt(context.Background(), route, 100, request, strings.Repeat("c", 64))
	var wire struct {
		Messages []struct{ Role, Content string }
	}
	if result.Status() != gateway.RouteDispatchSucceeded || json.Unmarshal(received, &wire) != nil || len(wire.Messages) != 2 || !bytes.Equal([]byte(wire.Messages[1].Content), inner) {
		t.Fatalf("verification=%#v", result)
	}
}
