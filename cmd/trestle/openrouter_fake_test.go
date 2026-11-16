package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// A synthetic, offline stand-in for OpenRouter's two public API lists. The
// JSON has the same shape as the real responses (GET /api/v1/models and GET
// /api/v1/endpoints/zdr), but every model, provider, price and limit is made
// up. It answers only plain GETs without a credential, cookie or query.

type fakeORModel struct {
	id                 string
	context, output    uint64
	prompt, completion string
	params             []string
	zdr                []fakeOREndpoint
	unlisted           bool // only in the ZDR list
}

type fakeOREndpoint struct {
	tag, provider      string
	context, output    uint64
	prompt, completion string
	safety             bool
	noMaxTokens        bool
}

type fakeOpenRouterAPI struct {
	t           *testing.T
	zdr, models string // response bodies; "" answers HTTP 503
	mu          sync.Mutex
	requests    []string
}

func (f *fakeOpenRouterAPI) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodGet || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody {
		f.t.Errorf("OpenRouter API read sent more than a plain GET: %s %s", request.Method, request.URL)
	}
	f.mu.Lock()
	f.requests = append(f.requests, request.URL.String())
	f.mu.Unlock()
	body := ""
	switch request.URL.String() {
	case "https://openrouter.ai/api/v1/endpoints/zdr":
		body = f.zdr
	case "https://openrouter.ai/api/v1/models":
		body = f.models
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	if body == "" {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func fakeOpenRouterBodies(models ...fakeORModel) (string, string) {
	listed, endpoints := []any{}, []any{}
	for _, model := range models {
		params := model.params
		if params == nil {
			params = []string{"max_tokens", "temperature", "response_format", "structured_outputs"}
		}
		if !model.unlisted {
			listed = append(listed, map[string]any{"id": model.id, "canonical_slug": model.id + "-fixture", "hugging_face_id": nil, "name": "Fixture: " + model.id, "created": 1790000000, "description": "synthetic fixture model",
				"context_length": model.context, "architecture": map[string]any{"modality": "text->text", "input_modalities": []string{"text"}, "output_modalities": []string{"text"}, "tokenizer": "Other", "instruct_type": nil},
				"pricing":      map[string]any{"prompt": model.prompt, "completion": model.completion, "web_search": "0.01"},
				"top_provider": map[string]any{"context_length": model.context, "max_completion_tokens": model.output, "is_moderated": false}, "per_request_limits": nil, "supported_parameters": params, "default_parameters": map[string]any{},
				"links": map[string]any{"details": "/api/v1/models/" + model.id + "/endpoints"}, "endpoints": []string{"/api/v1/chat/completions"}})
		}
		for _, endpoint := range model.zdr {
			endpointParams := []string{"max_tokens", "temperature", "response_format", "structured_outputs"}
			if endpoint.noMaxTokens {
				endpointParams = []string{"temperature"}
			}
			endpoints = append(endpoints, map[string]any{"name": endpoint.provider + " | " + model.id, "model_id": model.id, "model_name": "Fixture: " + model.id, "context_length": endpoint.context,
				"pricing":       map[string]any{"prompt": endpoint.prompt, "completion": endpoint.completion, "discount": 0},
				"provider_name": endpoint.provider, "tag": endpoint.tag, "service_tier": nil, "quantization": "unknown", "max_completion_tokens": endpoint.output, "max_prompt_tokens": nil,
				"supported_parameters": endpointParams, "supports_tool_choice": map[string]any{"none": true}, "status": 0, "uptime_last_30m": 100, "uptime_last_5m": nil, "uptime_last_1d": 99.9,
				"supports_implicit_caching": false, "native_tools": map[string]any{}, "latency_last_30m": nil, "throughput_last_30m": nil, "safety_retention": endpoint.safety})
		}
	}
	zdr, _ := json.Marshal(map[string]any{"data": endpoints})
	list, _ := json.Marshal(map[string]any{"data": listed, "total_count": len(listed), "links": map[string]any{"next": nil}})
	return string(zdr), string(list)
}

// fakeOpenRouter installs the fake as the setup fetch transport.
func fakeOpenRouter(t *testing.T, models ...fakeORModel) *fakeOpenRouterAPI {
	t.Helper()
	fake := &fakeOpenRouterAPI{t: t}
	fake.zdr, fake.models = fakeOpenRouterBodies(models...)
	previous := initEvidenceTransport
	initEvidenceTransport = fake
	t.Cleanup(func() { initEvidenceTransport = previous })
	return fake
}

// The standard pair: a finder with two usable ZDR endpoints (plus one that
// keeps prompts for Safety Retention) and a checker with one.
var (
	fakeORFinder = fakeORModel{id: "vendor/generator", context: 200000, output: 64000, prompt: "0.000003", completion: "0.000015", zdr: []fakeOREndpoint{
		{tag: "fixture-cloud/us", provider: "Fixture Cloud", context: 200000, output: 64000, prompt: "0.0000033", completion: "0.0000165"},
		{tag: "fixture-cloud", provider: "Fixture Cloud", context: 200000, output: 64000, prompt: "0.000003", completion: "0.000015"},
		{tag: "fixture-safety/global", provider: "Fixture Safety", context: 200000, output: 64000, prompt: "0.000001", completion: "0.000002", safety: true},
	}}
	fakeORChecker = fakeORModel{id: "other/verifier", context: 128000, output: 16000, prompt: "0.0000005", completion: "0.0000015", zdr: []fakeOREndpoint{
		{tag: "fixture-host/fp8", provider: "Fixture Host", context: 128000, output: 16000, prompt: "0.0000005", completion: "0.0000015"},
	}}
	fakeORNoZDR = fakeORModel{id: "plain/verifier", context: 64000, output: 8192, prompt: "0.000001", completion: "0.000002"}
)
