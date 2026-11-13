package openai

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func ollamaSigninTestRoute(t *testing.T, model string) provider.RouteReference {
	t.Helper()
	route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "ollama-signin", "adapter-a", "connection-a", model, "")
	if err != nil {
		t.Fatal(err)
	}
	return route
}

// Shape captured from a real local Ollama daemon relaying gpt-oss:120b-cloud.
const ollamaSigninRelayedResponse = `{"id":"chatcmpl-681","object":"chat.completion","created":1794118965,"model":"gpt-oss:120b","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":2,\"candidates\":[]}","reasoning":"We need to inspect the change."},"finish_reason":"stop"}],"usage":{"prompt_tokens":2194,"completion_tokens":792,"total_tokens":2986,"prompt_tokens_details":{"cached_tokens":560}}}`

func TestOllamaSigninResponseAcceptsRelayedNameAndDiscardsReasoning(t *testing.T) {
	response, err := normalizeOllamaSigninResponse([]byte(ollamaSigninRelayedResponse), ollamaSigninTestRoute(t, "gpt-oss:120b-cloud"))
	if err != nil {
		t.Fatalf("relayed Ollama response refused: %v", err)
	}
	for _, part := range response.Parts() {
		if string(part.Payload()) == "We need to inspect the change." {
			t.Fatal("reasoning trace leaked into response output")
		}
	}
	// The generic Chat normalizer still refuses the Ollama-only field.
	if _, err := normalizeChatResponse([]byte(ollamaSigninRelayedResponse), ollamaSigninTestRoute(t, "gpt-oss:120b")); err == nil {
		t.Fatal("generic Chat normalizer accepted message.reasoning")
	}
}

func TestOllamaSigninResponseRefusesOtherModel(t *testing.T) {
	if _, err := normalizeOllamaSigninResponse([]byte(ollamaSigninRelayedResponse), ollamaSigninTestRoute(t, "gemma4:31b-cloud")); err == nil {
		t.Fatal("response from a different model was accepted")
	}
}

func TestUnwrapOllamaJSONFence(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"ok\":true}\n```":        `{"ok":true}`,
		"  ```\n{\"ok\":true}\n```  \n":      `{"ok":true}`,
		`{"ok":true}`:                        `{"ok":true}`,
		"```python\n{\"ok\":true}\n```":      "```python\n{\"ok\":true}\n```",
		"```json\n{}\n```\n```json\n{}\n```": "```json\n{}\n```\n```json\n{}\n```",
		"```json {\"ok\":true}```":           "```json {\"ok\":true}```",
		"text ```json\n{}\n```":              "text ```json\n{}\n```",
	}
	for input, want := range cases {
		if got := unwrapOneJSONFence(input); got != want {
			t.Errorf("unwrapOneJSONFence(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestOllamaRelayedModelMatches(t *testing.T) {
	cases := []struct {
		requested, reported string
		want                bool
	}{
		{"gpt-oss:120b-cloud", "gpt-oss:120b-cloud", true},
		{"gpt-oss:120b-cloud", "gpt-oss:120b", true},
		{"gpt-oss:120b-cloud", "gpt-oss:20b", false},
		{"gpt-oss:120b-cloud", "gpt-oss", false},
		{"nemotron-3-super:cloud", "nemotron-3-super", true},
		{"deepseek-v4-pro:cloud", "deepseek-v4-pro:0813", true},
		{"deepseek-v4-pro:cloud", "deepseek-v4-pro:08:13", false},
		{"deepseek-v4-pro:cloud", "deepseek-v4-flash:0731", false},
		{"deepseek-v4-pro:cloud", "deepseek-v4-pro:", false},
		{"qwen3:8b", "qwen3:8b-other", false},
		{"gpt-oss:120b-cloud", "", false},
		{"gpt-oss:120b-cloud", "gpt-oss:120b\n", false},
	}
	for _, c := range cases {
		if got := ollamaRelayedModelMatches(c.requested, c.reported); got != c.want {
			t.Errorf("ollamaRelayedModelMatches(%q, %q) = %v, want %v", c.requested, c.reported, got, c.want)
		}
	}
}
