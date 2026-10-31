package openai

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestLocalChatMetadataIsInertAndUsageRemainsAuthoritative(t *testing.T) {
	var wire map[string]any
	if err := json.Unmarshal([]byte(chatResponse("model")), &wire); err != nil {
		t.Fatal(err)
	}
	wire["timings"] = map[string]any{"cache_n": 236, "prompt_n": 1, "prompt_ms": 30.958, "prompt_per_token_ms": 30.958, "prompt_per_second": 32.301828283480845, "predicted_n": 35, "predicted_ms": 661.064, "predicted_per_token_ms": 18.887542857142858, "predicted_per_second": 52.94494935437416}
	message := wire["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	message["reasoning_content"] = "private reasoning must not become review output"
	document, _ := json.Marshal(wire)
	response, err := normalizeChatResponse(document, testRoute(t, "model", ""))
	if err != nil {
		t.Fatal(err)
	}
	if response.Usage().InputTokens() != 120 || response.Usage().OutputTokens() != 30 || response.Usage().CachedInputTokens() != 20 || len(response.Parts()) != 1 || response.Parts()[0].Kind() != provider.ResponsePartStructuredData || strings.Contains(string(response.Parts()[0].Payload()), "private reasoning") {
		t.Fatalf("metadata altered response: %#v", response)
	}
	delete(wire, "usage")
	document, _ = json.Marshal(wire)
	response, err = normalizeChatResponse(document, testRoute(t, "model", ""))
	if err != nil || response.Usage().IsKnown() {
		t.Fatal("timings invented token usage")
	}
	delete(message, "content")
	document, _ = json.Marshal(wire)
	if _, err := normalizeChatResponse(document, testRoute(t, "model", "")); err == nil {
		t.Fatal("reasoning substituted for missing content")
	}
}

func TestLocalChatMetadataKeepsStrictShapeAndBounds(t *testing.T) {
	for _, mutate := range []func(map[string]any){
		func(w map[string]any) { w["timings"] = map[string]any{"unknown": 1} },
		func(w map[string]any) { w["timings"] = map[string]any{"prompt_n": -1} },
		func(w map[string]any) { w["timings"] = map[string]any{"prompt_ms": -1} },
		func(w map[string]any) { w["timings"] = map[string]any{"prompt_ms": "fast"} },
		func(w map[string]any) { w["timings"] = []any{} },
		func(w map[string]any) {
			w["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)["reasoning_content"] = map[string]any{"text": "not a string"}
		},
		func(w map[string]any) { w["unreviewed_metadata"] = true },
	} {
		var wire map[string]any
		if err := json.Unmarshal([]byte(chatResponse("model")), &wire); err != nil {
			t.Fatal(err)
		}
		mutate(wire)
		document, _ := json.Marshal(wire)
		if _, err := normalizeChatResponse(document, testRoute(t, "model", "")); err == nil {
			t.Fatalf("accepted %s", document)
		}
	}
	document := strings.Replace(chatResponse("model"), `"model":"model"`, `"model":"model","timings":{"prompt_ms":1e999}`, 1)
	if _, err := normalizeChatResponse([]byte(document), testRoute(t, "model", "")); err == nil {
		t.Fatal("accepted overflowing timing")
	}
	document = strings.Replace(chatResponse("model"), `"role":"assistant"`, `"role":"assistant","reasoning_content":"`+strings.Repeat("x", maximumResponseBytes)+`"`, 1)
	if len(document) <= maximumResponseBytes {
		t.Fatal("oversize fixture was not oversized")
	}
	if _, err := normalizeChatResponse([]byte(document), testRoute(t, "model", "")); err == nil {
		t.Fatal("accepted oversized body")
	}
	invalidUTF8 := bytes.Replace([]byte(chatResponse("model")), []byte(`"role":"assistant"`), append([]byte(`"role":"assistant","reasoning_content":"`), 0xff, '"'), 1)
	if _, err := normalizeChatResponse(invalidUTF8, testRoute(t, "model", "")); err == nil {
		t.Fatal("accepted invalid UTF-8 metadata")
	}
}
