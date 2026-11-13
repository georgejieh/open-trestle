package openai

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func openRouterDocumentedChatResponse(model string) []byte {
	return []byte(`{"id":"chatcmpl-profile","object":"chat.completion","created":1730000000,"model":"` + model + `","choices":[{"index":0,"message":{"role":"assistant","content":"{\"summary\":\"ok\",\"findings\":[]}"},"finish_reason":"stop","logprobs":null}],"usage":{"prompt_tokens":120,"completion_tokens":30,"total_tokens":150,"cost":0.0012,"is_byok":false,"cost_details":{"upstream_inference_prompt_cost":0.0008,"upstream_inference_completions_cost":0.0004,"upstream_inference_cost":null},"prompt_tokens_details":{"cached_tokens":20,"cache_write_tokens":5,"audio_tokens":0,"video_tokens":0},"completion_tokens_details":{"reasoning_tokens":10,"audio_tokens":null,"accepted_prediction_tokens":null,"rejected_prediction_tokens":0},"server_tool_use_details":{"tool_calls_requested":0,"tool_calls_executed":null,"web_search_requests":0}}}`)
}

func TestOpenRouterResponseDocumentedMetadataRequiresProfile(t *testing.T) {
	body := openRouterDocumentedChatResponse("model")
	if _, err := normalizeChatResponse(body, testRoute(t, "model", "")); err == nil {
		t.Fatal("generic chat accepted profile additions")
	}
	// Only the named profile uses the response envelope.
	a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
	response, err := a.normalizeProviderResponse(body, testRoute(t, "model", ""))
	if err != nil || !response.Usage().IsKnown() || response.Usage().InputTokens() != 120 || response.Usage().OutputTokens() != 30 || response.Usage().CachedInputTokens() != 20 {
		t.Fatalf("profile response=%#v error=%v", response, err)
	}
	if response.Parts()[0].Kind() != provider.ResponsePartStructuredData {
		t.Fatal("content normalization changed")
	}
}

func TestOpenRouterResponseUsageAbsentOrNullRemainsUnknown(t *testing.T) {
	for _, absent := range []bool{true, false} {
		var body map[string]json.RawMessage
		if json.Unmarshal(openRouterDocumentedChatResponse("model"), &body) != nil {
			t.Fatal("fixture")
		}
		if absent {
			delete(body, "usage")
		} else {
			body["usage"] = json.RawMessage("null")
		}
		encoded, _ := json.Marshal(body)
		a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
		response, err := a.normalizeProviderResponse(encoded, testRoute(t, "model", ""))
		if err != nil || response.Usage().IsKnown() {
			t.Fatalf("unknown usage=%#v %v", response, err)
		}
	}
}

func TestOpenRouterResponseAllowsOnlyAbsentOrFalseBYOK(t *testing.T) {
	valid := string(openRouterDocumentedChatResponse("model"))
	for _, replacement := range []string{``, `"is_byok":false,`} {
		body := strings.Replace(valid, `"is_byok":false,`, replacement, 1)
		a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
		if _, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", "")); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"true", "null", "0", `"false"`} {
		body := strings.Replace(valid, `"is_byok":false`, `"is_byok":`+value, 1)
		a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
		if _, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", "")); err == nil {
			t.Fatalf("accepted BYOK %s", value)
		}
	}
}

func TestOpenRouterResponseRejectsUnsafeUsageAndUnknownMetadata(t *testing.T) {
	valid := string(openRouterDocumentedChatResponse("model"))
	cases := map[string]string{
		"tool requested":               strings.Replace(valid, `"tool_calls_requested":0`, `"tool_calls_requested":1`, 1),
		"tool executed":                strings.Replace(valid, `"tool_calls_executed":null`, `"tool_calls_executed":1`, 1),
		"web search":                   strings.Replace(valid, `"web_search_requests":0`, `"web_search_requests":1`, 1),
		"tool negative":                strings.Replace(valid, `"tool_calls_requested":0`, `"tool_calls_requested":-1`, 1),
		"tool fractional":              strings.Replace(valid, `"tool_calls_requested":0`, `"tool_calls_requested":0.5`, 1),
		"tool unknown":                 strings.Replace(valid, `"tool_calls_requested":0`, `"unknown_tool":0`, 1),
		"tool wrong type":              strings.Replace(valid, `"tool_calls_executed":null`, `"tool_calls_executed":"0"`, 1),
		"tool overflow":                strings.Replace(valid, `"tool_calls_requested":0`, `"tool_calls_requested":18446744073709551616`, 1),
		"negative cost":                strings.Replace(valid, `"cost":0.0012`, `"cost":-0.001`, 1),
		"negative cost underflow":      strings.Replace(valid, `"cost":0.0012`, `"cost":-1e-999`, 1),
		"infinite cost":                strings.Replace(valid, `"cost":0.0012`, `"cost":1e309`, 1),
		"quoted cost":                  strings.Replace(valid, `"cost":0.0012`, `"cost":"0.0012"`, 1),
		"negative detail cost":         strings.Replace(valid, `"upstream_inference_prompt_cost":0.0008`, `"upstream_inference_prompt_cost":-1`, 1),
		"missing required cost detail": strings.Replace(valid, `"upstream_inference_prompt_cost":0.0008,`, ``, 1),
		"null required cost detail":    strings.Replace(valid, `"upstream_inference_prompt_cost":0.0008`, `"upstream_inference_prompt_cost":null`, 1),
		"unknown cost detail":          strings.Replace(valid, `"upstream_inference_cost":null`, `"unreviewed_cost":0`, 1),
		"server tool charge":           strings.Replace(valid, `"upstream_inference_cost":null`, `"upstream_inference_cost":null,"server_tool_cost":0.01`, 1),
		"null prompt detail":           strings.Replace(valid, `"video_tokens":0`, `"video_tokens":null`, 1),
		"server charge underflow":      strings.Replace(valid, `"upstream_inference_cost":null`, `"upstream_inference_cost":null,"server_tool_cost":1e-999`, 1),
		"cache write overflow":         strings.Replace(valid, `"cache_write_tokens":5`, `"cache_write_tokens":121`, 1),
		"video overflow":               strings.Replace(valid, `"video_tokens":0`, `"video_tokens":121`, 1),
		"fractional token count":       strings.Replace(valid, `"completion_tokens":30`, `"completion_tokens":30.5`, 1),
		"sum overflow":                 strings.Replace(valid, `"prompt_tokens":120`, `"prompt_tokens":18446744073709551615`, 1),
		"unknown usage":                strings.Replace(valid, `"cost":0.0012`, `"extra":0`, 1),
		"wrong case":                   strings.Replace(valid, `"is_byok":false`, `"Is_Byok":false`, 1),
		"duplicate":                    strings.Replace(valid, `"cost":0.0012`, `"cost":0.0012,"cost":0`, 1),
		"wrong model":                  strings.Replace(valid, `"model":"model"`, `"model":"other"`, 1),
		"action message":               strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","tool_calls":[{"id":"call"}]`, 1),
		"trailing":                     valid + ` {}`,
		"oversized":                    strings.Repeat(" ", maximumResponseBytes) + valid,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
			if _, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", "")); err == nil {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}

func TestOpenRouterResponseNullableZeroMetadataAndLegacyIdentity(t *testing.T) {
	valid := string(openRouterDocumentedChatResponse("model"))
	for _, change := range []struct{ old, replacement string }{
		{`"cost":0.0012`, `"cost":null`},
		{`"cost_details":{"upstream_inference_prompt_cost":0.0008,"upstream_inference_completions_cost":0.0004,"upstream_inference_cost":null}`, `"cost_details":null`},
		{`"server_tool_use_details":{"tool_calls_requested":0,"tool_calls_executed":null,"web_search_requests":0}`, `"server_tool_use_details":null`},
		{`"server_tool_use_details":{"tool_calls_requested":0,"tool_calls_executed":null,"web_search_requests":0}`, `"server_tool_use_details":{}`},
		{`"upstream_inference_cost":null`, `"upstream_inference_cost":null,"server_tool_cost":0`},
	} {
		a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
		body := strings.Replace(valid, change.old, change.replacement, 1)
		if _, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", "")); err != nil {
			t.Fatal(err)
		}
	}
	generic := []byte(chatResponse("model"))
	legacy, err := normalizeChatResponse(generic, testRoute(t, "model", ""))
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
	profile, err := a.normalizeProviderResponse(generic, testRoute(t, "model", ""))
	if err != nil || !bytes.Equal(profile.Parts()[0].Payload(), legacy.Parts()[0].Payload()) || profile.Usage() != legacy.Usage() {
		t.Fatal("generic-shaped response changed")
	}
}

func TestOpenRouterResponseRejectsInvalidUTF8LikeGenericChat(t *testing.T) {
	// A raw 0xff byte inside the assistant content string is not valid UTF-8. The JSON
	// decoder would silently replace it with U+FFFD, so the raw body must be rejected
	// exactly as the generic, OpenCode Go and OpenCode Console normalizers reject it.
	body := bytes.Replace(openRouterDocumentedChatResponse("model"), []byte(`\"summary\":\"ok\"`), []byte("\\\"summary\\\":\\\"o\xffk\\\""), 1)
	if bytes.Equal(body, openRouterDocumentedChatResponse("model")) {
		t.Fatal("fixture replacement did not apply")
	}
	if _, err := normalizeChatResponse(body, testRoute(t, "model", "")); err == nil {
		t.Fatal("generic chat accepted invalid UTF-8")
	}
	a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
	if response, err := a.normalizeProviderResponse(body, testRoute(t, "model", "")); err == nil {
		t.Fatalf("OpenRouter profile accepted invalid UTF-8 and rewrote content to %q", response.Parts()[0].Payload())
	}
}

// The fixtures are OpenRouter's replies to a synthetic probe on 2026-11-11,
// byte for byte. Their provider, native_finish_reason, message.reasoning and
// image_tokens members are undocumented or newer than the decoder was, and
// every real review failed as an invalid response until they were accepted.
func TestOpenRouterResponseAcceptsLiveReplies(t *testing.T) {
	for file, model := range map[string]string{
		"openrouter-live-2026-11-11-gpt-oss-120b.json":  "openai/gpt-oss-120b",
		"openrouter-live-2026-11-11-glm-5.3-flash.json": "z-ai/glm-5.3-flash",
		// A verification reply with reasoning and reasoning_details, and 99
		// reasoning tokens reported against 95 billed completion tokens. Only
		// the reasoning text is replaced; every other byte is as received.
		"openrouter-live-2026-11-11-glm-5.3-flash-verification.json": "z-ai/glm-5.3-flash",
	} {
		body, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, profile := range []RequestProfile{RequestProfileOpenRouterZDRChatV1, RequestProfileOpenRouterZDRChatV2} {
			a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: profile}
			response, err := a.normalizeProviderResponse(body, testRoute(t, model, ""))
			if err != nil {
				t.Fatalf("%s %s: %v", file, profile, err)
			}
			if !response.Usage().IsKnown() || response.Usage().InputTokens() == 0 || response.Usage().OutputTokens() == 0 {
				t.Fatalf("%s %s usage=%#v", file, profile, response.Usage())
			}
			if len(response.Parts()) != 1 || response.Parts()[0].Kind() != provider.ResponsePartStructuredData {
				t.Fatalf("%s %s parts=%#v", file, profile, response.Parts())
			}
		}
	}
}

func TestOpenRouterResponseIgnoresRoutingMetadataAndDropsReasoning(t *testing.T) {
	valid := string(openRouterDocumentedChatResponse("model"))
	base := mustNormalizeOpenRouter(t, valid)
	for name, body := range map[string]string{
		"provider":                   strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile","provider":"PrimeIntellect"`, 1),
		"null provider":              strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile","provider":null`, 1),
		"unknown envelope":           strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile","extra":null,"later_member":{"nested":[1,2]}`, 1),
		"alignment":                  strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile","alignment":{"calls":[]},"safeguard_results":[]`, 1),
		"guardrail stage":            strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile","openrouter_metadata":{"requested":"model","strategy":"direct","pipeline":[{"type":"guardrail","name":"budget"}]}`, 1),
		"metadata no stages":         strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile","openrouter_metadata":{"requested":"model","attempt":1}`, 1),
		"native finish":              strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"stop","native_finish_reason":"end_turn"`, 1),
		"null choice error":          strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"stop","error":null`, 1),
		"reasoning":                  strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","reasoning":"thinking about it"`, 1),
		"reasoning details":          strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","reasoning_details":[{"type":"reasoning.summary","summary":"s","index":0},{"type":"reasoning.encrypted","data":"x"},{"type":"reasoning.text","text":"t"}]`, 1),
		"empty images":               strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","images":[]`, 1),
		"message model name":         strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","model":"model","name":"assistant"`, 1),
		"image tokens":               strings.Replace(valid, `"reasoning_tokens":10`, `"reasoning_tokens":10,"image_tokens":0`, 1),
		"breakdown above completion": strings.Replace(valid, `"reasoning_tokens":10`, `"reasoning_tokens":31,"image_tokens":31`, 1),
		"zero deferred tools":        strings.Replace(valid, `"is_byok":false`, `"is_byok":false,"deferred_tools_details":{"turns":0,"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			response := mustNormalizeOpenRouter(t, body)
			if !bytes.Equal(response.Parts()[0].Payload(), base.Parts()[0].Payload()) || response.Usage() != base.Usage() {
				t.Fatal("routing metadata or reasoning changed the answer or usage")
			}
		})
	}
}

func TestOpenRouterResponseRefusesAlteredOrUnexpectedAnswers(t *testing.T) {
	valid := string(openRouterDocumentedChatResponse("model"))
	envelope := func(member string) string {
		return strings.Replace(valid, `"id":"chatcmpl-profile"`, `"id":"chatcmpl-profile",`+member, 1)
	}
	message := func(member string) string {
		return strings.Replace(valid, `"role":"assistant"`, `"role":"assistant",`+member, 1)
	}
	for name, body := range map[string]string{
		"plugin stage":             envelope(`"openrouter_metadata":{"pipeline":[{"type":"plugin","name":"web"}]}`),
		"server tools stage":       envelope(`"openrouter_metadata":{"pipeline":[{"type":"server_tools","name":"search"}]}`),
		"response healing":         envelope(`"openrouter_metadata":{"pipeline":[{"type":"response_healing","name":"json"}]}`),
		"context compression":      envelope(`"openrouter_metadata":{"pipeline":[{"type":"guardrail","name":"budget"},{"type":"context_compression","name":"middle-out"}]}`),
		"untyped stage":            envelope(`"openrouter_metadata":{"pipeline":[{"name":"x"}]}`),
		"pipeline not a list":      envelope(`"openrouter_metadata":{"pipeline":"guardrail"}`),
		"metadata not an object":   envelope(`"openrouter_metadata":"direct"`),
		"provider not a string":    envelope(`"provider":{"name":"x"}`),
		"empty provider":           envelope(`"provider":""`),
		"control in provider":      envelope(`"provider":"a\u0007b"`),
		"long provider":            envelope(`"provider":"` + strings.Repeat("p", 129) + `"`),
		"choice error":             strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"stop","error":{"code":502,"message":"upstream"}`, 1),
		"native finish not string": strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"stop","native_finish_reason":1`, 1),
		"long native finish":       strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"stop","native_finish_reason":"`+strings.Repeat("x", 65)+`"`, 1),
		"unknown choice member":    strings.Replace(valid, `"finish_reason":"stop"`, `"finish_reason":"stop","extra":null`, 1),
		"unknown message member":   message(`"extra":null`),
		"images":                   message(`"images":[{"image_url":{"url":"data:image/png;base64,AA=="}}]`),
		"server tool reasoning":    message(`"reasoning_details":[{"type":"reasoning.server_tool_call","tool_name":"web","arguments":"{}","result":"r"}]`),
		"unknown reasoning type":   message(`"reasoning_details":[{"type":"reasoning.other"}]`),
		"reasoning detail scalar":  message(`"reasoning_details":["text"]`),
		"reasoning not a string":   message(`"reasoning":{"text":"t"}`),
		"deferred tool turn":       strings.Replace(valid, `"is_byok":false`, `"is_byok":false,"deferred_tools_details":{"turns":1,"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}`, 1),
		"negative reasoning count": strings.Replace(valid, `"reasoning_tokens":10`, `"reasoning_tokens":-1`, 1),
		"fractional image count":   strings.Replace(valid, `"reasoning_tokens":10`, `"reasoning_tokens":10,"image_tokens":0.5`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV2}
			if _, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", "")); err == nil {
				t.Fatal("altered or unexpected answer accepted")
			}
		})
	}
}

func mustNormalizeOpenRouter(t *testing.T, body string) provider.Response {
	t.Helper()
	a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV2}
	response, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", ""))
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestOpenRouterResponseUnwrapsOneOuterJSONFence(t *testing.T) {
	valid := string(openRouterDocumentedChatResponse("model"))
	base := mustNormalizeOpenRouter(t, valid)
	answer := `{\"summary\":\"ok\",\"findings\":[]}`
	for _, fence := range []string{"```json\\n%s\\n```", "```\\n%s\\n```", "\\n```json\\n%s\\n```\\n"} {
		body := strings.Replace(valid, `"content":"`+answer+`"`, `"content":"`+strings.Replace(fence, "%s", answer, 1)+`"`, 1)
		if body == valid {
			t.Fatal("fixture replacement did not apply")
		}
		response := mustNormalizeOpenRouter(t, body)
		if !bytes.Equal(response.Parts()[0].Payload(), base.Parts()[0].Payload()) || response.Parts()[0].Kind() != provider.ResponsePartStructuredData {
			t.Fatalf("fenced answer %q was not read as the same document", fence)
		}
	}
	for _, fence := range []string{"```go\\n%s\\n```", "```json\\n```json\\n%s\\n```\\n```", "Here it is:\\n```json\\n%s\\n```", "```json\\n%s"} {
		body := strings.Replace(valid, `"content":"`+answer+`"`, `"content":"`+strings.Replace(fence, "%s", answer, 1)+`"`, 1)
		a := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV2}
		response, err := a.normalizeProviderResponse([]byte(body), testRoute(t, "model", ""))
		if err == nil && response.Parts()[0].Kind() == provider.ResponsePartStructuredData {
			t.Fatalf("%q was read as a structured document", fence)
		}
	}
}
