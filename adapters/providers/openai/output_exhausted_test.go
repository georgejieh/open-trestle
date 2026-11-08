package openai

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// Shape of the live reply from a local Ollama daemon relaying the reasoning
// model nemotron-3-super:cloud as verifier: the whole output allowance went to
// the reasoning trace and the answer is empty.
const ollamaSigninExhaustedResponse = `{"id":"chatcmpl-12","object":"chat.completion","created":1794119300,"model":"nemotron-3-super","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning":"We need to check each candidate against the evidence."},"finish_reason":"length"}],"usage":{"prompt_tokens":3120,"completion_tokens":4096,"total_tokens":7216}}`

func TestOllamaSigninEmptyLengthFinishIsOutputExhausted(t *testing.T) {
	_, err := normalizeOllamaSigninResponse([]byte(ollamaSigninExhaustedResponse), ollamaSigninTestRoute(t, "nemotron-3-super:cloud"))
	if !errors.Is(err, errModelOutputExhausted) {
		t.Fatalf("empty length finish classified as %v", err)
	}
}

func TestChatLengthFinishClassification(t *testing.T) {
	route := ollamaSigninTestRoute(t, "model-a")
	for _, tc := range []struct {
		name, content string
		exhausted     bool
	}{
		{"empty", `""`, true},
		{"whitespace", `" \n\t"`, true},
		{"null", `null`, true},
		{"truncated answer", `"{\"schema_version\":1,\"verdicts\":["`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"chatcmpl-1","object":"chat.completion","model":"model-a","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":` + tc.content + `}}],"usage":{"prompt_tokens":1,"completion_tokens":4096,"total_tokens":4097}}`
			response, err := normalizeChatResponse([]byte(body), route)
			if tc.exhausted != errors.Is(err, errModelOutputExhausted) {
				t.Fatalf("exhausted=%v err=%v", tc.exhausted, err)
			}
			// Partial output is still a length-finished response for the
			// strict document parser to refuse, not an exhausted allowance.
			if !tc.exhausted && (err != nil || response.FinishReason() != provider.ResponseFinishLength) {
				t.Fatalf("truncated answer err=%v finish=%v", err, response.FinishReason())
			}
		})
	}
	stop := `{"id":"chatcmpl-1","object":"chat.completion","model":"model-a","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":""}}]}`
	if _, err := normalizeChatResponse([]byte(stop), route); err == nil || errors.Is(err, errModelOutputExhausted) {
		t.Fatalf("empty stop answer classified as %v", err)
	}
}

func TestResponsesIncompleteWithoutOutputIsOutputExhausted(t *testing.T) {
	route := ollamaSigninTestRoute(t, "model-a")
	body := `{"id":"resp-1","object":"response","status":"incomplete","model":"model-a","output":[],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":1,"output_tokens":4096,"total_tokens":4097}}`
	if _, err := normalizeResponse([]byte(body), route); !errors.Is(err, errModelOutputExhausted) {
		t.Fatalf("incomplete response without output classified as %v", err)
	}
}

func TestOutputExhaustedRouteFailureClassRoundTrips(t *testing.T) {
	parsed, err := gateway.ParseRouteFailureClass("output_exhausted")
	if err != nil || parsed != gateway.RouteFailureOutputExhausted || parsed.Validate() != nil {
		t.Fatalf("parsed=%v err=%v", parsed, err)
	}
	if _, err := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureOutputExhausted, gateway.RouteReplayOutcomeUnknown, provider.NewUnknownRouteTokenUsage(), 0); err != nil {
		t.Fatal(err)
	}
}
