package openai

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// Shape of the reply from a local Ollama daemon relaying the reasoning
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
		// An answer the model did not finish also spent the allowance.
		{"truncated answer", `"{\"schema_version\":1,\"verdicts\":["`, true},
		{"complete answer", `"{\"schema_version\":1,\"verdicts\":[]}"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"id":"chatcmpl-1","object":"chat.completion","model":"model-a","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":` + tc.content + `}}],"usage":{"prompt_tokens":1,"completion_tokens":4096,"total_tokens":4097}}`
			response, err := normalizeChatResponse([]byte(body), route)
			if tc.exhausted != errors.Is(err, errModelOutputExhausted) {
				t.Fatalf("exhausted=%v err=%v", tc.exhausted, err)
			}
			// A complete JSON answer is still a length-finished response for
			// the strict document parser to refuse, not an exhausted allowance.
			if !tc.exhausted && (err != nil || response.FinishReason() != provider.ResponseFinishLength) {
				t.Fatalf("complete answer err=%v finish=%v", err, response.FinishReason())
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

// exhaustedBody turns a successful fixture into a reply that stopped at the
// output limit with no answer, keeping its usage.
func exhaustedBody(t *testing.T, body []byte) []byte {
	t.Helper()
	answered := []string{`"finish_reason":"stop"`, `"content":"{\"schema_version\":1,\"candidates\":[]}"`, `"content":"{\"summary\":\"ok\",\"findings\":[]}"`}
	changed := strings.Replace(string(body), answered[0], `"finish_reason":"length"`, 1)
	for _, content := range answered[1:] {
		changed = strings.Replace(changed, content, `"content":""`, 1)
	}
	if changed == string(body) || !strings.Contains(changed, `"finish_reason":"length"`) || !strings.Contains(changed, `"content":""`) {
		t.Fatalf("fixture did not become an exhausted reply: %s", changed)
	}
	return []byte(changed)
}

// TestOutputExhaustedKeepsTheUsageItsResponseReported requires an exhausted
// reply to keep the usage it reported under the same checks and trust as a
// successful reply of its profile, and stay unknown when it reported none.
func TestOutputExhaustedKeepsTheUsageItsResponseReported(t *testing.T) {
	route := ollamaSigninTestRoute(t, "model-a")
	known := func(input, output, cached uint32) provider.RouteTokenUsage {
		usage, err := provider.NewRouteTokenUsage(uint64(input), uint64(output), uint64(cached))
		if err != nil {
			t.Fatal(err)
		}
		return usage
	}
	unknown := provider.NewUnknownRouteTokenUsage()
	responses := `{"id":"resp-1","object":"response","status":"incomplete","model":"model-a","output":[],"incomplete_details":{"reason":"max_output_tokens"}`
	chat := `{"id":"chatcmpl-1","object":"chat.completion","model":"model-a","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":""}}]`
	chatAdapter := &Adapter{protocol: ProtocolChatCompletions}
	openRouter := &Adapter{protocol: ProtocolChatCompletions, requestProfile: RequestProfileOpenRouterZDRChatV1}
	modelRoute := testRoute(t, "model", "")
	for _, test := range []struct {
		name      string
		normalize func() error
		want      provider.RouteTokenUsage
	}{
		{"responses with usage", func() error {
			_, err := normalizeResponse([]byte(responses+`,"usage":{"input_tokens":3000,"output_tokens":4096,"total_tokens":7096,"input_tokens_details":{"cached_tokens":100}}}`), route)
			return err
		}, known(3000, 4096, 100)},
		{"responses without usage", func() error { _, err := normalizeResponse([]byte(responses+`}`), route); return err }, unknown},
		{"responses with inconsistent usage", func() error {
			_, err := normalizeResponse([]byte(responses+`,"usage":{"input_tokens":3000,"output_tokens":4096,"total_tokens":1}}`), route)
			return err
		}, unknown},
		{"chat with usage", func() error {
			_, err := chatAdapter.normalizeProviderResponse([]byte(chat+`,"usage":{"prompt_tokens":3120,"completion_tokens":4096,"total_tokens":7216,"prompt_tokens_details":{"cached_tokens":120}}}`), route)
			return err
		}, known(3120, 4096, 120)},
		{"chat without usage", func() error { _, err := chatAdapter.normalizeProviderResponse([]byte(chat+`}`), route); return err }, unknown},
		{"ollama signin with usage", func() error {
			_, err := normalizeOllamaSigninResponse([]byte(ollamaSigninExhaustedResponse), ollamaSigninTestRoute(t, "nemotron-3-super:cloud"))
			return err
		}, known(3120, 4096, 0)},
		{"openrouter with usage", func() error {
			_, err := openRouter.normalizeProviderResponse(exhaustedBody(t, openRouterDocumentedChatResponse("model")), modelRoute)
			return err
		}, known(120, 30, 20)},
		{"opencode go with usage", func() error {
			_, err := normalizeOpenCodeGoResponse(exhaustedBody(t, []byte(goResponseFixture())), modelRoute)
			return err
		}, known(1200, 300, 0)},
		// The console profile withholds native usage from a successful reply too.
		{"opencode console withholds usage", func() error {
			_, err := normalizeOpenCodeConsoleResponse(exhaustedBody(t, []byte(consoleResponseFixture())), modelRoute)
			return err
		}, unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.normalize()
			if !errors.Is(err, errModelOutputExhausted) {
				t.Fatalf("classified as %v", err)
			}
			if got := exhaustedUsage(err); got != test.want {
				t.Fatalf("usage known=%t %d/%d/%d, want known=%t %d/%d/%d", got.IsKnown(), got.InputTokens(), got.OutputTokens(), got.CachedInputTokens(), test.want.IsKnown(), test.want.InputTokens(), test.want.OutputTokens(), test.want.CachedInputTokens())
			}
		})
	}
	if got := exhaustedUsage(ErrInvalidConfig); got.IsKnown() {
		t.Fatal("an error other than an exhausted reply carried usage")
	}
}

// TestExecuteKeepsUsageOfAnExhaustedReplyOnly requires the dispatch result of
// an exhausted reply to carry its reported usage, and every other failure,
// including an exhausted reply without usage and a transport failure, to keep
// unknown usage.
func TestExecuteKeepsUsageOfAnExhaustedReplyOnly(t *testing.T) {
	exhausted := `{"id":"resp-1","object":"response","status":"incomplete","model":"gpt-safe","output":[],"incomplete_details":{"reason":"max_output_tokens"}`
	for _, test := range []struct {
		name, body string
		status     int
		failure    gateway.RouteFailureClass
		known      bool
	}{
		{"exhausted with usage", exhausted + `,"usage":{"input_tokens":3000,"output_tokens":4096,"total_tokens":7096}}`, http.StatusOK, gateway.RouteFailureOutputExhausted, true},
		{"exhausted without usage", exhausted + `}`, http.StatusOK, gateway.RouteFailureOutputExhausted, false},
		{"server failure", `{"usage":{"input_tokens":3000,"output_tokens":4096,"total_tokens":7096}}`, http.StatusBadGateway, gateway.RouteFailureProviderServer, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(test.status)
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL, &credentialProvider{key: testKey(t)})
			result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 4096, testRequest(t))
			usage := result.Usage()
			if result.Status() != gateway.RouteDispatchFailed || result.Failure() != test.failure || result.Validate() != nil || usage.IsKnown() != test.known {
				t.Fatalf("result failure=%s known=%t", result.Failure(), usage.IsKnown())
			}
			if test.known && (usage.InputTokens() != 3000 || usage.OutputTokens() != 4096 || usage.CachedInputTokens() != 0) {
				t.Fatalf("usage=%d/%d/%d", usage.InputTokens(), usage.OutputTokens(), usage.CachedInputTokens())
			}
		})
	}
	// A transport failure has no response and so no usage.
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := closed.URL
	closed.Close()
	result := newTestAdapter(t, endpoint, &credentialProvider{key: testKey(t)}).execute(context.Background(), testRoute(t, "gpt-safe", ""), 4096, testRequest(t))
	if result.Status() != gateway.RouteDispatchFailed || result.Failure() != gateway.RouteFailureTransport || result.Usage().IsKnown() {
		t.Fatalf("transport failure=%s known=%t", result.Failure(), result.Usage().IsKnown())
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
