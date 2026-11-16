package openai

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Every reply below is a synthetic fixture. A reply that stopped at the output
// limit with answer text that is not a complete JSON value (a review document
// the model did not finish) is an exhausted allowance on every profile, with
// the usage it reported kept as for a reply with no answer. A complete JSON
// value that happens to end with a length stop is still returned unchanged.

const (
	partialAnswer  = `"content":"{\"schema_version\":1,\"verdicts\":[{\"candidate_id\":\"c1\",\"outcome\":\"veri"`
	completeAnswer = `"content":"{\"schema_version\":1,\"candidates\":[]}"`
)

// lengthStopBody turns a successful fixture into a reply that stopped at the
// output limit with the given content member.
func lengthStopBody(t *testing.T, body []byte, content string) []byte {
	t.Helper()
	changed := strings.Replace(string(body), `"finish_reason":"stop"`, `"finish_reason":"length"`, 1)
	for _, answered := range []string{`"content":"{\"schema_version\":1,\"candidates\":[]}"`, `"content":"{\"summary\":\"ok\",\"findings\":[]}"`} {
		changed = strings.Replace(changed, answered, content, 1)
	}
	if !strings.Contains(changed, `"finish_reason":"length"`) || !strings.Contains(changed, content) {
		t.Fatalf("fixture did not become a length stop: %s", changed)
	}
	return []byte(changed)
}

type lengthStopProfile struct {
	name      string
	body      []byte
	normalize func([]byte) (provider.Response, error)
	usage     provider.RouteTokenUsage
}

func lengthStopProfiles(t *testing.T) []lengthStopProfile {
	t.Helper()
	known := func(input, output, cached uint64) provider.RouteTokenUsage {
		usage, err := provider.NewRouteTokenUsage(input, output, cached)
		if err != nil {
			t.Fatal(err)
		}
		return usage
	}
	modelRoute := testRoute(t, "model", "")
	signinRoute := ollamaSigninTestRoute(t, "model-a")
	generic := &Adapter{protocol: ProtocolChatCompletions}
	openRouterEndpointURL, err := url.Parse(openRouterEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	openRouterGeneric := &Adapter{protocol: ProtocolChatCompletions, endpoint: openRouterEndpointURL}
	chat := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"model-a","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"{\"schema_version\":1,\"candidates\":[]}"}}],"usage":{"prompt_tokens":3120,"completion_tokens":4096,"total_tokens":7216,"prompt_tokens_details":{"cached_tokens":120}}}`)
	signin := []byte(`{"id":"chatcmpl-12","object":"chat.completion","created":1794119300,"model":"model-a","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":1,\"candidates\":[]}","reasoning":"We need to check each candidate."},"finish_reason":"stop"}],"usage":{"prompt_tokens":3120,"completion_tokens":4096,"total_tokens":7216}}`)
	profiles := []lengthStopProfile{
		{"chat completions", chat, func(body []byte) (provider.Response, error) {
			return generic.normalizeProviderResponse(body, signinRoute)
		}, known(3120, 4096, 120)},
		{"ollama signin", signin, func(body []byte) (provider.Response, error) { return normalizeOllamaSigninResponse(body, signinRoute) }, known(3120, 4096, 0)},
		{"opencode go", []byte(goResponseFixture()), func(body []byte) (provider.Response, error) { return normalizeOpenCodeGoResponse(body, modelRoute) }, known(1200, 300, 0)},
		// The console profile withholds native usage from every reply.
		{"opencode console", []byte(consoleResponseFixture()), func(body []byte) (provider.Response, error) {
			return normalizeOpenCodeConsoleResponse(body, modelRoute)
		}, provider.NewUnknownRouteTokenUsage()},
		{"openrouter generic connection", openRouterDocumentedChatResponse("model"), func(body []byte) (provider.Response, error) {
			return openRouterGeneric.normalizeProviderResponse(body, modelRoute)
		}, known(120, 30, 20)},
	}
	for _, profile := range []RequestProfile{RequestProfileOpenRouterZDRChatV1, RequestProfileOpenRouterZDRChatV2} {
		adapter := &Adapter{protocol: ProtocolChatCompletions, requestProfile: profile}
		profiles = append(profiles, lengthStopProfile{"openrouter " + string(profile), openRouterDocumentedChatResponse("model"), func(body []byte) (provider.Response, error) {
			return adapter.normalizeProviderResponse(body, modelRoute)
		}, known(120, 30, 20)})
	}
	return profiles
}

func TestLengthStopWithPartialAnswerIsOutputExhaustedOnEveryProfile(t *testing.T) {
	for _, profile := range lengthStopProfiles(t) {
		t.Run(profile.name, func(t *testing.T) {
			if _, err := profile.normalize(profile.body); err != nil {
				t.Fatalf("the successful fixture was refused: %v", err)
			}
			_, err := profile.normalize(lengthStopBody(t, profile.body, partialAnswer))
			if !errors.Is(err, errModelOutputExhausted) {
				t.Fatalf("a length stop with a partial answer classified as %v", err)
			}
			if got := exhaustedUsage(err); got != profile.usage {
				t.Fatalf("usage known=%t %d/%d/%d, want known=%t %d/%d/%d", got.IsKnown(), got.InputTokens(), got.OutputTokens(), got.CachedInputTokens(), profile.usage.IsKnown(), profile.usage.InputTokens(), profile.usage.OutputTokens(), profile.usage.CachedInputTokens())
			}
		})
	}
}

func TestLengthStopWithCompleteJSONIsUnchangedOnEveryProfile(t *testing.T) {
	for _, profile := range lengthStopProfiles(t) {
		t.Run(profile.name, func(t *testing.T) {
			response, err := profile.normalize(lengthStopBody(t, profile.body, completeAnswer))
			if err != nil || response.FinishReason() != provider.ResponseFinishLength || response.PartCount() != 1 || response.Parts()[0].Kind() != provider.ResponsePartStructuredData || string(response.Parts()[0].Payload()) != `{"schema_version":1,"candidates":[]}` {
				t.Fatalf("a complete JSON answer at a length stop changed: err=%v", err)
			}
		})
	}
}

// A length stop whose partial answer is plain text, or a refusal, keeps its
// classification: plain text is exhausted, a refusal is returned as one.
func TestChatLengthStopWithTextOrRefusal(t *testing.T) {
	route := ollamaSigninTestRoute(t, "model-a")
	body := func(message string) []byte {
		return []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"model-a","choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant",` + message + `}}],"usage":{"prompt_tokens":1,"completion_tokens":4096,"total_tokens":4097}}`)
	}
	if _, err := normalizeChatResponse(body(`"content":"Let me look at each candidate in turn and"`), route); !errors.Is(err, errModelOutputExhausted) {
		t.Fatalf("a length stop with partial text classified as %v", err)
	}
	response, err := normalizeChatResponse(body(`"content":null,"refusal":"I cannot help with that."`), route)
	if err != nil || response.Parts()[0].Kind() != provider.ResponsePartRefusal {
		t.Fatalf("a length-stopped refusal changed: %v", err)
	}
}

func TestResponsesLengthStopWithPartialAnswerIsOutputExhausted(t *testing.T) {
	route := ollamaSigninTestRoute(t, "model-a")
	body := func(text string) []byte {
		return []byte(`{"id":"resp-1","object":"response","status":"incomplete","model":"model-a","output":[{"id":"msg-1","type":"message","status":"incomplete","role":"assistant","content":[{"type":"output_text","text":` + text + `}]}],"incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":3000,"output_tokens":4096,"total_tokens":7096,"input_tokens_details":{"cached_tokens":100}}}`)
	}
	_, err := normalizeResponse(body(`"{\"schema_version\":1,\"candidates\":[{\"title\":\"Zero"`), route)
	if !errors.Is(err, errModelOutputExhausted) {
		t.Fatalf("an incomplete response with a partial answer classified as %v", err)
	}
	if usage := exhaustedUsage(err); !usage.IsKnown() || usage.InputTokens() != 3000 || usage.OutputTokens() != 4096 || usage.CachedInputTokens() != 100 {
		t.Fatalf("usage lost: known=%t", usage.IsKnown())
	}
	response, err := normalizeResponse(body(`"{\"schema_version\":1,\"candidates\":[]}"`), route)
	if err != nil || response.FinishReason() != provider.ResponseFinishLength || response.Parts()[0].Kind() != provider.ResponsePartStructuredData {
		t.Fatalf("a complete JSON answer in an incomplete response changed: %v", err)
	}
}
