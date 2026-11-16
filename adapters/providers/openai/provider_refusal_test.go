package openai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

// Provider refusal bodies in the shape an Ollama daemon returns for an
// account without usage credit and for a retired cloud model. Their message
// text is untrusted and must never reach a result, record or log.
const (
	providerPaymentBody = `{"error":{"message":"Add usage credits or subscribe and save up to 66%: https://ollama.com/plans (ref: 0b6d)","type":"api_error","param":null,"code":null}}`
	providerRetiredBody = `{"error":{"message":"qwen3.5:397b was retired on September 25, 2026. Try glm-5.3-flash:cloud. (ref: 4c1e)","type":"api_error","param":null,"code":null}}`
	providerMissingBody = `{"error":{"message":"model \"qwen3.5:397b\" not found, try pulling it first","type":"api_error","param":null,"code":null}}`
	// providerRejectedBody is a synthetic body in the shape OpenRouter returns
	// for an unknown model ID with HTTP 400.
	providerRejectedBody = `{"error":{"message":"vendor/no-such-model is not a valid model ID","code":400}}`
)

var providerRefusalCanaries = []string{"usage credits", "ollama.com/plans", "retired on", "glm-5.3-flash", "not found", "pulling", "ref:", "no-such-model", "valid model ID"}

// TestExecuteClassifiesProviderRefusalsWithoutProviderText requires HTTP 402,
// 404 and 410, and a request rejected as invalid (400 and 422), to become the
// closed refusal classes over both protocols, with no replay side effect, no
// usage and no Retry-After, and requires that none of the provider's message
// text appears in the result or its outcome.
func TestExecuteClassifiesProviderRefusalsWithoutProviderText(t *testing.T) {
	for _, protocol := range []Protocol{ProtocolResponses, ProtocolChatCompletions} {
		for _, test := range []struct {
			name    string
			status  int
			body    string
			failure gateway.RouteFailureClass
		}{
			{"payment required", http.StatusPaymentRequired, providerPaymentBody, gateway.RouteFailurePaymentRequired},
			{"model unavailable", http.StatusNotFound, providerMissingBody, gateway.RouteFailureModelUnavailable},
			{"model retired", http.StatusGone, providerRetiredBody, gateway.RouteFailureModelRetired},
			{"request rejected", http.StatusBadRequest, providerRejectedBody, gateway.RouteFailureRequestRejected},
			{"request unprocessable", http.StatusUnprocessableEntity, providerRejectedBody, gateway.RouteFailureRequestRejected},
		} {
			t.Run(string(protocol)+"/"+test.name, func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					calls++
					writer.Header().Set("Content-Type", "application/json")
					writer.Header().Set("Retry-After", "30")
					writer.WriteHeader(test.status)
					_, _ = io.WriteString(writer, test.body)
				}))
				defer server.Close()
				adapter := newTestAdapter(t, server.URL+"/v1", &credentialProvider{key: testKey(t)})
				if protocol == ProtocolChatCompletions {
					useChatProtocol(adapter)
				}
				result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
				if calls != 1 || result.Status() != gateway.RouteDispatchFailed || result.Failure() != test.failure || result.ReplaySafety() != gateway.RouteReplayNoSideEffect || result.RetryAfterMilliseconds() != 0 || result.Usage().IsKnown() || result.Validate() != nil {
					t.Fatalf("calls=%d failure=%s safety=%s retry=%d", calls, result.Failure(), result.ReplaySafety(), result.RetryAfterMilliseconds())
				}
				assertNoProviderText(t, fmt.Sprintf("%v %+v %#v %s %s", result, result, result, result.Failure(), result.Identity()))
			})
		}
	}
}

// TestHTTPFailureClassificationNamesEachProviderStatus pins the one status
// classification every request profile uses, the OpenCode console included,
// and requires it to close the body it does not read. A 429, and a 503 that
// names a Retry-After, is a refusal before processing: it records known zero
// usage. Every other failure keeps unknown usage.
func TestHTTPFailureClassificationNamesEachProviderStatus(t *testing.T) {
	for _, test := range []struct {
		status     int
		retryAfter string
		failure    gateway.RouteFailureClass
		safety     gateway.RouteReplaySafety
		retry      uint32
		zero       bool
	}{
		{http.StatusUnauthorized, "7", gateway.RouteFailureAuthentication, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusPaymentRequired, "7", gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusForbidden, "7", gateway.RouteFailureAuthorization, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusNotFound, "7", gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusGone, "7", gateway.RouteFailureModelRetired, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusTooManyRequests, "7", gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 7000, true},
		{http.StatusTooManyRequests, "", gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 0, true},
		{http.StatusInternalServerError, "7", gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0, false},
		{http.StatusServiceUnavailable, "7", gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 7000, true},
		{http.StatusServiceUnavailable, "", gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0, false},
		{http.StatusServiceUnavailable, "Wed, 21 Oct 2026 07:28:00 GMT", gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0, false},
		{http.StatusServiceUnavailable, "0", gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0, false},
		// A request the provider rejects as invalid: malformed or with an
		// unknown model ID or parameter (400, 422), or a method or media type
		// the endpoint does not take (405, 415).
		{http.StatusBadRequest, "7", gateway.RouteFailureRequestRejected, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusMethodNotAllowed, "7", gateway.RouteFailureRequestRejected, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusUnsupportedMediaType, "7", gateway.RouteFailureRequestRejected, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusUnprocessableEntity, "7", gateway.RouteFailureRequestRejected, gateway.RouteReplayNoSideEffect, 0, false},
		// A status no class names, such as a conflict with resource state, is
		// still an unexpected answer, not a rejection of the request.
		{http.StatusConflict, "7", gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusNotAcceptable, "7", gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0, false},
		{http.StatusTeapot, "7", gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0, false},
	} {
		t.Run(http.StatusText(test.status)+"/"+test.retryAfter, func(t *testing.T) {
			body := &closeRecorder{Reader: strings.NewReader(providerPaymentBody)}
			response := &http.Response{StatusCode: test.status, Header: http.Header{"Retry-After": []string{test.retryAfter}}, Body: body}
			result := classifyHTTPFailure(response)
			usage := result.Usage()
			zero := usage.IsKnown() && usage.InputTokens() == 0 && usage.OutputTokens() == 0 && usage.CachedInputTokens() == 0
			if result.Failure() != test.failure || result.ReplaySafety() != test.safety || result.RetryAfterMilliseconds() != test.retry || usage.IsKnown() != test.zero || zero != test.zero || result.Validate() != nil || !body.closed {
				t.Fatalf("status %d = %s/%s retry %d known usage %t closed=%t", test.status, result.Failure(), result.ReplaySafety(), result.RetryAfterMilliseconds(), usage.IsKnown(), body.closed)
			}
		})
	}
}

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error {
	c.closed = true
	return nil
}

func assertNoProviderText(t *testing.T, text string) {
	t.Helper()
	for _, canary := range providerRefusalCanaries {
		if strings.Contains(text, canary) {
			t.Fatalf("provider text %q escaped into %q", canary, text)
		}
	}
}
