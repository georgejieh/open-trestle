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

// Provider refusal bodies in the shape a live Ollama daemon returned for an
// account without usage credit and for a retired cloud model. Their message
// text is untrusted and must never reach a result, record or log.
const (
	providerPaymentBody = `{"error":{"message":"Add usage credits or subscribe and save up to 66%: https://ollama.com/plans (ref: 0b6d)","type":"api_error","param":null,"code":null}}`
	providerRetiredBody = `{"error":{"message":"qwen3.5:397b was retired on September 25, 2026. Try glm-5.3-flash:cloud. (ref: 4c1e)","type":"api_error","param":null,"code":null}}`
	providerMissingBody = `{"error":{"message":"model \"qwen3.5:397b\" not found, try pulling it first","type":"api_error","param":null,"code":null}}`
)

var providerRefusalCanaries = []string{"usage credits", "ollama.com/plans", "retired on", "glm-5.3-flash", "not found", "pulling", "ref:"}

// TestExecuteClassifiesProviderRefusalsWithoutProviderText requires HTTP 402,
// 404 and 410 to become the closed refusal classes over both protocols, with
// no replay side effect, no usage and no Retry-After, and requires that none
// of the provider's message text appears in the result or its outcome.
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
// and requires it to close the body it does not read.
func TestHTTPFailureClassificationNamesEachProviderStatus(t *testing.T) {
	for _, test := range []struct {
		status  int
		failure gateway.RouteFailureClass
		safety  gateway.RouteReplaySafety
		retry   uint32
	}{
		{http.StatusUnauthorized, gateway.RouteFailureAuthentication, gateway.RouteReplayNoSideEffect, 0},
		{http.StatusPaymentRequired, gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect, 0},
		{http.StatusForbidden, gateway.RouteFailureAuthorization, gateway.RouteReplayNoSideEffect, 0},
		{http.StatusNotFound, gateway.RouteFailureModelUnavailable, gateway.RouteReplayNoSideEffect, 0},
		{http.StatusGone, gateway.RouteFailureModelRetired, gateway.RouteReplayNoSideEffect, 0},
		{http.StatusTooManyRequests, gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, 7000},
		{http.StatusInternalServerError, gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0},
		{http.StatusServiceUnavailable, gateway.RouteFailureProviderServer, gateway.RouteReplayOutcomeUnknown, 0},
		{http.StatusBadRequest, gateway.RouteFailureInvalidResponse, gateway.RouteReplayNoSideEffect, 0},
	} {
		t.Run(http.StatusText(test.status), func(t *testing.T) {
			body := &closeRecorder{Reader: strings.NewReader(providerPaymentBody)}
			response := &http.Response{StatusCode: test.status, Header: http.Header{"Retry-After": []string{"7"}}, Body: body}
			result := classifyHTTPFailure(response)
			if result.Failure() != test.failure || result.ReplaySafety() != test.safety || result.RetryAfterMilliseconds() != test.retry || result.Usage().IsKnown() || result.Validate() != nil || !body.closed {
				t.Fatalf("status %d = %s/%s retry %d closed=%t", test.status, result.Failure(), result.ReplaySafety(), result.RetryAfterMilliseconds(), body.closed)
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
