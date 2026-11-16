package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// stallingBodyHandler sends success headers and a partial body, then stalls until released.
func stallingBodyHandler(release <-chan struct{}) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Content-Length", "4096")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"id":`))
		writer.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}
}

func TestExecuteClassifiesBodyReadTimeoutAsTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(stallingBodyHandler(release))
	defer server.Close()
	defer close(release)
	adapter, err := New(Config{
		AdapterID:          "openai-responses",
		ProviderID:         "openai",
		ConnectionID:       "primary/openai",
		Zone:               provider.ProviderZoneLocal,
		ContentLoggingMode: provider.ContentLoggingDisabled,
		Endpoint:           server.URL,
		Credentials:        &credentialProvider{key: testKey(t)},
		CredentialIdentity: strings.Repeat("a", 64),
		HTTPClient:         &http.Client{Timeout: 200 * time.Millisecond},
		HTTPClientIdentity: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureTimeout || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown {
		t.Fatalf("body-read timeout = (%s, %s), want (timeout, outcome_unknown)", result.Failure(), result.ReplaySafety())
	}
}

func TestExecuteClassifiesBodyReadCancellationAsCancelled(t *testing.T) {
	release := make(chan struct{})
	headersSent := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "4096")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"id":`))
		writer.(http.Flusher).Flush()
		close(headersSent)
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}))
	defer server.Close()
	defer close(release)
	adapter := newTestAdapter(t, server.URL, &credentialProvider{key: testKey(t)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-headersSent
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	result := adapter.execute(ctx, testRoute(t, "gpt-safe", ""), 100, testRequest(t))
	if result.Failure() != gateway.RouteFailureCancelled || result.ReplaySafety() != gateway.RouteReplayOutcomeUnknown {
		t.Fatalf("body-read cancellation = (%s, %s), want (cancelled, outcome_unknown)", result.Failure(), result.ReplaySafety())
	}
}

func TestNormalizeResponseRejectsInvalidUTF8(t *testing.T) {
	valid := successfulResponse("gpt-safe")
	body := strings.Replace(valid, `\"summary\":\"ok\"`, "\\\"summary\\\":\\\"o\xffk\\\"", 1)
	if body == valid {
		t.Fatal("fixture replacement did not apply")
	}
	if _, err := normalizeResponse([]byte(valid), testRoute(t, "gpt-safe", "")); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	if response, err := normalizeResponse([]byte(body), testRoute(t, "gpt-safe", "")); err == nil {
		t.Fatalf("Responses normalizer accepted invalid UTF-8 and rewrote content to %q", response.Parts()[0].Payload())
	}
}
