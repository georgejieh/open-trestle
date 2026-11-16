package openai

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// The default client gives each request two minutes per 4096 tokens of its
// output allowance, from two to five minutes, so a larger review output
// allowance is not cut off by a fixed two-minute timeout.
func TestDefaultClientRequestTimeoutScalesWithTheOutputAllowance(t *testing.T) {
	for allowance, want := range map[uint32]time.Duration{
		1: 2 * time.Minute, 4096: 2 * time.Minute, 6144: 3 * time.Minute, 8192: 4 * time.Minute,
		10240: 5 * time.Minute, 16384: 5 * time.Minute, ^uint32(0): 5 * time.Minute,
	} {
		if got := DefaultClientRequestTimeout(allowance); got != want {
			t.Fatalf("DefaultClientRequestTimeout(%d) = %s, want %s", allowance, got, want)
		}
	}
}

// deadlineTransport records the deadline of each request's context and
// answers with a fixed reply.
type deadlineTransport struct {
	remaining []time.Duration
	reply     string
}

func (d *deadlineTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, ok := request.Context().Deadline()
	if !ok {
		d.remaining = append(d.remaining, 0)
	} else {
		d.remaining = append(d.remaining, time.Until(deadline))
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(d.reply)), Request: request}, nil
}

func TestDefaultClientGivesEachRequestTheDeadlineOfItsAllowance(t *testing.T) {
	adapter := newTestAdapter(t, "http://127.0.0.1:9/v1", &credentialProvider{key: testKey(t)})
	if adapter.httpClient.Timeout != maximumRequestTimeout || !adapter.scaledTimeout {
		t.Fatalf("default client timeout %s scaled=%t", adapter.httpClient.Timeout, adapter.scaledTimeout)
	}
	transport := &deadlineTransport{reply: successfulResponse("gpt-safe")}
	adapter.httpClient.Transport = transport
	for _, allowance := range []uint32{4096, 16384} {
		if result := adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), allowance, testRequest(t)); result.Status() != gateway.RouteDispatchSucceeded {
			t.Fatalf("allowance %d: %s", allowance, result.Failure())
		}
	}
	if len(transport.remaining) != 2 || transport.remaining[0] > 2*time.Minute || transport.remaining[0] < 2*time.Minute-time.Minute/2 || transport.remaining[1] > 5*time.Minute || transport.remaining[1] < 5*time.Minute-time.Minute/2 {
		t.Fatalf("request deadlines %v", transport.remaining)
	}
	// A caller's earlier deadline still wins.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adapter.execute(ctx, testRoute(t, "gpt-safe", ""), 16384, testRequest(t))
	if last := transport.remaining[len(transport.remaining)-1]; last > 30*time.Second {
		t.Fatalf("the caller's deadline was extended to %s", last)
	}
}

// A configured client keeps its own timeout and gets no other deadline.
func TestConfiguredClientKeepsItsOwnTimeout(t *testing.T) {
	transport := &deadlineTransport{reply: successfulResponse("gpt-safe")}
	adapter, err := New(Config{
		AdapterID: "openai-responses", ProviderID: "openai", ConnectionID: "primary/openai", Zone: provider.ProviderZoneLocal,
		ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "http://127.0.0.1:9/v1", Credentials: &credentialProvider{key: testKey(t)}, CredentialIdentity: strings.Repeat("a", 64),
		HTTPClient: &http.Client{Transport: transport, Timeout: 90 * time.Second}, HTTPClientIdentity: strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.scaledTimeout || adapter.httpClient.Timeout != 90*time.Second {
		t.Fatalf("configured client changed: timeout %s scaled=%t", adapter.httpClient.Timeout, adapter.scaledTimeout)
	}
	adapter.execute(context.Background(), testRoute(t, "gpt-safe", ""), 16384, testRequest(t))
	// Only the client's own 90-second timeout bounds the request.
	if len(transport.remaining) != 1 || transport.remaining[0] > 90*time.Second || transport.remaining[0] < 60*time.Second {
		t.Fatalf("a configured client got another deadline: %v", transport.remaining)
	}
}
