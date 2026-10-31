package runtimecatalog_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

type consoleHTTPFailureTransport struct {
	delegate *consoleCallerTransport
	status   int
}

func (r consoleHTTPFailureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.delegate.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	response.StatusCode = r.status
	response.Body = io.NopCloser(strings.NewReader("PRIVATE_ERROR_BODY"))
	return response, nil
}

func TestOpenCodeConsoleHandlerHTTPFailuresNeverRetryOrPersistProviderBody(t *testing.T) {
	for _, status := range []int{401, 402, 403, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			ctx := context.Background()
			clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
			configuration, inventory := consoleCallerRuntimePolicy(t)
			key, err := openai.NewAPIKey([]byte("synthetic-console-key"))
			requiredCheck(t, err)
			credentials := &brokeredCountingCredentials{key: key}
			transport := &consoleCallerTransport{t: t}
			catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, brokeredResolver{credentials}, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Transport: consoleHTTPFailureTransport{transport, status}, Timeout: time.Minute}, HTTPClientIdentity: requiredDigest("console-error-http")})
			requiredCheck(t, err)
			store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
			requiredCheck(t, err)
			ledger := audit.NewMemoryLedger()
			transport.ledger = ledger
			sanitizer := testsupport.NewCleanGenerationSanitizer()
			handler, err := modelhandler.NewGenerationHandler(store, catalog, ledger, clock, sanitizer.ExpectedBinaryDigests())
			requiredCheck(t, err)
			scope, err := audit.NewReviewScope("tenant-a", "repository-a", "console-http-failure")
			requiredCheck(t, err)
			request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
			dependency, ok := request.DependencyOutput("context")
			if !ok {
				t.Fatal("context missing")
			}
			inputArtifact, err := store.Get(ctx, scope, dependency.OutputIdentity(), clock.Now())
			requiredCheck(t, err)
			input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
			requiredCheck(t, err)
			transport.scope, transport.authorization = scope, input.Authorization()
			completion := handler.Execute(ctx, request)
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil || transport.calls != 1 || credentials.calls != 1 {
				t.Fatal("error retried, succeeded or skipped authorized request")
			}
			events, err := ledger.Read(ctx, scope, 0, 20)
			requiredCheck(t, err)
			for _, event := range events {
				encoded, err := audit.EncodeEvent(event)
				requiredCheck(t, err)
				if strings.Contains(string(encoded), "PRIVATE_ERROR_BODY") {
					t.Fatal("provider body leaked")
				}
			}
		})
	}
}
