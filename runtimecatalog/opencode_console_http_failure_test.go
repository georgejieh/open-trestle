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
	"github.com/georgejieh/open-trestle/internal/gateway"
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

// classRecordingDispatcher keeps the console adapter's proof-bearing dispatch
// and records the closed failure class of each result it returns.
type classRecordingDispatcher struct {
	modelhandler.SanitizedRouteDispatcher
	failures *[]gateway.RouteFailureClass
}

func (d classRecordingDispatcher) DispatchSanitizedRoute(ctx context.Context, request gateway.RouteDispatchRequest, proof modelhandler.SanitizedDispatchProof) gateway.RouteDispatchResult {
	result := d.SanitizedRouteDispatcher.DispatchSanitizedRoute(ctx, request, proof)
	*d.failures = append(*d.failures, result.Failure())
	return result
}

// recordConsoleFailures wraps every console dispatcher of catalog; the
// wrapped catalog keeps each adapter and configuration identity.
func recordConsoleFailures(t *testing.T, catalog gateway.RouteDispatcherCatalog) (gateway.RouteDispatcherCatalog, *[]gateway.RouteFailureClass) {
	t.Helper()
	failures := &[]gateway.RouteFailureClass{}
	dispatchers := []gateway.RouteDispatcher{}
	for _, id := range catalog.AdapterIDs() {
		dispatcher, ok := catalog.Resolve(id)
		sanitized, isSanitized := dispatcher.(modelhandler.SanitizedRouteDispatcher)
		if !ok || !isSanitized {
			t.Fatal("console dispatcher lost its sanitized dispatch")
		}
		dispatchers = append(dispatchers, classRecordingDispatcher{sanitized, failures})
	}
	wrapped, err := gateway.NewRouteDispatcherCatalog(dispatchers)
	requiredCheck(t, err)
	if wrapped.Identity() != catalog.Identity() {
		t.Fatal("recording changed the catalog identity")
	}
	return wrapped, failures
}

// Each console HTTP failure is classified by its status alone, as for every
// other profile: 402 is a payment refusal, not a spent local budget, and a
// status no class names is a refused reply. Only a 429, which the provider
// refused before processing, is retried, twice on the same route; no
// provider body is persisted.
func TestOpenCodeConsoleHandlerHTTPFailuresRetryOnlyRateLimitsAndPersistNoProviderBody(t *testing.T) {
	for _, test := range []struct {
		status  int
		failure gateway.RouteFailureClass
		run     controlplane.RunFailure
		reason  controlplane.TaskFailureReason
	}{
		{401, gateway.RouteFailureAuthentication, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderAuthenticationFailed},
		{402, gateway.RouteFailurePaymentRequired, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderPaymentRequired},
		{403, gateway.RouteFailureAuthorization, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderAuthorizationDenied},
		{404, gateway.RouteFailureModelUnavailable, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderModelUnavailable},
		{410, gateway.RouteFailureModelRetired, controlplane.RunFailurePolicy, controlplane.TaskFailureReasonProviderModelRetired},
		{429, gateway.RouteFailureRateLimited, controlplane.RunFailureTransient, controlplane.TaskFailureReasonProviderRateLimited},
		{400, gateway.RouteFailureInvalidResponse, controlplane.RunFailureInternal, controlplane.TaskFailureReasonProviderResponseInvalid},
		{500, gateway.RouteFailureProviderServer, controlplane.RunFailureTransient, 0},
	} {
		status := test.status
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
			catalog, failures := recordConsoleFailures(t, catalog)
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
			sent := 1
			if status == http.StatusTooManyRequests {
				sent = 3
			}
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil || transport.calls != sent || credentials.calls != sent {
				t.Fatalf("status %d sent %d requests with %d credentials, want %d", status, transport.calls, credentials.calls, sent)
			}
			if len(*failures) != sent || (*failures)[sent-1] != test.failure || completion.Failure() != test.run || completion.FailureReason() != test.reason {
				t.Fatalf("status %d classified %v, task failure %s reason %s; want %s, %s, %s", status, *failures, completion.Failure(), completion.FailureReason(), test.failure, test.run, test.reason)
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
