package runtimecatalog_test

import (
	"context"
	"net/http"
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

type consoleCountingResolver struct {
	credentials openai.APIKeyProvider
	calls       int
}

func (r *consoleCountingResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	r.calls++
	return r.credentials, nil
}

func TestOpenCodeConsoleCatalogRefusesStaleWitnessBeforeAnyResolver(t *testing.T) {
	configuration, inventory := consoleCallerRuntimePolicy(t)
	clock := &requiredClock{at: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	credentials := &brokeredCountingCredentials{}
	resolver := &consoleCountingResolver{credentials: credentials}
	if _, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, resolver, runtimecatalog.OpenAICatalogOptions{Clock: clock}); err == nil {
		t.Fatal("expired Console witness admitted")
	}
	if resolver.calls != 0 || credentials.calls != 0 {
		t.Fatal("stale Console witness reached resolver/key")
	}
}

func TestOpenCodeConsoleHandlerRefusesWrongRepositoryAndExpiryBeforeKey(t *testing.T) {
	for _, expired := range []bool{false, true} {
		configuration, inventory := consoleCallerRuntimePolicy(t)
		clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
		if expired {
			clock.at = time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC)
		}
		key, err := openai.NewAPIKey([]byte("synthetic-console-key"))
		requiredCheck(t, err)
		credentials := &brokeredCountingCredentials{key: key}
		transport := &consoleCallerTransport{t: t}
		catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, brokeredResolver{credentials}, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Transport: transport, Timeout: time.Minute}, HTTPClientIdentity: requiredDigest("console-denied-http")})
		requiredCheck(t, err)
		store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
		requiredCheck(t, err)
		ledger := audit.NewMemoryLedger()
		transport.ledger = ledger
		sanitizer := testsupport.NewCleanGenerationSanitizer()
		handler, err := modelhandler.NewGenerationHandler(store, catalog, ledger, clock, sanitizer.ExpectedBinaryDigests())
		requiredCheck(t, err)
		repository := "another-repository"
		if expired {
			repository = "repository-a"
		}
		scope, err := audit.NewReviewScope("tenant-a", repository, "console-denied-run")
		requiredCheck(t, err)
		request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
		if expired {
			clock.at = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil {
			t.Fatal("wrong-repository/expired Console handler admitted")
		}
		if credentials.calls != 0 || transport.calls != 0 {
			t.Fatal("denied Console handler reached key/HTTP")
		}
	}
}
