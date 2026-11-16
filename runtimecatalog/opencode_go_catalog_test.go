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

type goCountingResolver struct {
	credentials openai.APIKeyProvider
	calls       int
}

func (r *goCountingResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	r.calls++
	return r.credentials, nil
}

func TestOpenCodeGoCatalogRefusesStaleWitnessBeforeAnyResolver(t *testing.T) {
	configuration, inventory := goCallerRuntimePolicy(t)
	clock := &requiredClock{at: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	credentials := &brokeredCountingCredentials{}
	resolver := &goCountingResolver{credentials: credentials}
	if _, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, resolver, runtimecatalog.OpenAICatalogOptions{Clock: clock}); err == nil {
		t.Fatal("expired Go witness admitted")
	}
	if resolver.calls != 0 || credentials.calls != 0 {
		t.Fatal("stale Go witness reached resolver/key")
	}
}

func TestOpenCodeGoHandlerRefusesWrongRepositoryAndExpiryBeforeKey(t *testing.T) {
	for _, expired := range []bool{false, true} {
		configuration, inventory := goCallerRuntimePolicy(t)
		clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
		if expired {
			clock.at = time.Date(2026, 10, 31, 23, 59, 59, 0, time.UTC)
		}
		key, err := openai.NewAPIKey([]byte("synthetic-go-key"))
		requiredCheck(t, err)
		credentials := &brokeredCountingCredentials{key: key}
		transport := &goCallerTransport{t: t}
		catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, brokeredResolver{credentials}, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Transport: transport, Timeout: time.Minute}, HTTPClientIdentity: requiredDigest("go-denied-http")})
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
		scope, err := audit.NewReviewScope("tenant-a", repository, "go-denied-run")
		requiredCheck(t, err)
		request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
		if expired {
			clock.at = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil {
			t.Fatal("wrong-repository/expired Go handler admitted")
		}
		if credentials.calls != 0 || transport.calls != 0 {
			t.Fatal("denied Go handler reached key/HTTP")
		}
	}
}
