package model

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestSanitizedGenerationHandlerIdentityMatchesEnrolledHandler(t *testing.T) {
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 1)
	if err != nil {
		t.Fatal(err)
	}
	expected := review.ScannerBinaryDigests{HelperSHA256: strings.Repeat("a", 64)}
	handler, err := NewGenerationHandler(store, catalog, audit.NewMemoryLedger(), fixedClock{at: time.UnixMilli(1000)}, expected)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := SanitizedGenerationHandlerIdentity(catalog, expected)
	if err != nil || identity != handler.HandlerIdentity() {
		t.Fatalf("enrolled identity mismatch: %v", err)
	}
	legacy, err := newLegacyGenerationHandler(store, catalog, audit.NewMemoryLedger(), fixedClock{at: time.UnixMilli(1000)})
	if err != nil || identity == legacy.HandlerIdentity() {
		t.Fatal("sanitized identity aliases legacy handler")
	}
	for _, changed := range []review.ScannerBinaryDigests{{HelperSHA256: strings.Repeat("c", 64)}, {HelperSHA256: expected.HelperSHA256}} {
		current, err := SanitizedGenerationHandlerIdentity(catalog, changed)
		if err != nil || current == identity {
			t.Fatal("scanner lineage omitted")
		}
	}
	other, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{&recordingDispatcher{adapterID: "other-model", result: successfulProviderResult(t)}})
	if err != nil {
		t.Fatal(err)
	}
	current, err := SanitizedGenerationHandlerIdentity(other, expected)
	if err != nil || current == identity {
		t.Fatal("dispatcher lineage omitted")
	}
	if identity, err := SanitizedGenerationHandlerIdentity(gateway.RouteDispatcherCatalog{}, expected); !errors.Is(err, ErrInvalidGenerationHandler) || identity != "" {
		t.Fatal("invalid catalog admitted")
	}
	if dispatcher.calls != 0 {
		t.Fatal("identity observation dispatched provider")
	}
}
