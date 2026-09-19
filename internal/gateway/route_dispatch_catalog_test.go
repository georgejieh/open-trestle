package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestRouteDispatcherCatalogResolvesAuthorizedAdapter(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: successfulDispatchResult(t)}
	catalog, err := NewRouteDispatcherCatalog([]RouteDispatcher{dispatcher})
	if err != nil {
		t.Fatal(err)
	}
	result, err := DispatchAuthorizedRouteFromCatalog(context.Background(), catalog, authorization, request)
	if err != nil || result.AuthorizationIdentity() != authorization.Identity() || dispatcher.calls != 1 {
		t.Fatalf("catalog dispatch = (%#v, %v), calls=%d", result, err, dispatcher.calls)
	}
	resolved, exists := catalog.Resolve(authorization.RouteReference().AdapterID())
	if !exists || resolved != dispatcher || catalog.Len() != 1 || catalog.Identity() == "" || catalog.Validate() != nil {
		t.Fatal("catalog did not round trip")
	}
	if fmt.Sprint(catalog) != "route dispatcher catalog" || fmt.Sprintf("%#v", catalog) != "gateway.RouteDispatcherCatalog{<redacted>}" {
		t.Fatalf("catalog formatting leaked: %v / %#v", catalog, catalog)
	}
}

func TestRouteDispatcherCatalogRejectsInvalidRegistrations(t *testing.T) {
	valid := &recordingRouteDispatcher{adapterID: "adapter"}
	for _, test := range []struct {
		name        string
		dispatchers []RouteDispatcher
		want        error
	}{
		{"empty", nil, ErrInvalidRouteDispatcherCatalog},
		{"nil", []RouteDispatcher{nil}, ErrInvalidRouteDispatcher},
		{"invalid id", []RouteDispatcher{&recordingRouteDispatcher{adapterID: "Bad"}}, provider.ErrInvalidAdapterID},
		{"duplicate", []RouteDispatcher{valid, valid}, ErrDuplicateRouteDispatcher},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewRouteDispatcherCatalog(test.dispatchers)
			if !errors.Is(err, test.want) || catalog.Len() != 0 {
				t.Fatalf("NewRouteDispatcherCatalog() = (%#v, %v), want %v", catalog, err, test.want)
			}
		})
	}
}

func TestDispatchAuthorizedRouteFromCatalogFailsBeforeContentRelease(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	other := &recordingRouteDispatcher{adapterID: "other-adapter", result: successfulDispatchResult(t)}
	catalog, _ := NewRouteDispatcherCatalog([]RouteDispatcher{other})
	result, err := DispatchAuthorizedRouteFromCatalog(context.Background(), catalog, authorization, request)
	if !errors.Is(err, ErrRouteDispatcherNotRegistered) || result.Identity() != "" || other.calls != 0 {
		t.Fatalf("missing adapter = (%#v, %v), calls=%d", result, err, other.calls)
	}
}

func TestRouteDispatcherCatalogIdentityIsPermutationStable(t *testing.T) {
	first := &recordingRouteDispatcher{adapterID: "adapter-a"}
	second := &recordingRouteDispatcher{adapterID: "adapter-b"}
	forward, err := NewRouteDispatcherCatalog([]RouteDispatcher{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NewRouteDispatcherCatalog([]RouteDispatcher{second, first})
	if err != nil {
		t.Fatal(err)
	}
	if forward.Identity() != reverse.Identity() {
		t.Fatal("equivalent dispatcher sets had different identities")
	}
	ids := forward.AdapterIDs()
	ids[0] = "changed"
	if forward.AdapterIDs()[0] != "adapter-a" {
		t.Fatal("adapter IDs were mutable")
	}
}

func TestRouteDispatcherCatalogIdentityBindsAdapterConfiguration(t *testing.T) {
	first := &recordingRouteDispatcher{adapterID: "adapter-a", configurationIdentity: strings.Repeat("a", 64)}
	second := &recordingRouteDispatcher{adapterID: "adapter-a", configurationIdentity: strings.Repeat("b", 64)}
	left, err := NewRouteDispatcherCatalog([]RouteDispatcher{first})
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewRouteDispatcherCatalog([]RouteDispatcher{second})
	if err != nil {
		t.Fatal(err)
	}
	if left.Identity() == right.Identity() {
		t.Fatal("catalog identity omitted adapter configuration")
	}
	invalid := &recordingRouteDispatcher{adapterID: "adapter-a", configurationIdentity: strings.Repeat("0", 64)}
	if catalog, err := NewRouteDispatcherCatalog([]RouteDispatcher{invalid}); !errors.Is(err, ErrInvalidRouteDispatcher) || catalog.Identity() != "" {
		t.Fatalf("catalog=(%#v,%v)", catalog, err)
	}
}
