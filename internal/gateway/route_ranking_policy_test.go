package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func rankingRouteReference(t *testing.T, model string) provider.RouteReference {
	t.Helper()
	reference, err := provider.NewRouteReference(provider.ProviderZoneLocal, "provider", "adapter", "connection", model, "Version")
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func TestRouteRankingPolicyRoundTripsAndDefendsPreferences(t *testing.T) {
	pin := rankingRouteReference(t, "Pinned")
	first := rankingRouteReference(t, "First")
	second := rankingRouteReference(t, "Second")
	policy, err := NewPinnedRouteRankingPolicy(pin, []provider.RouteReference{first, second})
	if err != nil {
		t.Fatal(err)
	}
	gotPin, ok := policy.PinnedRoute()
	if !ok || gotPin != pin || policy.Identity() == "" || policy.Validate() != nil {
		t.Fatal("ranking policy did not round trip")
	}
	preferences := policy.PreferredRoutes()
	if !reflect.DeepEqual(preferences, []provider.RouteReference{first, second}) {
		t.Fatalf("preferences = %#v", preferences)
	}
	preferences[0] = pin
	if policy.PreferredRoutes()[0] != first {
		t.Fatal("preferred route accessor exposed mutable slice")
	}
	copied := policy
	if copied.Identity() != policy.Identity() {
		t.Fatal("copied policy changed")
	}
}

func TestRouteRankingPolicyIdentityBindsPinAndPreferenceOrder(t *testing.T) {
	pin := rankingRouteReference(t, "Pinned")
	first := rankingRouteReference(t, "First")
	second := rankingRouteReference(t, "Second")
	base, _ := NewRouteRankingPolicy([]provider.RouteReference{first, second})
	reversed, _ := NewRouteRankingPolicy([]provider.RouteReference{second, first})
	pinned, _ := NewPinnedRouteRankingPolicy(pin, []provider.RouteReference{first, second})
	empty, _ := NewRouteRankingPolicy(nil)
	identities := map[string]bool{base.Identity(): true, reversed.Identity(): true, pinned.Identity(): true, empty.Identity(): true}
	if len(identities) != 4 {
		t.Fatalf("policy identities collided: %#v", identities)
	}
	if _, ok := empty.PinnedRoute(); ok || empty.PreferredRoutes() != nil || empty.Validate() != nil {
		t.Fatal("empty policy is not canonical")
	}
}

func TestRouteRankingPolicyRejectsInvalidAndDuplicateRoutes(t *testing.T) {
	valid := rankingRouteReference(t, "Valid")
	tooMany := make([]provider.RouteReference, maxRouteRankingPreferences+1)
	for index := range tooMany {
		tooMany[index] = rankingRouteReference(t, fmt.Sprintf("Model-%d", index))
	}
	for _, test := range []struct {
		name        string
		pinned      bool
		pin         provider.RouteReference
		preferences []provider.RouteReference
		want        error
	}{
		{name: "invalid preference", preferences: []provider.RouteReference{{}}, want: provider.ErrInvalidProviderZone},
		{name: "duplicate preference", preferences: []provider.RouteReference{valid, valid}, want: ErrDuplicateRoutePreference},
		{name: "too many", preferences: tooMany, want: ErrTooManyRoutePreferences},
		{name: "invalid pin", pinned: true, want: provider.ErrInvalidProviderZone},
		{name: "pin repeated", pinned: true, pin: valid, preferences: []provider.RouteReference{valid}, want: ErrPinnedRouteRepeatedInPreferences},
	} {
		t.Run(test.name, func(t *testing.T) {
			var policy RouteRankingPolicy
			var err error
			if test.pinned {
				policy, err = NewPinnedRouteRankingPolicy(test.pin, test.preferences)
			} else {
				policy, err = NewRouteRankingPolicy(test.preferences)
			}
			if !errors.Is(err, test.want) || policy.Identity() != "" {
				t.Fatalf("ranking policy constructor = (%#v, %v), want %v", policy, err, test.want)
			}
		})
	}
	if err := (RouteRankingPolicy{}).Validate(); !errors.Is(err, ErrInvalidRouteRankingPolicyIdentity) {
		t.Fatalf("zero policy Validate() = %v", err)
	}
}

func TestRouteRankingPolicyFormattingRedactsRoutes(t *testing.T) {
	reference := rankingRouteReference(t, "Sensitive-Model")
	policy, _ := NewPinnedRouteRankingPolicy(reference, nil)
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, policy)
		if strings.Contains(formatted, "Sensitive-Model") || strings.Contains(formatted, "connection") {
			t.Fatalf("format %q exposed route: %q", format, formatted)
		}
	}
}
