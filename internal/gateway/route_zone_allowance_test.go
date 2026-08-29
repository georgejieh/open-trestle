package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func newZoneCheckInput(t *testing.T, zones ...provider.ProviderZone) ReviewRoutingInput {
	t.Helper()
	request, requirements, _ := newRoutingFixture(t, []byte("payload"))
	allowance, err := policy.NewAllowedProviderZones(zones...)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, allowance, false)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewReviewRoutingInput(request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func newZoneCheckRoute(t *testing.T, zone provider.ProviderZone) provider.RouteReference {
	t.Helper()
	route, err := provider.NewRouteReference(zone, "provider", "adapter", "sentinel-connection", "SentinelModel", "")
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func TestValidateRouteZoneAllowanceAcceptsNamedZone(t *testing.T) {
	input := newZoneCheckInput(t, provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	for _, zone := range []provider.ProviderZone{provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote} {
		if err := ValidateRouteZoneAllowance(input, newZoneCheckRoute(t, zone)); err != nil {
			t.Fatalf("ValidateRouteZoneAllowance(%v) = %v", zone, err)
		}
	}
}

func TestValidateRouteZoneAllowanceRejectsUnlistedZone(t *testing.T) {
	input := newZoneCheckInput(t, provider.ProviderZoneLocal)
	err := ValidateRouteZoneAllowance(input, newZoneCheckRoute(t, provider.ProviderZoneBrokeredRemote))
	if err != ErrRouteZoneNotAllowed {
		t.Fatalf("ValidateRouteZoneAllowance() = %v", err)
	}
	if strings.Contains(err.Error(), "sentinel") || strings.Contains(err.Error(), "Sentinel") {
		t.Fatalf("zone denial exposed route labels: %v", err)
	}
}

func TestValidateRouteZoneAllowanceDenyAllRejectsEveryZone(t *testing.T) {
	input := newZoneCheckInput(t)
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if err := ValidateRouteZoneAllowance(input, newZoneCheckRoute(t, zone)); err != ErrRouteZoneNotAllowed {
			t.Fatalf("zone %v denial = %v", zone, err)
		}
	}
}

func TestValidateRouteZoneAllowanceRejectsInvalidValuesInOrder(t *testing.T) {
	validInput := newZoneCheckInput(t, provider.ProviderZoneLocal)
	validRoute := newZoneCheckRoute(t, provider.ProviderZoneLocal)
	for _, test := range []struct {
		name  string
		input ReviewRoutingInput
		route provider.RouteReference
		want  error
	}{
		{name: "input", route: validRoute, want: ErrInvalidRequestIdentity},
		{name: "route", input: validInput, want: provider.ErrInvalidProviderZone},
		{name: "input first", want: ErrInvalidRequestIdentity},
	} {
		if err := ValidateRouteZoneAllowance(test.input, test.route); !errors.Is(err, test.want) {
			t.Fatalf("%s = %v, want %v", test.name, err, test.want)
		}
	}
}
