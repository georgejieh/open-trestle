package policy

import (
	"errors"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestNewAllowedProviderZonesAllowsExactMembers(t *testing.T) {
	allowance, err := NewAllowedProviderZones(
		provider.ProviderZoneSubscriptionOAuth,
		provider.ProviderZoneLocal,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		zone provider.ProviderZone
		want bool
	}{
		{provider.ProviderZoneLocal, true},
		{provider.ProviderZonePrivateRemote, false},
		{provider.ProviderZoneBrokeredRemote, false},
		{provider.ProviderZoneSubscriptionOAuth, true},
		{provider.ProviderZone(99), false},
	} {
		if allowance.Allows(test.zone) != test.want {
			t.Fatalf("Allows(%v) = %t, want %t", test.zone, allowance.Allows(test.zone), test.want)
		}
	}
}

func TestAllowedProviderZonesIgnoreInputOrder(t *testing.T) {
	first, _ := NewAllowedProviderZones(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	second, _ := NewAllowedProviderZones(provider.ProviderZonePrivateRemote, provider.ProviderZoneLocal)
	if first != second {
		t.Fatalf("equal allowance sets differ: %#v %#v", first, second)
	}
}

func TestAllowedProviderZonesZeroAndEmptyDenyAll(t *testing.T) {
	empty, err := NewAllowedProviderZones()
	if err != nil || empty != (AllowedProviderZones{}) || empty.Validate() != nil {
		t.Fatalf("empty allowance = (%#v, %v)", empty, err)
	}
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if empty.Allows(zone) {
			t.Fatalf("empty allowance permits %v", zone)
		}
	}
	if empty.Allows(provider.ProviderZone(99)) {
		t.Fatal("empty allowance permits unknown zone")
	}
}

func TestNewAllowedProviderZonesRejectsDuplicateOrUnknownZones(t *testing.T) {
	for _, test := range []struct {
		name  string
		zones []provider.ProviderZone
		want  error
	}{
		{name: "duplicate", zones: []provider.ProviderZone{provider.ProviderZoneLocal, provider.ProviderZoneLocal}, want: ErrDuplicateProviderZone},
		{name: "zero", zones: []provider.ProviderZone{0}, want: provider.ErrInvalidProviderZone},
		{name: "unknown", zones: []provider.ProviderZone{99}, want: provider.ErrInvalidProviderZone},
		{name: "mixed", zones: []provider.ProviderZone{provider.ProviderZoneLocal, 99}, want: provider.ErrInvalidProviderZone},
	} {
		allowance, err := NewAllowedProviderZones(test.zones...)
		if !errors.Is(err, test.want) || allowance != (AllowedProviderZones{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, allowance, err, test.want)
		}
		for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
			if allowance.Allows(zone) {
				t.Fatalf("failed %s allowance permits %v", test.name, zone)
			}
		}
	}
}

func TestAllowedProviderZonesDoesNotRetainInput(t *testing.T) {
	zones := []provider.ProviderZone{provider.ProviderZoneLocal}
	allowance, _ := NewAllowedProviderZones(zones...)
	zones[0] = provider.ProviderZonePrivateRemote
	if !allowance.Allows(provider.ProviderZoneLocal) || allowance.Allows(provider.ProviderZonePrivateRemote) {
		t.Fatal("caller slice changed allowance")
	}
}

func TestAllowedProviderZonesForgedBitsFailValidation(t *testing.T) {
	allowance := AllowedProviderZones{zones: 1 << 7}
	if err := allowance.Validate(); !errors.Is(err, provider.ErrInvalidProviderZone) {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestAllowedProviderZonesSurfaceContainsOnlyZoneBits(t *testing.T) {
	typeOfAllowance := reflect.TypeOf(AllowedProviderZones{})
	if typeOfAllowance.NumField() != 1 || typeOfAllowance.Field(0).Name != "zones" || typeOfAllowance.Field(0).Type.Kind() != reflect.Uint8 {
		t.Fatalf("AllowedProviderZones surface = %v", typeOfAllowance)
	}
	if typeOfAllowance.NumMethod() != 2 {
		t.Fatalf("AllowedProviderZones methods = %d, want Allows and Validate", typeOfAllowance.NumMethod())
	}
}
