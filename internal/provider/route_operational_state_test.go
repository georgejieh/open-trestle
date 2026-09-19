package provider

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestRouteHealthRoundTrips(t *testing.T) {
	values := []struct {
		value RouteHealth
		name  string
	}{{RouteHealthHealthy, "healthy"}, {RouteHealthUnhealthy, "unhealthy"}, {RouteHealthUnknown, "unknown"}}
	for _, test := range values {
		parsed, err := ParseRouteHealth(test.name)
		if err != nil || parsed != test.value || parsed.String() != test.name || parsed.Validate() != nil {
			t.Fatalf("health %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
	for _, value := range []string{"", "healthy ", "HEALTHY", "degraded"} {
		parsed, err := ParseRouteHealth(value)
		if !errors.Is(err, ErrInvalidRouteHealth) || parsed != 0 {
			t.Fatalf("ParseRouteHealth(%q) = (%v, %v)", value, parsed, err)
		}
	}
}

func TestRouteQuotaRoundTrips(t *testing.T) {
	values := []struct {
		value RouteQuota
		name  string
	}{{RouteQuotaAvailable, "available"}, {RouteQuotaExhausted, "exhausted"}, {RouteQuotaUnknown, "unknown"}}
	for _, test := range values {
		parsed, err := ParseRouteQuota(test.name)
		if err != nil || parsed != test.value || parsed.String() != test.name || parsed.Validate() != nil {
			t.Fatalf("quota %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
	for _, value := range []string{"", "available ", "AVAILABLE", "limited"} {
		parsed, err := ParseRouteQuota(value)
		if !errors.Is(err, ErrInvalidRouteQuota) || parsed != 0 {
			t.Fatalf("ParseRouteQuota(%q) = (%v, %v)", value, parsed, err)
		}
	}
}

func TestNewRouteOperationalStateBindsObservation(t *testing.T) {
	record, _ := NewRouteRegistryRecord(1, mustRouteRegistryCandidate(t, ContentLoggingDisabled), RouteRegistryApproved, routeRegistryEvidenceDigest)
	state, err := NewRouteOperationalState(record.Identity(), 9, RouteHealthHealthy, RouteQuotaAvailable)
	if err != nil {
		t.Fatal(err)
	}
	if state.RecordIdentity() != record.Identity() || state.ObservationRevision() != 9 || state.Health() != RouteHealthHealthy || state.Quota() != RouteQuotaAvailable || state.Validate() != nil {
		t.Fatal("route operational state does not round trip")
	}
	copied := state
	if copied != state {
		t.Fatal("copied route operational state changed")
	}
}

func TestNewRouteOperationalStateRejectsInvalidValuesInOrder(t *testing.T) {
	record, _ := NewRouteRegistryRecord(1, mustRouteRegistryCandidate(t, ContentLoggingDisabled), RouteRegistryApproved, routeRegistryEvidenceDigest)
	for _, test := range []struct {
		name     string
		identity string
		revision uint64
		health   RouteHealth
		quota    RouteQuota
		want     error
	}{
		{name: "identity", revision: 1, health: RouteHealthHealthy, quota: RouteQuotaAvailable, want: ErrInvalidRouteOperationalRecordIdentity},
		{name: "revision", identity: record.Identity(), health: RouteHealthHealthy, quota: RouteQuotaAvailable, want: ErrInvalidRouteOperationalRevision},
		{name: "health", identity: record.Identity(), revision: 1, quota: RouteQuotaAvailable, want: ErrInvalidRouteHealth},
		{name: "quota", identity: record.Identity(), revision: 1, health: RouteHealthHealthy, want: ErrInvalidRouteQuota},
		{name: "identity first", want: ErrInvalidRouteOperationalRecordIdentity},
	} {
		state, err := NewRouteOperationalState(test.identity, test.revision, test.health, test.quota)
		if !errors.Is(err, test.want) || state != (RouteOperationalState{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, state, err, test.want)
		}
	}
}

func TestRouteOperationalStateSurfaceAndFormatting(t *testing.T) {
	record, _ := NewRouteRegistryRecord(1, mustRouteRegistryCandidate(t, ContentLoggingDisabled), RouteRegistryApproved, routeRegistryEvidenceDigest)
	state, _ := NewRouteOperationalState(record.Identity(), 1, RouteHealthHealthy, RouteQuotaAvailable)
	typeOfState := reflect.TypeOf(state)
	want := []string{"recordIdentity", "observationRevision", "health", "quota"}
	if typeOfState.NumField() != len(want) {
		t.Fatalf("RouteOperationalState has %d fields", typeOfState.NumField())
	}
	for index, name := range want {
		if field := typeOfState.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, state)
		if strings.Contains(formatted, record.Identity()) {
			t.Fatalf("format %q exposed record identity: %q", format, formatted)
		}
	}
}
