package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newOperationalEligibilityFixture(t *testing.T) ResolvedRouteRegistryRecord {
	t.Helper()
	return newFilterResolvedRecord(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
}

func TestCheckRouteOperationalEligibilityAcceptsExplicitReadiness(t *testing.T) {
	resolved := newOperationalEligibilityFixture(t)
	state, err := provider.NewRouteOperationalState(resolved.RouteRegistryRecord().Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckRouteOperationalEligibility(resolved, state); err != nil {
		t.Fatalf("CheckRouteOperationalEligibility() = %v", err)
	}
}

func TestCheckRouteOperationalEligibilityRejectsEveryNonReadyState(t *testing.T) {
	resolved := newOperationalEligibilityFixture(t)
	for _, test := range []struct {
		name   string
		health provider.RouteHealth
		quota  provider.RouteQuota
		want   error
	}{
		{name: "unhealthy", health: provider.RouteHealthUnhealthy, quota: provider.RouteQuotaAvailable, want: ErrRouteUnhealthy},
		{name: "health unknown", health: provider.RouteHealthUnknown, quota: provider.RouteQuotaAvailable, want: ErrRouteHealthUnknown},
		{name: "quota exhausted", health: provider.RouteHealthHealthy, quota: provider.RouteQuotaExhausted, want: ErrRouteQuotaExhausted},
		{name: "quota unknown", health: provider.RouteHealthHealthy, quota: provider.RouteQuotaUnknown, want: ErrRouteQuotaUnknown},
		{name: "health before quota", health: provider.RouteHealthUnhealthy, quota: provider.RouteQuotaExhausted, want: ErrRouteUnhealthy},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, err := provider.NewRouteOperationalState(resolved.RouteRegistryRecord().Identity(), 1, test.health, test.quota)
			if err != nil {
				t.Fatal(err)
			}
			if err := CheckRouteOperationalEligibility(resolved, state); err != test.want {
				t.Fatalf("CheckRouteOperationalEligibility() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCheckRouteOperationalEligibilityRejectsCrossWiredState(t *testing.T) {
	resolved := newOperationalEligibilityFixture(t)
	other := newFilterResolvedRecord(t, 2, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	state, _ := provider.NewRouteOperationalState(other.RouteRegistryRecord().Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	if err := CheckRouteOperationalEligibility(resolved, state); err != ErrRouteOperationalIdentityMismatch {
		t.Fatalf("CheckRouteOperationalEligibility() = %v", err)
	}
}

func TestCheckRouteOperationalEligibilityValidatesValuesInOrder(t *testing.T) {
	resolved := newOperationalEligibilityFixture(t)
	validState, _ := provider.NewRouteOperationalState(resolved.RouteRegistryRecord().Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	for _, test := range []struct {
		name     string
		resolved ResolvedRouteRegistryRecord
		state    provider.RouteOperationalState
		want     error
	}{
		{name: "record", state: validState, want: provider.ErrInvalidRouteRegistryRevision},
		{name: "state", resolved: resolved, want: provider.ErrInvalidRouteOperationalRecordIdentity},
		{name: "record first", want: provider.ErrInvalidRouteRegistryRevision},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckRouteOperationalEligibility(test.resolved, test.state); !errors.Is(err, test.want) {
				t.Fatalf("CheckRouteOperationalEligibility() = %v, want %v", err, test.want)
			}
		})
	}
}
