package gateway

import (
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newRouteRegistryRecord(t *testing.T, zone provider.ProviderZone, logging provider.ContentLoggingMode, status provider.RouteRegistryStatus, contextTokens, outputTokens uint64, features ...provider.ModelFeature) provider.RouteRegistryRecord {
	t.Helper()
	candidate := newRouteCandidate(t, zone, logging, contextTokens, outputTokens, features...)
	record, err := provider.NewRouteRegistryRecord(1, candidate, status, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestCheckRouteRegistryRecordCompatibilityAcceptsApprovedCompatibleRecord(t *testing.T) {
	input := newContentLoggingInput(t, false)
	record := newRouteRegistryRecord(t, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	if err := CheckRouteRegistryRecordCompatibility(input, record); err != nil {
		t.Fatalf("CheckRouteRegistryRecordCompatibility() = %v", err)
	}
}

func TestCheckRouteRegistryRecordCompatibilityUsesFailClosedOrder(t *testing.T) {
	input := newContentLoggingInput(t, false)
	for _, test := range []struct {
		name    string
		zone    provider.ProviderZone
		logging provider.ContentLoggingMode
		status  provider.RouteRegistryStatus
		want    error
	}{
		{name: "zone before logging approval and capability", zone: provider.ProviderZoneBrokeredRemote, logging: provider.ContentLoggingEnabled, status: provider.RouteRegistryPending, want: ErrRouteZoneNotAllowed},
		{name: "logging before approval and capability", zone: provider.ProviderZoneLocal, logging: provider.ContentLoggingEnabled, status: provider.RouteRegistryPending, want: ErrRouteContentLoggingNotAllowed},
		{name: "approval before capability", zone: provider.ProviderZoneLocal, logging: provider.ContentLoggingDisabled, status: provider.RouteRegistryPending, want: ErrRouteRegistryRecordNotApproved},
		{name: "capability", zone: provider.ProviderZoneLocal, logging: provider.ContentLoggingDisabled, status: provider.RouteRegistryApproved, want: provider.ErrMissingModelFeature},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := newRouteRegistryRecord(t, test.zone, test.logging, test.status, 1, 1)
			if err := CheckRouteRegistryRecordCompatibility(input, record); err != test.want {
				t.Fatalf("CheckRouteRegistryRecordCompatibility() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCheckRouteRegistryRecordCompatibilityRejectsEveryUnapprovedStatus(t *testing.T) {
	input := newContentLoggingInput(t, false)
	for _, status := range []provider.RouteRegistryStatus{provider.RouteRegistryPending, provider.RouteRegistryDegraded, provider.RouteRegistryDisabled} {
		record := newRouteRegistryRecord(t, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, status, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
		if err := CheckRouteRegistryRecordCompatibility(input, record); err != ErrRouteRegistryRecordNotApproved {
			t.Fatalf("status %q = %v", status, err)
		}
	}
}

func TestCheckRouteRegistryRecordCompatibilityValidatesInputBeforeRecord(t *testing.T) {
	validInput := newContentLoggingInput(t, false)
	validRecord := newRouteRegistryRecord(t, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	for _, test := range []struct {
		name   string
		input  ReviewRoutingInput
		record provider.RouteRegistryRecord
		want   error
	}{
		{name: "input", record: validRecord, want: ErrInvalidRequestIdentity},
		{name: "record", input: validInput, want: provider.ErrInvalidRouteRegistryRevision},
		{name: "input first", want: ErrInvalidRequestIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := CheckRouteRegistryRecordCompatibility(test.input, test.record); !errors.Is(err, test.want) {
				t.Fatalf("CheckRouteRegistryRecordCompatibility() = %v, want %v", err, test.want)
			}
		})
	}
}
