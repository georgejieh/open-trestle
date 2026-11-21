package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newFilterResolvedRecord(t *testing.T, revision uint64, zone provider.ProviderZone, logging provider.ContentLoggingMode, status provider.RouteRegistryStatus, contextTokens, outputTokens uint64, features ...provider.ModelFeature) ResolvedRouteRegistryRecord {
	t.Helper()
	manifest := []byte("route evidence manifest")
	digest := sha256.Sum256(manifest)
	candidate := newRouteCandidate(t, zone, logging, contextTokens, outputTokens, features...)
	record, err := provider.NewRouteRegistryRecord(revision, candidate, status, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveRouteRegistryRecord(context.Background(), record.Identity(), &routeRegistryReaderStub{record: record}, &routeEvidenceManifestReaderStub{content: manifest})
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestRouteRejectionReasonRoundTrips(t *testing.T) {
	reasons := []struct {
		reason RouteRejectionReason
		name   string
	}{
		{RouteRejectedZone, "zone_not_allowed"},
		{RouteRejectedContentLogging, "content_logging_not_allowed"},
		{RouteRejectedNotApproved, "not_approved"},
		{RouteRejectedMissingFeature, "missing_model_feature"},
		{RouteRejectedInsufficientContext, "insufficient_model_context"},
		{RouteRejectedInsufficientOutput, "insufficient_model_output"},
		{RouteRejectedUnhealthy, "route_unhealthy"},
		{RouteRejectedHealthUnknown, "route_health_unknown"},
		{RouteRejectedQuotaExhausted, "route_quota_exhausted"},
		{RouteRejectedQuotaUnknown, "route_quota_unknown"},
		{RouteRejectedUnknownPricing, "route_pricing_unknown"},
		{RouteRejectedCostBudget, "route_cost_exceeds_budget"},
	}
	for _, test := range reasons {
		parsed, err := ParseRouteRejectionReason(test.name)
		if err != nil || parsed != test.reason || parsed.String() != test.name || parsed.Validate() != nil {
			t.Fatalf("reason %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
	for _, value := range []string{"", "not_approved ", "NOT_APPROVED", "unknown"} {
		reason, err := ParseRouteRejectionReason(value)
		if !errors.Is(err, ErrInvalidRouteRejectionReason) || reason != 0 {
			t.Fatalf("ParseRouteRejectionReason(%q) = (%v, %v)", value, reason, err)
		}
	}
}
