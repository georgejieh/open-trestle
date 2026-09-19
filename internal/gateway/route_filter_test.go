package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
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

func TestFilterCompatibleRouteRecordsRetainsEveryDecision(t *testing.T) {
	input := newContentLoggingInput(t, false)
	records := []ResolvedRouteRegistryRecord{
		newFilterResolvedRecord(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput),
		newFilterResolvedRecord(t, 7, provider.ProviderZoneBrokeredRemote, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput),
		newFilterResolvedRecord(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingEnabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput),
		newFilterResolvedRecord(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryPending, 128_000, 16_000, provider.ModelFeatureStructuredOutput),
		newFilterResolvedRecord(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000),
		newFilterResolvedRecord(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 127_999, 16_000, provider.ModelFeatureStructuredOutput),
		newFilterResolvedRecord(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 15_999, provider.ModelFeatureStructuredOutput),
	}

	result, err := FilterCompatibleRouteRecords(input, 7, records)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestIdentity() != input.RequestIdentity() || result.RegistryRevision() != 7 || len(result.CompatibleRecords()) != 1 || len(result.RejectedRoutes()) != 6 {
		t.Fatalf("filter counts = (%d, %d)", len(result.CompatibleRecords()), len(result.RejectedRoutes()))
	}
	gotReasons := make([]RouteRejectionReason, 0, 6)
	seen := map[string]bool{}
	for _, record := range result.CompatibleRecords() {
		seen[record.RouteRegistryRecord().Identity()] = true
	}
	for _, rejection := range result.RejectedRoutes() {
		gotReasons = append(gotReasons, rejection.Reason())
		seen[rejection.RecordIdentity()] = true
	}
	sort.Slice(gotReasons, func(i, j int) bool { return gotReasons[i] < gotReasons[j] })
	wantReasons := []RouteRejectionReason{RouteRejectedZone, RouteRejectedContentLogging, RouteRejectedNotApproved, RouteRejectedMissingFeature, RouteRejectedInsufficientContext, RouteRejectedInsufficientOutput}
	sort.Slice(wantReasons, func(i, j int) bool { return wantReasons[i] < wantReasons[j] })
	if !reflect.DeepEqual(gotReasons, wantReasons) || len(seen) != len(records) {
		t.Fatalf("rejections = %v, seen = %d", gotReasons, len(seen))
	}
}

func TestFilterCompatibleRouteRecordsCanonicalizesInputOrder(t *testing.T) {
	input := newContentLoggingInput(t, false)
	first := newFilterResolvedRecord(t, 3, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	second := newFilterResolvedRecord(t, 3, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 129_000, 16_000, provider.ModelFeatureStructuredOutput)
	forward, err := FilterCompatibleRouteRecords(input, 3, []ResolvedRouteRegistryRecord{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := FilterCompatibleRouteRecords(input, 3, []ResolvedRouteRegistryRecord{second, first})
	if err != nil {
		t.Fatal(err)
	}
	forwardIDs := routeFilterRecordIdentities(forward.CompatibleRecords())
	reverseIDs := routeFilterRecordIdentities(reverse.CompatibleRecords())
	if !reflect.DeepEqual(forwardIDs, reverseIDs) || !sort.StringsAreSorted(forwardIDs) {
		t.Fatalf("canonical identities = %v and %v", forwardIDs, reverseIDs)
	}
}

func TestFilterCompatibleRouteRecordsValidatesBoundsAndMembership(t *testing.T) {
	input := newContentLoggingInput(t, false)
	valid := newFilterResolvedRecord(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	otherRevision := newFilterResolvedRecord(t, 2, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	tooMany := make([]ResolvedRouteRegistryRecord, maxRouteFilterCandidates+1)
	for index := range tooMany {
		tooMany[index] = newFilterResolvedRecord(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, uint64(128_000+index), 16_000, provider.ModelFeatureStructuredOutput)
	}
	for _, test := range []struct {
		name     string
		input    ReviewRoutingInput
		revision uint64
		records  []ResolvedRouteRegistryRecord
		want     error
	}{
		{name: "input", revision: 1, want: ErrInvalidRequestIdentity},
		{name: "revision", input: input, want: ErrInvalidRouteFilterRevision},
		{name: "limit", input: input, revision: 1, records: tooMany, want: ErrTooManyRouteCandidates},
		{name: "invalid record", input: input, revision: 1, records: []ResolvedRouteRegistryRecord{{}}, want: provider.ErrInvalidRouteRegistryRevision},
		{name: "mixed revision", input: input, revision: 1, records: []ResolvedRouteRegistryRecord{otherRevision}, want: ErrRouteCandidateRevisionMismatch},
		{name: "duplicate", input: input, revision: 1, records: []ResolvedRouteRegistryRecord{valid, valid}, want: ErrDuplicateRouteCandidate},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := FilterCompatibleRouteRecords(test.input, test.revision, test.records)
			if !errors.Is(err, test.want) || result.RegistryRevision() != 0 || result.CompatibleRecords() != nil || result.RejectedRoutes() != nil {
				t.Fatalf("FilterCompatibleRouteRecords() = (%#v, %v), want %v", result, err, test.want)
			}
		})
	}
	empty, err := FilterCompatibleRouteRecords(input, 1, nil)
	if err != nil || empty.RequestIdentity() != input.RequestIdentity() || empty.RegistryRevision() != 1 || empty.CompatibleRecords() != nil || empty.RejectedRoutes() != nil {
		t.Fatalf("empty filter = (%#v, %v)", empty, err)
	}
	maximum, err := FilterCompatibleRouteRecords(input, 1, tooMany[:maxRouteFilterCandidates])
	if err != nil || len(maximum.CompatibleRecords()) != maxRouteFilterCandidates || maximum.RejectedRoutes() != nil {
		t.Fatalf("maximum filter = (%d, %d, %v)", len(maximum.CompatibleRecords()), len(maximum.RejectedRoutes()), err)
	}
}

func TestRouteFilterResultAccessorsAreDefensive(t *testing.T) {
	input := newContentLoggingInput(t, false)
	accepted := newFilterResolvedRecord(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	rejected := newFilterResolvedRecord(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryPending, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	result, err := FilterCompatibleRouteRecords(input, 1, []ResolvedRouteRegistryRecord{accepted, rejected})
	if err != nil {
		t.Fatal(err)
	}
	compatible := result.CompatibleRecords()
	rejections := result.RejectedRoutes()
	compatible[0] = ResolvedRouteRegistryRecord{}
	rejections[0] = RouteRejection{}
	if result.CompatibleRecords()[0].RouteRegistryRecord().Identity() != accepted.RouteRegistryRecord().Identity() || result.RejectedRoutes()[0].RecordIdentity() != rejected.RouteRegistryRecord().Identity() {
		t.Fatal("result accessors exposed mutable slices")
	}
}

func routeFilterRecordIdentities(records []ResolvedRouteRegistryRecord) []string {
	identities := make([]string, len(records))
	for index, record := range records {
		identities[index] = record.RouteRegistryRecord().Identity()
	}
	return identities
}

func TestRouteFilterFormattingRedactsRecordAndRequestIdentities(t *testing.T) {
	input := newContentLoggingInput(t, false)
	record := newFilterResolvedRecord(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryPending, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	result, err := FilterCompatibleRouteRecords(input, 1, []ResolvedRouteRegistryRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	rejection := result.RejectedRoutes()[0]
	for _, value := range []any{result, &result, rejection, &rejection} {
		for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, input.RequestIdentity()) || strings.Contains(formatted, record.RouteRegistryRecord().Identity()) {
				t.Fatalf("format %q exposed filter identity: %q", format, formatted)
			}
		}
	}
}
