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

func newObservedRoute(t *testing.T, revision uint64, zone provider.ProviderZone, logging provider.ContentLoggingMode, status provider.RouteRegistryStatus, pricing provider.RoutePricing, health provider.RouteHealth, quota provider.RouteQuota, contextTokens, outputTokens uint64, features ...provider.ModelFeature) ObservedRouteCandidate {
	t.Helper()
	return newObservedRouteWithQuality(t, revision, zone, logging, status, pricing, provider.RouteQualityTier1, health, quota, contextTokens, outputTokens, features...)
}

func newObservedRouteWithQuality(t *testing.T, revision uint64, zone provider.ProviderZone, logging provider.ContentLoggingMode, status provider.RouteRegistryStatus, pricing provider.RoutePricing, quality provider.RouteQualityTier, health provider.RouteHealth, quota provider.RouteQuota, contextTokens, outputTokens uint64, features ...provider.ModelFeature) ObservedRouteCandidate {
	t.Helper()
	manifest := []byte("observed route evidence")
	digest := sha256.Sum256(manifest)
	capability := newRouteCompatibilityDeclaration(t, zone, contextTokens, outputTokens, features...)
	candidate, err := provider.NewRouteCandidateDeclaration(capability, logging, pricing, quality)
	if err != nil {
		t.Fatal(err)
	}
	record, err := provider.NewRouteRegistryRecord(revision, candidate, status, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveRouteRegistryRecord(context.Background(), record.Identity(), &routeRegistryReaderStub{record: record}, &routeEvidenceManifestReaderStub{content: manifest})
	if err != nil {
		t.Fatal(err)
	}
	state, err := provider.NewRouteOperationalState(record.Identity(), 1, health, quota)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := NewObservedRouteCandidate(resolved, state)
	if err != nil {
		t.Fatal(err)
	}
	return observed
}

func TestNewObservedRouteCandidateBindsMatchingState(t *testing.T) {
	free, _ := provider.NewRoutePricing(0, 0)
	observed := newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	if observed.ResolvedRecord().RouteRegistryRecord().Identity() != observed.OperationalState().RecordIdentity() || observed.Validate() != nil {
		t.Fatal("observed route candidate does not round trip")
	}
	copied := observed
	if copied != observed {
		t.Fatal("copied observed route changed")
	}
}

func TestNewObservedRouteCandidateRejectsCrossWiredState(t *testing.T) {
	free, _ := provider.NewRoutePricing(0, 0)
	first := newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	second := newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 129_000, 16_000, provider.ModelFeatureStructuredOutput)
	observed, err := NewObservedRouteCandidate(first.ResolvedRecord(), second.OperationalState())
	if err != ErrRouteOperationalIdentityMismatch || observed != (ObservedRouteCandidate{}) {
		t.Fatalf("NewObservedRouteCandidate() = (%#v, %v)", observed, err)
	}
	if err := (ObservedRouteCandidate{}).Validate(); !errors.Is(err, provider.ErrInvalidRouteRegistryRevision) {
		t.Fatalf("zero Validate() = %v", err)
	}
}

func TestObservedRouteCandidateSurfaceAndFormatting(t *testing.T) {
	free, _ := provider.NewRoutePricing(0, 0)
	observed := newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	typeOfObserved := reflect.TypeOf(observed)
	want := []string{"resolvedRecord", "operationalState"}
	if typeOfObserved.NumField() != len(want) {
		t.Fatalf("ObservedRouteCandidate has %d fields", typeOfObserved.NumField())
	}
	for index, name := range want {
		if field := typeOfObserved.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
	identity := observed.ResolvedRecord().RouteRegistryRecord().Identity()
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, observed)
		if strings.Contains(formatted, identity) {
			t.Fatalf("format %q exposed route identity: %q", format, formatted)
		}
	}
}

func TestFilterEligibleRoutesRetainsOperationalAndCostRejections(t *testing.T) {
	input := newContentLoggingInput(t, false)
	budget, _ := provider.NewModelCostBudget(2, 16_000, 20_000)
	free, _ := provider.NewRoutePricing(0, 0)
	over, _ := provider.NewRoutePricing(2_000_000, 2_000_000)
	routes := []ObservedRouteCandidate{
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput),
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthUnhealthy, provider.RouteQuotaAvailable, 128_001, 16_000, provider.ModelFeatureStructuredOutput),
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthUnknown, provider.RouteQuotaAvailable, 128_002, 16_000, provider.ModelFeatureStructuredOutput),
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaExhausted, 128_003, 16_000, provider.ModelFeatureStructuredOutput),
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaUnknown, 128_004, 16_000, provider.ModelFeatureStructuredOutput),
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, provider.NewUnknownRoutePricing(), provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_005, 16_000, provider.ModelFeatureStructuredOutput),
		newObservedRoute(t, 7, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, over, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_006, 16_000, provider.ModelFeatureStructuredOutput),
	}
	result, err := FilterEligibleRoutes(input, budget, 7, routes)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestIdentity() != input.RequestIdentity() || result.ReviewScopeIdentity() != input.ReviewScopeIdentity() || result.RoutingInputIdentity() != input.Identity() || result.RegistryRevision() != 7 || result.CostBudget() != budget || len(result.EligibleRoutes()) != 1 || len(result.RejectedRoutes()) != 6 {
		t.Fatalf("eligibility counts = (%d, %d)", len(result.EligibleRoutes()), len(result.RejectedRoutes()))
	}
	got := make([]RouteRejectionReason, 0, 6)
	seen := map[string]bool{}
	for _, route := range result.EligibleRoutes() {
		seen[route.ResolvedRecord().RouteRegistryRecord().Identity()] = true
	}
	for _, rejection := range result.RejectedRoutes() {
		got = append(got, rejection.Reason())
		seen[rejection.RecordIdentity()] = true
	}
	want := []RouteRejectionReason{RouteRejectedUnhealthy, RouteRejectedHealthUnknown, RouteRejectedQuotaExhausted, RouteRejectedQuotaUnknown, RouteRejectedUnknownPricing, RouteRejectedCostBudget}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if !reflect.DeepEqual(got, want) || len(seen) != len(routes) {
		t.Fatalf("reasons = %v, seen = %d", got, len(seen))
	}
}

func TestFilterEligibleRoutesPreservesGateOrder(t *testing.T) {
	input := newContentLoggingInput(t, false)
	budget, _ := provider.NewModelCostBudget(2, 16_000, 0)
	over, _ := provider.NewRoutePricing(2_000_000, 2_000_000)
	for _, test := range []struct {
		name   string
		zone   provider.ProviderZone
		status provider.RouteRegistryStatus
		health provider.RouteHealth
		want   RouteRejectionReason
	}{
		{name: "policy before readiness and cost", zone: provider.ProviderZoneBrokeredRemote, status: provider.RouteRegistryApproved, health: provider.RouteHealthUnhealthy, want: RouteRejectedZone},
		{name: "approval before readiness and cost", zone: provider.ProviderZoneLocal, status: provider.RouteRegistryPending, health: provider.RouteHealthUnhealthy, want: RouteRejectedNotApproved},
		{name: "readiness before cost", zone: provider.ProviderZoneLocal, status: provider.RouteRegistryApproved, health: provider.RouteHealthUnhealthy, want: RouteRejectedUnhealthy},
	} {
		t.Run(test.name, func(t *testing.T) {
			route := newObservedRoute(t, 1, test.zone, provider.ContentLoggingDisabled, test.status, over, test.health, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
			result, err := FilterEligibleRoutes(input, budget, 1, []ObservedRouteCandidate{route})
			if err != nil || len(result.RejectedRoutes()) != 1 || result.RejectedRoutes()[0].Reason() != test.want {
				t.Fatalf("FilterEligibleRoutes() = (%#v, %v), want %v", result, err, test.want)
			}
		})
	}
}

func TestFilterEligibleRoutesCanonicalizesAndDefendsResults(t *testing.T) {
	input := newContentLoggingInput(t, false)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	free, _ := provider.NewRoutePricing(0, 0)
	first := newObservedRoute(t, 3, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	second := newObservedRoute(t, 3, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 129_000, 16_000, provider.ModelFeatureStructuredOutput)
	forward, err := FilterEligibleRoutes(input, budget, 3, []ObservedRouteCandidate{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := FilterEligibleRoutes(input, budget, 3, []ObservedRouteCandidate{second, first})
	if err != nil {
		t.Fatal(err)
	}
	forwardIDs := observedRouteIdentities(forward.EligibleRoutes())
	reverseIDs := observedRouteIdentities(reverse.EligibleRoutes())
	if !reflect.DeepEqual(forwardIDs, reverseIDs) || !sort.StringsAreSorted(forwardIDs) {
		t.Fatalf("canonical identities = %v and %v", forwardIDs, reverseIDs)
	}
	returned := forward.EligibleRoutes()
	returned[0] = ObservedRouteCandidate{}
	if forward.EligibleRoutes()[0].ResolvedRecord().RouteRegistryRecord().Identity() == "" {
		t.Fatal("eligible route accessor exposed mutable slice")
	}
}

func TestFilterEligibleRoutesRejectsInvalidCollections(t *testing.T) {
	input := newContentLoggingInput(t, false)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	conflictingBudget, _ := provider.NewModelCostBudget(1, 1, 0)
	free, _ := provider.NewRoutePricing(0, 0)
	valid := newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	otherRevision := newObservedRoute(t, 2, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	tooMany := make([]ObservedRouteCandidate, maxRouteFilterCandidates+1)
	for index := range tooMany {
		tooMany[index] = newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, uint64(128_000+index), 16_000, provider.ModelFeatureStructuredOutput)
	}
	for _, test := range []struct {
		name     string
		input    ReviewRoutingInput
		budget   provider.ModelCostBudget
		revision uint64
		routes   []ObservedRouteCandidate
		want     error
	}{
		{name: "input", budget: budget, revision: 1, want: ErrInvalidRequestIdentity},
		{name: "budget", input: input, revision: 1, want: provider.ErrInvalidModelCostBudget},
		{name: "budget requirements", input: input, budget: conflictingBudget, revision: 1, want: ErrModelCostBudgetConflictsWithRequirements},
		{name: "revision", input: input, budget: budget, want: ErrInvalidRouteFilterRevision},
		{name: "limit", input: input, budget: budget, revision: 1, routes: tooMany, want: ErrTooManyRouteCandidates},
		{name: "invalid", input: input, budget: budget, revision: 1, routes: []ObservedRouteCandidate{{}}, want: provider.ErrInvalidRouteRegistryRevision},
		{name: "mixed revision", input: input, budget: budget, revision: 1, routes: []ObservedRouteCandidate{otherRevision}, want: ErrRouteCandidateRevisionMismatch},
		{name: "duplicate", input: input, budget: budget, revision: 1, routes: []ObservedRouteCandidate{valid, valid}, want: ErrDuplicateRouteCandidate},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := FilterEligibleRoutes(test.input, test.budget, test.revision, test.routes)
			if !errors.Is(err, test.want) || result.RequestIdentity() != "" || result.EligibleRoutes() != nil || result.RejectedRoutes() != nil {
				t.Fatalf("FilterEligibleRoutes() = (%#v, %v), want %v", result, err, test.want)
			}
		})
	}
	empty, err := FilterEligibleRoutes(input, budget, 1, nil)
	if err != nil || empty.RequestIdentity() != input.RequestIdentity() || empty.ReviewScopeIdentity() != input.ReviewScopeIdentity() || empty.RoutingInputIdentity() != input.Identity() || empty.RegistryRevision() != 1 || empty.CostBudget() != budget || empty.EligibleRoutes() != nil || empty.RejectedRoutes() != nil {
		t.Fatalf("empty eligibility result = (%#v, %v)", empty, err)
	}
}

func observedRouteIdentities(routes []ObservedRouteCandidate) []string {
	identities := make([]string, len(routes))
	for index, route := range routes {
		identities[index] = route.ResolvedRecord().RouteRegistryRecord().Identity()
	}
	return identities
}

func TestFilterEligibleRoutesRejectsBudgetAboveApprovedCapacity(t *testing.T) {
	input := newContentLoggingInput(t, false)
	free, _ := provider.NewRoutePricing(0, 0)
	route := newObservedRoute(t, 1, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 128000, 16000, provider.ModelFeatureStructuredOutput)
	tests := []struct {
		name                   string
		inputTokens, maxOutput uint64
		want                   RouteRejectionReason
	}{{"output", 1000, 20000, RouteRejectedInsufficientOutput}, {"total context", 120000, 16000, RouteRejectedInsufficientContext}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			budget, err := provider.NewModelCostBudget(test.inputTokens, test.maxOutput, 100000)
			if err != nil {
				t.Fatal(err)
			}
			result, err := FilterEligibleRoutes(input, budget, 1, []ObservedRouteCandidate{route})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.EligibleRoutes()) != 0 || len(result.RejectedRoutes()) != 1 || result.RejectedRoutes()[0].Reason() != test.want {
				t.Fatalf("result=%#v", result)
			}
		})
	}
}
