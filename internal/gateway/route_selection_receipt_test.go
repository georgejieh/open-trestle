package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type selectionFixture struct {
	eligibility RouteEligibilityResult
	ranking     RouteRankingResult
	selected    ObservedRouteCandidate
	rejected    ObservedRouteCandidate
	policy      RouteRankingPolicy
	budget      provider.ModelCostBudget
}

func newSelectionFixture(t *testing.T, operationalRevision, performanceRevision uint64, latency uint32, maxCost uint64, preferSelected bool) selectionFixture {
	t.Helper()
	free := mustKnownFreePricing(t)
	budget, err := provider.NewModelCostBudget(1, 16_000, maxCost)
	if err != nil {
		t.Fatal(err)
	}
	selected := rankTestRoute(t, 129_000, provider.RouteQualityTier3, free)
	state, err := provider.NewRouteOperationalState(observedRouteIdentity(selected), operationalRevision, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	if err != nil {
		t.Fatal(err)
	}
	selected, err = NewObservedRouteCandidate(selected.ResolvedRecord(), state)
	if err != nil {
		t.Fatal(err)
	}
	rejected := newObservedRouteWithQuality(t, 11, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteQualityTier4, provider.RouteHealthUnhealthy, provider.RouteQuotaAvailable, 129_001, 16_000, provider.ModelFeatureStructuredOutput)
	input := newContentLoggingInput(t, false)
	eligibility, err := FilterEligibleRoutes(input, budget, 11, []ObservedRouteCandidate{rejected, selected})
	if err != nil {
		t.Fatal(err)
	}
	var policy RouteRankingPolicy
	if preferSelected {
		policy, err = NewRouteRankingPolicy([]provider.RouteReference{observedRouteReference(selected)})
	} else {
		policy, err = NewRouteRankingPolicy(nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	observation := routePerformance(t, selected, performanceRevision, latency)
	ranking, err := RankEligibleRoutes(eligibility, policy, performanceRevision, []provider.RoutePerformanceObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	return selectionFixture{eligibility: eligibility, ranking: ranking, selected: selected, rejected: rejected, policy: policy, budget: budget}
}

func TestNewRouteSelectionReceiptBindsCompleteDecision(t *testing.T) {
	fixture := newSelectionFixture(t, 7, 9, 250, 10, true)
	receipt, err := NewRouteSelectionReceipt(fixture.eligibility, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Identity() == "" || receipt.RequestIdentity() != fixture.eligibility.RequestIdentity() || receipt.ReviewScopeIdentity() != fixture.eligibility.ReviewScopeIdentity() || receipt.RoutingInputIdentity() != fixture.eligibility.RoutingInputIdentity() || receipt.RegistryRevision() != 11 || receipt.PerformanceRevision() != 9 || receipt.CostBudget() != fixture.budget || receipt.RankingPolicyIdentity() != fixture.policy.Identity() || receipt.SelectedRecordIdentity() != observedRouteIdentity(fixture.selected) || receipt.Validate() != nil {
		t.Fatal("selection receipt did not bind decision inputs")
	}
	scores := receipt.CandidateScores()
	if len(scores) != 1 || scores[0].RecordIdentity() != observedRouteIdentity(fixture.selected) || scores[0].OperationalRevision() != 7 || scores[0].IsPinned() || scores[0].QualityTier() != provider.RouteQualityTier3 || scores[0].MaxContextTokens() != 129_000 || scores[0].MaxOutputTokens() != 16_000 || scores[0].MaximumCost().MaximumCostMicroUSD() != 0 || scores[0].Performance().P95LatencyMilliseconds() != 250 {
		t.Fatalf("candidate score did not round trip: %#v", scores)
	}
	preferenceRank, preferred := scores[0].PreferenceRank()
	if !preferred || preferenceRank != 1 {
		t.Fatalf("preference rank = (%d, %v)", preferenceRank, preferred)
	}
	rejections := receipt.Rejections()
	if len(rejections) != 1 || rejections[0].RecordIdentity() != observedRouteIdentity(fixture.rejected) || rejections[0].OperationalRevision() != 1 || rejections[0].Reason() != RouteRejectedUnhealthy {
		t.Fatalf("rejections = %#v", rejections)
	}
	scores[0] = RouteSelectionCandidateScore{}
	rejections[0] = RouteRejection{}
	if receipt.CandidateScores()[0].RecordIdentity() == "" || receipt.Rejections()[0].RecordIdentity() == "" {
		t.Fatal("receipt accessors exposed mutable slices")
	}
}

func TestRouteSelectionReceiptIdentityBindsEveryDecisionComponent(t *testing.T) {
	fixtures := []selectionFixture{
		newSelectionFixture(t, 1, 1, 100, 0, false),
		newSelectionFixture(t, 2, 1, 100, 0, false),
		newSelectionFixture(t, 1, 2, 100, 0, false),
		newSelectionFixture(t, 1, 1, 101, 0, false),
		newSelectionFixture(t, 1, 1, 100, 1, false),
		newSelectionFixture(t, 1, 1, 100, 0, true),
	}
	identities := make(map[string]bool, len(fixtures))
	for _, fixture := range fixtures {
		receipt, err := NewRouteSelectionReceipt(fixture.eligibility, fixture.ranking)
		if err != nil {
			t.Fatal(err)
		}
		identities[receipt.Identity()] = true
	}
	if len(identities) != len(fixtures) {
		t.Fatalf("receipt identities collided: %#v", identities)
	}
}

func TestNewRouteSelectionReceiptRejectsCrossWiredDecisions(t *testing.T) {
	first := newSelectionFixture(t, 1, 1, 100, 0, false)
	second := newSelectionFixture(t, 1, 1, 100, 1, false)
	for _, test := range []struct {
		name        string
		eligibility RouteEligibilityResult
		ranking     RouteRankingResult
		want        error
	}{
		{name: "eligibility", ranking: first.ranking, want: ErrInvalidRequestIdentity},
		{name: "ranking", eligibility: first.eligibility, want: ErrInvalidRequestIdentity},
		{name: "binding", eligibility: second.eligibility, ranking: first.ranking, want: ErrRouteSelectionBindingMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			receipt, err := NewRouteSelectionReceipt(test.eligibility, test.ranking)
			if !errors.Is(err, test.want) || receipt.Identity() != "" {
				t.Fatalf("NewRouteSelectionReceipt() = (%#v, %v), want %v", receipt, err, test.want)
			}
		})
	}
}

func TestRouteSelectionReceiptRejectsForgeryAndReordering(t *testing.T) {
	fixture := newSelectionFixture(t, 1, 1, 100, 0, false)
	receipt, _ := NewRouteSelectionReceipt(fixture.eligibility, fixture.ranking)
	forged := receipt
	forged.identity = strings.Repeat("0", 64)
	if err := forged.Validate(); err != ErrInvalidRouteSelectionReceiptIdentity {
		t.Fatalf("forged identity Validate() = %v", err)
	}
	if err := (RouteSelectionReceipt{}).Validate(); !errors.Is(err, ErrInvalidRequestIdentity) {
		t.Fatalf("zero receipt Validate() = %v", err)
	}
	if fixture.ranking.Validate() != nil {
		t.Fatal("valid ranking result rejected")
	}
	duplicatedRanking := fixture.ranking
	duplicatedRanking.rankedRoutes = append(duplicatedRanking.RankedRoutes(), fixture.ranking.RankedRoutes()[0])
	if err := duplicatedRanking.Validate(); err != ErrDuplicateRouteCandidate {
		t.Fatalf("duplicate ranking Validate() = %v", err)
	}
}

func TestRouteSelectionReceiptSurfaceAndFormatting(t *testing.T) {
	fixture := newSelectionFixture(t, 1, 1, 100, 0, false)
	receipt, _ := NewRouteSelectionReceipt(fixture.eligibility, fixture.ranking)
	typeOfReceipt := reflect.TypeOf(receipt)
	want := []string{"identity", "requestIdentity", "reviewScopeIdentity", "routingInputIdentity", "registryRevision", "performanceRevision", "costBudget", "rankingPolicyIdentity", "selectedRecordIdentity", "candidateScores", "rejections"}
	if typeOfReceipt.NumField() != len(want) {
		t.Fatalf("RouteSelectionReceipt has %d fields", typeOfReceipt.NumField())
	}
	for index, name := range want {
		if field := typeOfReceipt.Field(index); field.Name != name {
			t.Fatalf("field %d = %q, want %q", index, field.Name, name)
		}
	}
	sensitive := observedRouteIdentity(fixture.selected)
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, receipt)
		if strings.Contains(formatted, sensitive) || strings.Contains(formatted, "Model-") {
			t.Fatalf("format %q exposed route data: %q", format, formatted)
		}
	}
}

func TestRouteSelectionReceiptBindsRoutingPolicyInput(t *testing.T) {
	request, requirements, constraints := newRoutingFixture(t, []byte("policy-bound request"))
	baselineInput, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, constraints)
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZoneLocal, provider.ProviderZonePrivateRemote)
	otherConstraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	otherInput, _ := NewReviewRoutingInput(newRoutingScope(t), request, requirements, otherConstraints)
	free := mustKnownFreePricing(t)
	route := newFallbackRoute(t, 160_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	baselineEligibility, _ := FilterEligibleRoutes(baselineInput, budget, 21, []ObservedRouteCandidate{route})
	otherEligibility, _ := FilterEligibleRoutes(otherInput, budget, 21, []ObservedRouteCandidate{route})
	rankingPolicy, _ := NewRouteRankingPolicy(nil)
	observation := routePerformance(t, route, 9, 100)
	baselineRanking, _ := RankEligibleRoutes(baselineEligibility, rankingPolicy, 9, []provider.RoutePerformanceObservation{observation})
	otherRanking, _ := RankEligibleRoutes(otherEligibility, rankingPolicy, 9, []provider.RoutePerformanceObservation{observation})
	baseline, _ := NewRouteSelectionReceipt(baselineEligibility, baselineRanking)
	other, _ := NewRouteSelectionReceipt(otherEligibility, otherRanking)
	if baseline.RoutingInputIdentity() != baselineInput.Identity() || other.RoutingInputIdentity() != otherInput.Identity() || baseline.Identity() == other.Identity() {
		t.Fatal("selection receipt ignored routing policy input")
	}
}

func TestRouteSelectionReceiptRejectsBudgetAboveBoundCapacity(t *testing.T) {
	fixture := newSelectionFixture(t, 7, 9, 250, 200000, true)
	receipt, err := NewRouteSelectionReceipt(fixture.eligibility, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	budget, err := provider.NewModelCostBudget(120000, 16000, 200000)
	if err != nil {
		t.Fatal(err)
	}
	receipt.costBudget = budget
	receipt.identity, err = deriveRouteSelectionReceiptIdentity(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(receipt.Validate(), ErrInvalidRouteSelectionReceiptCandidates) {
		t.Fatal("receipt accepted token budget above bound route capacity")
	}
}
