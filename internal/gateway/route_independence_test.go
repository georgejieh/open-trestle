package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func authorizationForPayload(t *testing.T, scope audit.ReviewScope, payload string, route ObservedRouteCandidate) (RouteAttemptAuthorization, provider.Request) {
	t.Helper()
	request, requirements, _ := newRoutingFixture(t, []byte(payload))
	zones, _ := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	constraints, _ := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	input, err := NewReviewRoutingInput(scope, request, requirements, constraints)
	if err != nil {
		t.Fatal(err)
	}
	budget, _ := provider.NewModelCostBudget(1, 16_000, 0)
	eligibility, err := FilterEligibleRoutes(input, budget, 21, []ObservedRouteCandidate{route})
	if err != nil {
		t.Fatal(err)
	}
	rankingPolicy, _ := NewRouteRankingPolicy(nil)
	observation := routePerformance(t, route, 40, 100)
	ranking, err := RankEligibleRoutes(eligibility, rankingPolicy, 40, []provider.RoutePerformanceObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	selection, _ := NewRouteSelectionReceipt(eligibility, ranking)
	authorization, err := NewInitialRouteAttemptAuthorization(request, selection, ranking)
	if err != nil {
		t.Fatal(err)
	}
	return authorization, request
}

func TestVerifyIndependentRouteAttemptsBindsDistinctModels(t *testing.T) {
	free := mustKnownFreePricing(t)
	firstRoute := newFallbackRoute(t, 171_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	secondRoute := newFallbackRoute(t, 171_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	scope := newRoutingScope(t)
	first, _ := authorizationForPayload(t, scope, "candidate request", firstRoute)
	second, _ := authorizationForPayload(t, scope, "verification request", secondRoute)
	usage := provider.NewUnknownRouteTokenUsage()
	firstOutcome, _ := NewSuccessfulRouteAttemptOutcome(first, strings.Repeat("a", 64), usage, 1)
	secondOutcome, _ := NewSuccessfulRouteAttemptOutcome(second, strings.Repeat("b", 64), usage, 1)
	policy, _ := NewRouteIndependencePolicy(RouteIndependenceDistinctModel)
	if err := VerifyIndependentRouteAuthorizations(policy, first, second); err != nil {
		t.Fatal(err)
	}
	receipt, err := VerifyIndependentRouteAttempts(policy, first, firstOutcome, second, secondOutcome)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Identity() == "" || receipt.PolicyIdentity() != policy.Identity() || receipt.ReviewScopeIdentity() != scope.Identity() || receipt.FirstAuthorizationIdentity() != first.Identity() || receipt.FirstOutcomeIdentity() != firstOutcome.Identity() || receipt.SecondAuthorizationIdentity() != second.Identity() || receipt.SecondOutcomeIdentity() != secondOutcome.Identity() || receipt.Level() != RouteIndependenceDistinctModel || receipt.Validate() != nil {
		t.Fatalf("independence receipt did not round trip: %#v", receipt)
	}
}

func TestVerifyIndependentRouteAttemptsRejectsSharedRouteAndInsufficientLevel(t *testing.T) {
	free := mustKnownFreePricing(t)
	firstRoute := newFallbackRoute(t, 172_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	secondRoute := newFallbackRoute(t, 172_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	scope := newRoutingScope(t)
	first, _ := authorizationForPayload(t, scope, "candidate", firstRoute)
	same, _ := authorizationForPayload(t, scope, "verification", firstRoute)
	second, _ := authorizationForPayload(t, scope, "verification", secondRoute)
	usage := provider.NewUnknownRouteTokenUsage()
	firstOutcome, _ := NewSuccessfulRouteAttemptOutcome(first, strings.Repeat("a", 64), usage, 1)
	sameOutcome, _ := NewSuccessfulRouteAttemptOutcome(same, strings.Repeat("b", 64), usage, 1)
	secondOutcome, _ := NewSuccessfulRouteAttemptOutcome(second, strings.Repeat("c", 64), usage, 1)
	modelPolicy, _ := NewRouteIndependencePolicy(RouteIndependenceDistinctModel)
	if err := VerifyIndependentRouteCandidate(modelPolicy, first, firstRoute); !errors.Is(err, ErrRouteAttemptsNotIndependent) {
		t.Fatalf("same route candidate = %v", err)
	}
	if err := VerifyIndependentRouteCandidate(modelPolicy, first, secondRoute); err != nil {
		t.Fatalf("distinct route candidate = %v", err)
	}
	if err := VerifyIndependentRouteAuthorizations(modelPolicy, first, same); !errors.Is(err, ErrRouteAttemptsNotIndependent) {
		t.Fatalf("same authorization routes = %v", err)
	}
	if receipt, err := VerifyIndependentRouteAttempts(modelPolicy, first, firstOutcome, same, sameOutcome); !errors.Is(err, ErrRouteAttemptsNotIndependent) || receipt.Identity() != "" {
		t.Fatalf("same route = (%#v, %v)", receipt, err)
	}
	providerPolicy, _ := NewRouteIndependencePolicy(RouteIndependenceDistinctProvider)
	if receipt, err := VerifyIndependentRouteAttempts(providerPolicy, first, firstOutcome, second, secondOutcome); !errors.Is(err, ErrRouteAttemptsNotIndependent) || receipt.Identity() != "" {
		t.Fatalf("same provider = (%#v, %v)", receipt, err)
	}
}

func TestVerifyIndependentRouteAttemptsRejectsCrossScopeRequestAndFailure(t *testing.T) {
	free := mustKnownFreePricing(t)
	firstRoute := newFallbackRoute(t, 173_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	secondRoute := newFallbackRoute(t, 173_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	scope := newRoutingScope(t)
	otherScope, _ := audit.NewReviewScope("other", "repository", "review-run")
	first, _ := authorizationForPayload(t, scope, "candidate", firstRoute)
	second, _ := authorizationForPayload(t, scope, "verification", secondRoute)
	other, _ := authorizationForPayload(t, otherScope, "verification", secondRoute)
	usage := provider.NewUnknownRouteTokenUsage()
	firstOutcome, _ := NewSuccessfulRouteAttemptOutcome(first, strings.Repeat("a", 64), usage, 1)
	otherOutcome, _ := NewSuccessfulRouteAttemptOutcome(other, strings.Repeat("b", 64), usage, 1)
	policy, _ := NewRouteIndependencePolicy(RouteIndependenceDistinctModel)
	if receipt, err := VerifyIndependentRouteAttempts(policy, first, firstOutcome, other, otherOutcome); !errors.Is(err, ErrRouteIndependenceScopeMismatch) || receipt.Identity() != "" {
		t.Fatalf("cross scope = (%#v, %v)", receipt, err)
	}
	failed, _ := NewFailedRouteAttemptOutcome(other, RouteFailureTimeout, RouteReplayNoSideEffect, usage, 0, 1)
	if receipt, err := VerifyIndependentRouteAttempts(policy, first, firstOutcome, other, failed); !errors.Is(err, ErrRouteIndependenceRequiresSuccess) || receipt.Identity() != "" {
		t.Fatalf("failed verifier = (%#v, %v)", receipt, err)
	}
	sameRequest := second
	sameRequest.requestIdentity = first.RequestIdentity()
	sameRequest.identity = deriveRouteAttemptAuthorizationIdentity(sameRequest)
	sameRequestOutcome, _ := NewSuccessfulRouteAttemptOutcome(sameRequest, strings.Repeat("c", 64), usage, 1)
	if receipt, err := VerifyIndependentRouteAttempts(policy, first, firstOutcome, sameRequest, sameRequestOutcome); !errors.Is(err, ErrRouteIndependenceRequestMismatch) || receipt.Identity() != "" {
		t.Fatalf("same request = (%#v, %v)", receipt, err)
	}
}

func TestRouteIndependenceLevelRoundTrips(t *testing.T) {
	for _, token := range []string{"distinct_route", "distinct_model", "distinct_provider"} {
		level, err := ParseRouteIndependenceLevel(token)
		if err != nil || level.String() != token || level.Validate() != nil {
			t.Fatalf("level %q = (%v, %v)", token, level, err)
		}
	}
}

func TestDistinctRouteRejectsRegistryMetadataChurn(t *testing.T) {
	free := mustKnownFreePricing(t)
	firstRoute := newObservedRouteWithQuality(t, 21, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteQualityTier4, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 174_000, 16_000, provider.ModelFeatureStructuredOutput)
	changedMetadata := newObservedRouteWithQuality(t, 21, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteQualityTier3, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 174_000, 16_000, provider.ModelFeatureStructuredOutput)
	changedRevision := newObservedRouteWithQuality(t, 22, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteRegistryApproved, free, provider.RouteQualityTier4, provider.RouteHealthHealthy, provider.RouteQuotaAvailable, 174_000, 16_000, provider.ModelFeatureStructuredOutput)
	scope := newRoutingScope(t)
	first, _ := authorizationForPayload(t, scope, "candidate", firstRoute)
	second, _ := authorizationForPayload(t, scope, "verification", changedMetadata)
	if first.RouteReference() != second.RouteReference() || first.RouteRecordIdentity() == second.RouteRecordIdentity() {
		t.Fatal("fixture must change metadata without changing route")
	}
	policy, err := NewRouteIndependencePolicy(RouteIndependenceDistinctRoute)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []ObservedRouteCandidate{changedMetadata, changedRevision} {
		if err := VerifyIndependentRouteCandidate(policy, first, candidate); !errors.Is(err, ErrRouteAttemptsNotIndependent) {
			t.Errorf("metadata-only candidate accepted: %v", err)
		}
	}
	if err := VerifyIndependentRouteAuthorizations(policy, first, second); !errors.Is(err, ErrRouteAttemptsNotIndependent) {
		t.Errorf("metadata-only authorizations accepted: %v", err)
	}
	usage := provider.NewUnknownRouteTokenUsage()
	firstOutcome, _ := NewSuccessfulRouteAttemptOutcome(first, strings.Repeat("a", 64), usage, 1)
	secondOutcome, _ := NewSuccessfulRouteAttemptOutcome(second, strings.Repeat("b", 64), usage, 1)
	if receipt, err := VerifyIndependentRouteAttempts(policy, first, firstOutcome, second, secondOutcome); !errors.Is(err, ErrRouteAttemptsNotIndependent) || receipt.Identity() != "" {
		t.Errorf("metadata-only completed attempts accepted: %v", err)
	}
	different := newFallbackRoute(t, 174_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
	if err := VerifyIndependentRouteCandidate(policy, first, different); err != nil {
		t.Fatalf("genuinely distinct route rejected: %v", err)
	}
}
