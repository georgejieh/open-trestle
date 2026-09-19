package gateway

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func newInitialAttemptFixture(t *testing.T) (provider.Request, fallbackFixture, ObservedRouteCandidate) {
	t.Helper()
	pricing, _ := provider.NewRoutePricing(1_000_000, 1_000_000)
	route := newFallbackRoute(t, 140_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, pricing)
	fixture := newFallbackFixture(t, 20_000, route)
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
	if err != nil {
		t.Fatal(err)
	}
	return request, fixture, route
}

func TestRouteAttemptKindRoundTrips(t *testing.T) {
	values := []struct {
		kind  RouteAttemptKind
		token string
	}{
		{RouteAttemptInitial, "initial"},
		{RouteAttemptRetry, "retry"},
		{RouteAttemptFallback, "fallback"},
	}
	for _, test := range values {
		parsed, err := ParseRouteAttemptKind(test.token)
		if err != nil || parsed != test.kind || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("kind %q = (%v, %v)", test.token, parsed, err)
		}
	}
	if parsed, err := ParseRouteAttemptKind(""); !errors.Is(err, ErrInvalidRouteAttemptKind) || parsed != 0 {
		t.Fatalf("empty kind = (%v, %v)", parsed, err)
	}
}

func TestNewInitialRouteAttemptAuthorizationBindsSelectionAndReservation(t *testing.T) {
	request, fixture, route := newInitialAttemptFixture(t)
	authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if err != nil {
		t.Fatal(err)
	}
	candidate := route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
	if authorization.Identity() == "" || authorization.Kind() != RouteAttemptInitial || authorization.ReviewScopeIdentity() != fixture.selection.ReviewScopeIdentity() || authorization.RequestIdentity() != request.Identity() || authorization.SelectionReceiptIdentity() != fixture.selection.Identity() || authorization.RouteRecordIdentity() != observedRouteIdentity(route) || authorization.AttemptOrdinal() != 1 || authorization.RouteAttemptOrdinal() != 1 || authorization.PreviousOutcomeIdentity() != "" || authorization.ContinuationDecisionIdentity() != "" || authorization.RouteReference() != candidate.RouteCapabilityDeclaration().RouteReference() || authorization.ContentLoggingMode() != provider.ContentLoggingDisabled || authorization.Pricing() != candidate.RoutePricing() || authorization.MaxOutputTokens() != 16_000 || authorization.MaximumCost().MaximumCostMicroUSD() != 16_001 || authorization.RemainingCostBeforeMicroUSD() != 20_000 || authorization.ReservedCostMicroUSD() != 16_001 || authorization.RemainingCostAfterMicroUSD() != 3_999 || authorization.Validate() != nil {
		t.Fatalf("initial authorization did not round trip: %#v", authorization)
	}
}

func TestNewInitialRouteAttemptAuthorizationRejectsMismatchedInputs(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	otherRequest, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("other"))
	other := newSelectionFixture(t, 1, 1, 100, 0, false)
	otherReceipt, _ := NewRouteSelectionReceipt(other.eligibility, other.ranking)
	for _, test := range []struct {
		name      string
		request   provider.Request
		selection RouteSelectionReceipt
		ranking   RouteRankingResult
		want      error
	}{
		{name: "request", request: otherRequest, selection: fixture.selection, ranking: fixture.ranking, want: ErrRouteAttemptRequestMismatch},
		{name: "selection", request: request, ranking: fixture.ranking, want: ErrInvalidRequestIdentity},
		{name: "ranking", request: request, selection: fixture.selection, want: ErrInvalidRequestIdentity},
		{name: "cross wired", request: request, selection: otherReceipt, ranking: fixture.ranking, want: ErrRouteSelectionBindingMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorization, err := NewInitialRouteAttemptAuthorization(test.request, test.selection, test.ranking)
			if !errors.Is(err, test.want) || authorization.Identity() != "" {
				t.Fatalf("NewInitialRouteAttemptAuthorization() = (%#v, %v), want %v", authorization, err, test.want)
			}
		})
	}
}

func TestRouteAttemptOutcomeStatusRoundTrips(t *testing.T) {
	for _, test := range []struct {
		status RouteAttemptOutcomeStatus
		token  string
	}{
		{RouteAttemptSucceeded, "succeeded"},
		{RouteAttemptFailed, "failed"},
	} {
		parsed, err := ParseRouteAttemptOutcomeStatus(test.token)
		if err != nil || parsed != test.status || parsed.String() != test.token || parsed.Validate() != nil {
			t.Fatalf("status %q = (%v, %v)", test.token, parsed, err)
		}
	}
	if parsed, err := ParseRouteAttemptOutcomeStatus(""); !errors.Is(err, ErrInvalidRouteAttemptOutcomeStatus) || parsed != 0 {
		t.Fatalf("empty status = (%v, %v)", parsed, err)
	}
}

func TestRouteAttemptOutcomesBindSuccessAndFailure(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	usage, _ := provider.NewRouteTokenUsage(100, 20, 10)
	success, err := NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("e", 64), usage, 125)
	if err != nil || success.Identity() == "" || success.AuthorizationIdentity() != authorization.Identity() || success.Status() != RouteAttemptSucceeded || success.ResponseIdentity() != strings.Repeat("e", 64) || success.Usage() != usage || success.DurationMilliseconds() != 125 || success.Failure() != 0 || success.ReplaySafety() != 0 || success.RetryAfterMilliseconds() != 0 || success.Validate() != nil {
		t.Fatalf("success = (%#v, %v)", success, err)
	}
	failure, err := NewFailedRouteAttemptOutcome(authorization, RouteFailureRateLimited, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 500, 75)
	if err != nil || failure.Identity() == "" || failure.Status() != RouteAttemptFailed || failure.Failure() != RouteFailureRateLimited || failure.ReplaySafety() != RouteReplayNoSideEffect || failure.RetryAfterMilliseconds() != 500 || failure.DurationMilliseconds() != 75 || failure.Validate() != nil || failure.Identity() == success.Identity() {
		t.Fatalf("failure = (%#v, %v)", failure, err)
	}
}

func TestRouteAttemptOutcomesRejectInvalidValues(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	known, _ := provider.NewRouteTokenUsage(1, 1, 0)
	for _, test := range []struct {
		name       string
		failure    RouteFailureClass
		safety     RouteReplaySafety
		usage      provider.RouteTokenUsage
		retryAfter uint32
		duration   uint64
		want       error
	}{
		{name: "failure", safety: RouteReplayNoSideEffect, usage: known, want: ErrInvalidRouteFailureClass},
		{name: "safety", failure: RouteFailureTimeout, usage: known, want: ErrInvalidRouteReplaySafety},
		{name: "usage", failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, want: provider.ErrInvalidRouteTokenUsage},
		{name: "retry after", failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, usage: known, retryAfter: 1, want: ErrInvalidRouteRetryAfter},
		{name: "duration", failure: RouteFailureTimeout, safety: RouteReplayNoSideEffect, usage: known, duration: maxRouteAttemptDurationMilliseconds + 1, want: ErrInvalidRouteAttemptDuration},
	} {
		t.Run(test.name, func(t *testing.T) {
			outcome, err := NewFailedRouteAttemptOutcome(authorization, test.failure, test.safety, test.usage, test.retryAfter, test.duration)
			if !errors.Is(err, test.want) || outcome.Identity() != "" {
				t.Fatalf("NewFailedRouteAttemptOutcome() = (%#v, %v), want %v", outcome, err, test.want)
			}
		})
	}
	if outcome, err := NewSuccessfulRouteAttemptOutcome(RouteAttemptAuthorization{}, strings.Repeat("e", 64), known, 1); err == nil || outcome.Identity() != "" {
		t.Fatalf("success accepted invalid authorization: (%#v, %v)", outcome, err)
	}
}

func TestReconcileAuthorizedRouteAttemptCostRequiresMatchingOutcome(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	usage, _ := provider.NewRouteTokenUsage(1, 2, 0)
	outcome, _ := NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("e", 64), usage, 1)
	reconciliation, err := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	if err != nil || reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.ActualCost().TotalCostMicroUSD() != 3 || reconciliation.RemainingCostMicroUSD() != 19_997 || reconciliation.Validate() != nil {
		t.Fatalf("authorized reconciliation = (%#v, %v)", reconciliation, err)
	}
	forged := outcome
	forged.authorizationIdentity = strings.Repeat("f", 64)
	forged.identity = deriveRouteAttemptOutcomeIdentity(forged)
	if reconciliation, err = ReconcileAuthorizedRouteAttemptCost(authorization, forged); !errors.Is(err, ErrRouteAttemptOutcomeMismatch) || reconciliation.Identity() != "" {
		t.Fatalf("cross-wired reconciliation = (%#v, %v)", reconciliation, err)
	}
}

func TestRouteAttemptRecordsAreContentAddressedAndRedacted(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("e", 64), provider.NewUnknownRouteTokenUsage(), 1)
	forgedAuthorization := authorization
	forgedAuthorization.identity = strings.Repeat("0", 64)
	if forgedAuthorization.Validate() != ErrInvalidRouteAttemptAuthorizationIdentity {
		t.Fatal("forged authorization identity accepted")
	}
	forgedOutcome := outcome
	forgedOutcome.identity = strings.Repeat("0", 64)
	if forgedOutcome.Validate() != ErrInvalidRouteAttemptOutcomeIdentity {
		t.Fatal("forged outcome identity accepted")
	}
	if reflect.TypeOf(authorization).NumField() != 19 || reflect.TypeOf(outcome).NumField() != 9 {
		t.Fatalf("unexpected record fields: authorization=%d outcome=%d", reflect.TypeOf(authorization).NumField(), reflect.TypeOf(outcome).NumField())
	}
	for _, value := range []any{authorization, outcome} {
		for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, authorization.RouteReference().ModelID()) || strings.Contains(formatted, authorization.Identity()) {
				t.Fatalf("format %q exposed attempt data: %q", format, formatted)
			}
		}
	}
}
