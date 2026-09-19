package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestNewSuccessfulRouteOutputReceiptBindsRequestResponseAndArtifact(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("a", 64), provider.NewUnknownRouteTokenUsage(), 1)
	receipt, err := NewSuccessfulRouteOutputReceipt(RouteOutputCandidateBatch, strings.Repeat("b", 64), strings.Repeat("c", 64), request, authorization, outcome)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Identity() == "" || receipt.Kind() != RouteOutputCandidateBatch || receipt.ReviewScopeIdentity() != authorization.ReviewScopeIdentity() || receipt.ContextIdentity() != strings.Repeat("b", 64) || receipt.ArtifactIdentity() != strings.Repeat("c", 64) || receipt.RequestIdentity() != request.Identity() || receipt.ResponseIdentity() != outcome.ResponseIdentity() || receipt.AuthorizationIdentity() != authorization.Identity() || receipt.OutcomeIdentity() != outcome.Identity() || receipt.Validate() != nil {
		t.Fatalf("route output receipt did not round trip: %#v", receipt)
	}
}

func TestNewSuccessfulRouteOutputReceiptRejectsCrossWiringAndFailure(t *testing.T) {
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	outcome, _ := NewSuccessfulRouteAttemptOutcome(authorization, strings.Repeat("a", 64), provider.NewUnknownRouteTokenUsage(), 1)
	otherRequest, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("other"))
	if receipt, err := NewSuccessfulRouteOutputReceipt(RouteOutputCandidateBatch, strings.Repeat("b", 64), strings.Repeat("c", 64), otherRequest, authorization, outcome); !errors.Is(err, ErrRouteOutputRequestMismatch) || receipt.Identity() != "" {
		t.Fatalf("request mismatch = (%#v, %v)", receipt, err)
	}
	failed, _ := NewFailedRouteAttemptOutcome(authorization, RouteFailureTimeout, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0, 1)
	if receipt, err := NewSuccessfulRouteOutputReceipt(RouteOutputCandidateBatch, strings.Repeat("b", 64), strings.Repeat("c", 64), request, authorization, failed); !errors.Is(err, ErrRouteOutputRequiresSuccess) || receipt.Identity() != "" {
		t.Fatalf("failed output = (%#v, %v)", receipt, err)
	}
	forged := outcome
	forged.authorizationIdentity = strings.Repeat("f", 64)
	forged.identity = deriveRouteAttemptOutcomeIdentity(forged)
	if receipt, err := NewSuccessfulRouteOutputReceipt(RouteOutputCandidateBatch, strings.Repeat("b", 64), strings.Repeat("c", 64), request, authorization, forged); !errors.Is(err, ErrRouteAttemptOutcomeMismatch) || receipt.Identity() != "" {
		t.Fatalf("outcome mismatch = (%#v, %v)", receipt, err)
	}
}

func TestRouteOutputKindRoundTrips(t *testing.T) {
	for _, token := range []string{"candidate_batch", "verification_batch"} {
		kind, err := ParseRouteOutputKind(token)
		if err != nil || kind.String() != token || kind.Validate() != nil {
			t.Fatalf("kind %q = (%v, %v)", token, kind, err)
		}
	}
}
