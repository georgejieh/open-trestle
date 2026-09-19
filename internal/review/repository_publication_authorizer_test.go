package review

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
)

func TestRepositoryPublicationAuthorizerIssuesExactScopedGrant(t *testing.T) {
	_, plan := publicationPlanFixture(t)
	plan = acquiredPublicationPlanForTest(plan)
	scope, err := audit.NewReviewScope("tenant", "repository", "review-run")
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := NewRepositoryPublicationAuthorizer("tenant", "repository", strings.Repeat("a", 64), strings.Repeat("b", 64), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1000, 123456789).UTC()
	authorization, err := authorizer.Authorize(context.Background(), scope, plan, at)
	if err != nil {
		t.Fatal(err)
	}
	effect := authorization.EffectAuthorization()
	if authorization.Validate() != nil || effect.ScopeIdentity() != scope.Identity() || effect.Capability() != policy.CapabilityPublication || effect.Outcome() != policy.DecisionAllow || effect.Reason() != policy.AuthorizationRepositoryPolicy || effect.ExpiresAtUnixMilliseconds()-effect.IssuedAtUnixMilliseconds() != int64((10*time.Minute)/time.Millisecond) {
		t.Fatalf("authorization=%#v", authorization)
	}
}
func TestRepositoryPublicationAuthorizerRejectsCrossScopeAndInvalidAuthority(t *testing.T) {
	_, plan := publicationPlanFixture(t)
	plan = acquiredPublicationPlanForTest(plan)
	authorizer, err := NewRepositoryPublicationAuthorizer("tenant", "repository", strings.Repeat("a", 64), strings.Repeat("b", 64), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	other, err := audit.NewReviewScope("tenant-a", "repo-b", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	if authorization, err := authorizer.Authorize(context.Background(), other, plan, time.Unix(1000, 0)); !errors.Is(err, ErrInvalidRepositoryPublicationAuthorizer) || authorization.Identity() != "" {
		t.Fatalf("authorization=(%#v,%v)", authorization, err)
	}
	if invalid, err := NewRepositoryPublicationAuthorizer("tenant-a", "repo-a", strings.Repeat("0", 64), strings.Repeat("b", 64), 10*time.Minute); !errors.Is(err, ErrInvalidRepositoryPublicationAuthorizer) || invalid != nil {
		t.Fatalf("invalid=(%#v,%v)", invalid, err)
	}
}
