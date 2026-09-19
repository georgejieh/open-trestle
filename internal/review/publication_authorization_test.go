package review

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
)

func reviewPublicationTarget(t *testing.T) PublicationTarget {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	revision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	target, err := NewPublicationTarget("github", repository, "pull-42", revision)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func publicationPlanFixture(t *testing.T) (PublicationReadiness, PublicationPlan) {
	t.Helper()
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	publicationPolicy, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	readiness, _ := EvaluatePublicationReadiness(publicationPolicy, receipt, set)
	plan, err := newPublicationPlan(readiness, reviewPublicationTarget(t), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	return readiness, plan
}

func TestNewPublicationPlanBindsReadinessTargetAndSourceSnapshot(t *testing.T) {
	readiness, plan := publicationPlanFixture(t)
	if plan.Identity() == "" || plan.ReviewScopeIdentity() != readiness.ReviewScopeIdentity() || plan.ReadinessIdentity() != readiness.Identity() || plan.Target().Identity() == "" || plan.SourceSnapshotBindingIdentity() != strings.Repeat("d", 64) || plan.InlineFindingCount() != 1 || plan.SummaryOnlyFindingCount() != 0 || plan.AuthorizesPublication() || plan.Validate() != nil {
		t.Fatalf("publication plan did not round trip: %#v", plan)
	}
}

func TestNewPublicationPlanRejectsBlockedReadinessAndInvalidBinding(t *testing.T) {
	receipt, set := verifiedSetFixture(t, "inconclusive", gateway.RouteIndependenceDistinctProvider)
	publicationPolicy, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	blocked, _ := EvaluatePublicationReadiness(publicationPolicy, receipt, set)
	if plan, err := newPublicationPlan(blocked, reviewPublicationTarget(t), strings.Repeat("d", 64)); !errors.Is(err, ErrPublicationPlanNotReady) || plan.Identity() != "" {
		t.Fatalf("blocked plan = (%#v, %v)", plan, err)
	}
	readiness, _ := publicationPlanFixture(t)
	if plan, err := newPublicationPlan(readiness, reviewPublicationTarget(t), "bad"); !errors.Is(err, ErrInvalidSourceSnapshotBinding) || plan.Identity() != "" {
		t.Fatalf("invalid source binding = (%#v, %v)", plan, err)
	}
}

func TestNewPublicationAuthorizationRequiresLiveAllowDecision(t *testing.T) {
	_, plan := publicationPlanFixture(t)
	plan = acquiredPublicationPlanForTest(plan)
	issued := time.UnixMilli(1_700_000_000_000)
	effect, _ := policy.NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), plan.ReviewScopeIdentity(), policy.CapabilityPublication, policy.DecisionAllow, policy.AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour))
	authorization, err := NewPublicationAuthorization(plan, effect, issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Identity() == "" || authorization.PlanIdentity() != plan.Identity() || authorization.TargetIdentity() != plan.Target().Identity() || authorization.EffectAuthorizationIdentity() != effect.Identity() || authorization.IdempotencyKey() == "" || !authorization.Authorizes(plan.Target(), issued.Add(30*time.Minute)) || authorization.Authorizes(plan.Target(), issued.Add(2*time.Hour)) || authorization.Validate() != nil {
		t.Fatalf("publication authorization did not round trip: %#v", authorization)
	}
	if authorization.Authorizes(reviewPublicationTargetWithChange(t, "pull-43"), issued.Add(30*time.Minute)) {
		t.Fatal("authorization allowed another target")
	}
}

func reviewPublicationTargetWithChange(t *testing.T, change string) PublicationTarget {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	revision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	target, _ := NewPublicationTarget("github", repository, change, revision)
	return target
}

func TestNewPublicationAuthorizationRejectsDenialScopeAndCapability(t *testing.T) {
	_, plan := publicationPlanFixture(t)
	plan = acquiredPublicationPlanForTest(plan)
	issued := time.UnixMilli(1_700_000_000_000)
	for _, test := range []struct {
		name       string
		capability policy.Capability
		outcome    policy.DecisionOutcome
		scope      string
		want       error
	}{
		{"denied", policy.CapabilityPublication, policy.DecisionDeny, plan.ReviewScopeIdentity(), ErrPublicationNotAuthorized},
		{"capability", policy.CapabilitySourceMutation, policy.DecisionAllow, plan.ReviewScopeIdentity(), ErrPublicationNotAuthorized},
		{"scope", policy.CapabilityPublication, policy.DecisionAllow, strings.Repeat("c", 64), ErrPublicationNotAuthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			effect, _ := policy.NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), test.scope, test.capability, test.outcome, policy.AuthorizationRepositoryPolicy, issued, issued.Add(time.Hour))
			authorization, err := NewPublicationAuthorization(plan, effect, issued.Add(time.Minute))
			if !errors.Is(err, test.want) || authorization.Identity() != "" {
				t.Fatalf("NewPublicationAuthorization() = (%#v, %v)", authorization, err)
			}
		})
	}
}

func acquiredPublicationPlanForTest(plan PublicationPlan) PublicationPlan {
	plan.hasAcquiredSource = true
	plan.sourceRepositoryIdentity = plan.target.RepositoryIdentity().Identity()
	plan.sourceHeadRevisionIdentity = plan.target.HeadRevision().Identity()
	plan.acquiredContextBindingIdentity = strings.Repeat("e", 64)
	plan.identity = derivePublicationPlanIdentity(plan)
	return plan
}

func TestNewPublicationAuthorizationRejectsUnboundSourcePlan(t *testing.T) {
	_, plan := publicationPlanFixture(t)
	issued := time.UnixMilli(1_700_000_000_000)
	effect, _ := policy.NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), plan.ReviewScopeIdentity(), policy.CapabilityPublication, policy.DecisionAllow, policy.AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour))
	authorization, err := NewPublicationAuthorization(plan, effect, issued.Add(time.Minute))
	if !errors.Is(err, ErrInvalidSourceSnapshotBinding) || authorization.Identity() != "" {
		t.Fatalf("unbound authorization=(%#v,%v)", authorization, err)
	}
}
