package review

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"strings"
	"testing"
	"time"
)

func TestPublicationPlanAcceptsExactProtectedSourceBinding(t *testing.T) {
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	publicationPolicy, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	readiness, err := EvaluatePublicationReadiness(publicationPolicy, receipt, set)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	if scope.Identity() != receipt.ReviewScopeIdentity() {
		t.Fatal("fixture scope mismatch")
	}
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	target, _ := NewPublicationTarget("github-review", repository, "42", head)
	ids := func(marker string) string { return strings.Repeat(marker, 64) }
	binding, err := NewProtectedSourceBinding(scope, repository, head, ids("1"), ids("2"), ids("3"), ids("4"), ids("5"), ids("6"), ids("7"), readiness.GenerationContextIdentity(), set.SnapshotIdentity(), []string{ids("8")})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPublicationPlanFromProtectedSource(readiness, target, binding)
	if err != nil || plan.Validate() != nil || !plan.HasAcquiredSource() || plan.SourceSnapshotBindingIdentity() != binding.SourceIdentity() || plan.AcquiredContextBindingIdentity() != binding.ContextBindingIdentity() {
		t.Fatalf("plan=(%#v,%v)", plan, err)
	}
	ledger := audit.NewMemoryLedger()
	auditReceipt, err := RecordProtectedPublicationPrerequisites(context.Background(), ledger, scope, binding, readiness, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	if auditReceipt.SourceEvent().Kind() != audit.EventReviewSnapshotBound || auditReceipt.ContextEvent().Kind() != audit.EventContextAcquisitionBound || auditReceipt.ReadinessEvent().Kind() != audit.EventPublicationReadinessEvaluated {
		t.Fatalf("audit=%#v", auditReceipt)
	}
	effect, _ := policy.NewEffectAuthorization(ids("9"), ids("a"), scope.Identity(), policy.CapabilityPublication, policy.DecisionAllow, policy.AuthorizationExplicitUserApproval, time.UnixMilli(90), time.UnixMilli(1000))
	authorization, err := NewPublicationAuthorization(plan, effect, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, time.UnixMilli(101)); err != nil {
		t.Fatal(err)
	}
	if _, claimed, err := ClaimPublication(context.Background(), ledger, scope, authorization, time.UnixMilli(102)); err != nil || !claimed {
		t.Fatalf("claim=(%v,%v)", claimed, err)
	}
}
