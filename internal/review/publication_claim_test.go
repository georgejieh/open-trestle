package review

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/policy"
)

func authorizedPublicationFixture(t *testing.T, ledger audit.Ledger) (audit.ReviewScope, PublicationAuthorization) {
	t.Helper()
	scope, artifacts := modelPipelineArtifacts(t)
	sourceBindingIdentity := strings.Repeat("d", 64)
	sourceEvent, sourceErr := audit.NewEvent(
		scope, 1, "", audit.EventReviewSnapshotBound,
		sourceBindingIdentity, []string{artifacts.GenerationContext.SnapshotIdentity()}, time.UnixMilli(50),
	)
	if sourceErr != nil {
		t.Fatal(sourceErr)
	}
	if err := ledger.Append(context.Background(), "", sourceEvent); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordModelPipelineAudit(context.Background(), ledger, scope, artifacts, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	head, _, _ := ledger.Head(context.Background(), scope)
	contextEvent, contextErr := audit.NewEvent(
		scope, head.Sequence()+1, head.Identity(), audit.EventContextAcquisitionBound,
		strings.Repeat("e", 64), []string{artifacts.GenerationContext.Identity(), sourceBindingIdentity}, time.UnixMilli(150),
	)
	if contextErr != nil {
		t.Fatal(contextErr)
	}
	if err := ledger.Append(context.Background(), head.Identity(), contextEvent); err != nil {
		t.Fatal(err)
	}
	plan, err := newPublicationPlan(artifacts.PublicationReadiness, reviewPublicationTarget(t), sourceBindingIdentity)
	if err != nil {
		t.Fatal(err)
	}
	plan = acquiredPublicationPlanForTest(plan)
	issued := time.UnixMilli(200)
	effect, _ := policy.NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), scope.Identity(), policy.CapabilityPublication, policy.DecisionAllow, policy.AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour))
	authorization, err := NewPublicationAuthorization(plan, effect, issued.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return scope, authorization
}

func TestRecordAndClaimPublicationIsOrderedAndIdempotent(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	authorizedEvent, err := RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, time.UnixMilli(300))
	if err != nil || authorizedEvent.Kind() != audit.EventPublicationAuthorized || authorizedEvent.SubjectIdentity() != authorization.Identity() {
		t.Fatalf("authorization event = (%#v, %v)", authorizedEvent, err)
	}
	claim, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, time.UnixMilli(400))
	if err != nil || !acquired || claim.Identity() == "" || claim.AuthorizationIdentity() != authorization.Identity() || claim.IdempotencyKey() != authorization.IdempotencyKey() || claim.Validate() != nil {
		t.Fatalf("claim = (%#v, %t, %v)", claim, acquired, err)
	}
	again, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, time.UnixMilli(500))
	if err != nil || acquired || again.Identity() != "" {
		t.Fatalf("duplicate claim = (%#v, %t, %v)", again, acquired, err)
	}
}

func TestClaimPublicationSerializesConcurrentCallers(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	_, _ = RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, time.UnixMilli(300))
	claims := make(chan PublicationClaim, 2)
	acquiredValues := make(chan bool, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			claim, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, time.UnixMilli(400))
			claims <- claim
			acquiredValues <- acquired
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(claims)
	close(acquiredValues)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	count, nonzeroClaims := 0, 0
	for acquired := range acquiredValues {
		if acquired {
			count++
		}
	}
	for claim := range claims {
		if claim.Identity() != "" {
			nonzeroClaims++
		}
	}
	if count != 1 || nonzeroClaims != 1 {
		t.Fatalf("acquired=%d nonzero_claims=%d", count, nonzeroClaims)
	}
}

func TestClaimPublicationRejectsMissingAuthorizationAndScope(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	if claim, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, time.UnixMilli(400)); !errors.Is(err, ErrPublicationAuthorizationNotRecorded) || acquired || claim.Identity() != "" {
		t.Fatalf("missing authorization = (%#v, %t, %v)", claim, acquired, err)
	}
	otherScope, _ := audit.NewReviewScope("other", "repository", "review-run")
	if event, err := RecordPublicationAuthorization(context.Background(), ledger, otherScope, authorization, time.UnixMilli(300)); !errors.Is(err, ErrPublicationAuditScopeMismatch) || event.Identity() != "" {
		t.Fatalf("cross-scope authorization = (%#v, %v)", event, err)
	}
}
