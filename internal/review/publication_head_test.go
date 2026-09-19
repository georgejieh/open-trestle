package review

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

type recordingHeadResolver struct {
	resolverID            string
	configurationIdentity string
	observation           PublicationHeadObservation
	calls                 int
	request               PublicationHeadRequest
}

func (r *recordingHeadResolver) ResolverID() string { return r.resolverID }
func (r *recordingHeadResolver) ConfigurationIdentity() string {
	if r.configurationIdentity != "" {
		return r.configurationIdentity
	}
	return strings.Repeat("a", 64)
}
func (r *recordingHeadResolver) ResolveHead(_ context.Context, request PublicationHeadRequest) PublicationHeadObservation {
	r.calls++
	r.request = request
	return r.observation
}

func currentHeadGateFixture(t *testing.T, ledger audit.Ledger, scope audit.ReviewScope, authorization PublicationAuthorization, claim PublicationClaim, attempt PublicationAttemptAuthorization, at time.Time) PublicationHeadGate {
	t.Helper()
	raw, err := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	if err != nil {
		t.Fatal(err)
	}
	resolver := &recordingHeadResolver{resolverID: authorization.Plan().Target().PublisherID(), observation: raw}
	observation, err := ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at)
	if err != nil {
		t.Fatal(err)
	}
	reconciliation, err := ReconcilePublicationHead(scope, authorization, claim, attempt, observation, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := RecordPublicationHeadReconciliation(context.Background(), ledger, scope, authorization, claim, attempt, reconciliation, at.Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func TestResolveAndReconcileCurrentPublicationHead(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	_, _ = RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at)
	claim, _, _ := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	attempt, _ := NewInitialPublicationAttemptAuthorization(authorization, claim)
	raw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	resolver := &recordingHeadResolver{resolverID: "github", observation: raw}
	observation, err := ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at.Add(2*time.Millisecond))
	if err != nil || resolver.calls != 1 || resolver.request.Target().Identity() != authorization.TargetIdentity() || observation.Identity() == "" || observation.Validate() != nil {
		t.Fatalf("observation=(%#v,%v),calls=%d", observation, err, resolver.calls)
	}
	reconciliation, err := ReconcilePublicationHead(scope, authorization, claim, attempt, observation, at.Add(3*time.Millisecond))
	if err != nil || reconciliation.Status() != PublicationHeadCurrent || !reconciliation.AuthorizesPublication() || reconciliation.Validate() != nil {
		t.Fatalf("reconciliation=(%#v,%v)", reconciliation, err)
	}
	gate, err := RecordPublicationHeadReconciliation(context.Background(), ledger, scope, authorization, claim, attempt, reconciliation, at.Add(4*time.Millisecond))
	if err != nil || !gate.AuthorizesPublication() || gate.EventIdentity() == "" || gate.Validate() != nil {
		t.Fatalf("gate=(%#v,%v)", gate, err)
	}
}

func TestReconcilePublicationHeadDetectsStaleAndUnavailable(t *testing.T) {
	scope, authorization, claim, attempt, at := publicationClaimStateFixture(t)
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	staleRaw, _ := NewResolvedPublicationHeadObservation(otherHead)
	resolver := &recordingHeadResolver{resolverID: "github", observation: staleRaw}
	observation, _ := ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at)
	stale, err := ReconcilePublicationHead(scope, authorization, claim, attempt, observation, at.Add(time.Millisecond))
	if err != nil || stale.Status() != PublicationHeadStale || stale.AuthorizesPublication() {
		t.Fatalf("stale=(%#v,%v)", stale, err)
	}
	failedRaw, _ := NewFailedPublicationHeadObservation(PublicationHeadFailureTransient)
	resolver.observation = failedRaw
	observation, _ = ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at)
	unavailable, err := ReconcilePublicationHead(scope, authorization, claim, attempt, observation, at.Add(time.Millisecond))
	if err != nil || unavailable.Status() != PublicationHeadUnavailable || unavailable.AuthorizesPublication() {
		t.Fatalf("unavailable=(%#v,%v)", unavailable, err)
	}
}

func TestResolvePublicationHeadFailsClosedBeforeResolverCall(t *testing.T) {
	scope, authorization, claim, attempt, at := publicationClaimStateFixture(t)
	raw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	for _, test := range []struct {
		name     string
		resolver HeadResolver
		claim    PublicationClaim
		want     error
	}{
		{"nil", nil, claim, ErrInvalidHeadResolver}, {"wrong resolver", &recordingHeadResolver{resolverID: "gitlab", observation: raw}, claim, ErrPublicationHeadResolverMismatch}, {"claim", &recordingHeadResolver{resolverID: "github", observation: raw}, PublicationClaim{}, ErrInvalidPublicationClaim},
	} {
		t.Run(test.name, func(t *testing.T) {
			observation, err := ResolvePublicationHead(context.Background(), test.resolver, scope, authorization, test.claim, attempt, at)
			if !errors.Is(err, test.want) || observation.Identity() != "" {
				t.Fatalf("ResolvePublicationHead()=(%#v,%v),want %v", observation, err, test.want)
			}
			if resolver, ok := test.resolver.(*recordingHeadResolver); ok && resolver.calls != 0 {
				t.Fatalf("resolver called %d times", resolver.calls)
			}
		})
	}
}

func publicationClaimStateFixture(t *testing.T) (audit.ReviewScope, PublicationAuthorization, PublicationClaim, PublicationAttemptAuthorization, time.Time) {
	t.Helper()
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	_, _ = RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at)
	claim, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	if err != nil || !acquired {
		t.Fatal("claim unavailable")
	}
	attempt, _ := NewInitialPublicationAttemptAuthorization(authorization, claim)
	return scope, authorization, claim, attempt, at.Add(2 * time.Millisecond)
}

func TestRecordPublicationHeadReconciliationRejectsSecondDecision(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	_, _ = RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at)
	claim, _, _ := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	attempt, _ := NewInitialPublicationAttemptAuthorization(authorization, claim)
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	staleRaw, _ := NewResolvedPublicationHeadObservation(otherHead)
	resolver := &recordingHeadResolver{resolverID: "github", observation: staleRaw}
	observed, _ := ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at.Add(2*time.Millisecond))
	stale, _ := ReconcilePublicationHead(scope, authorization, claim, attempt, observed, at.Add(3*time.Millisecond))
	first, err := RecordPublicationHeadReconciliation(context.Background(), ledger, scope, authorization, claim, attempt, stale, at.Add(4*time.Millisecond))
	if err != nil || first.Identity() == "" || first.AuthorizesPublication() {
		t.Fatalf("first gate=(%#v,%v)", first, err)
	}
	currentRaw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	resolver.observation = currentRaw
	observed, _ = ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at.Add(5*time.Millisecond))
	current, _ := ReconcilePublicationHead(scope, authorization, claim, attempt, observed, at.Add(6*time.Millisecond))
	if second, err := RecordPublicationHeadReconciliation(context.Background(), ledger, scope, authorization, claim, attempt, current, at.Add(7*time.Millisecond)); !errors.Is(err, ErrPublicationHeadReconciliationConflict) || second.Identity() != "" {
		t.Fatalf("second gate=(%#v,%v)", second, err)
	}
}

func TestResolvePublicationHeadRejectsCrossScopeBeforeEffect(t *testing.T) {
	scope, authorization, claim, attempt, at := publicationClaimStateFixture(t)
	other, _ := audit.NewReviewScope(scope.TenantID(), scope.RepositoryID(), "other-run")
	raw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	resolver := &recordingHeadResolver{resolverID: authorization.Plan().Target().PublisherID(), observation: raw}
	observation, err := ResolvePublicationHead(context.Background(), resolver, other, authorization, claim, attempt, at)
	if !errors.Is(err, ErrInvalidPublicationHeadRequest) || observation.Identity() != "" || resolver.calls != 0 {
		t.Fatalf("observation=(%#v,%v) calls=%d", observation, err, resolver.calls)
	}
}
