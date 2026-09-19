package review

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

type recordingPublisher struct {
	publisherID           string
	configurationIdentity string
	result                PublicationResult
	calls                 int
	request               PublicationDispatchRequest
	guarantee             PublisherIdempotencyGuarantee
}

func (p *recordingPublisher) PublisherID() string { return p.publisherID }
func (p *recordingPublisher) ConfigurationIdentity() string {
	if p.configurationIdentity != "" {
		return p.configurationIdentity
	}
	return strings.Repeat("a", 64)
}
func (p *recordingPublisher) IdempotencyGuarantee() PublisherIdempotencyGuarantee {
	if p.guarantee == 0 {
		return PublisherExactOperationKey
	}
	return p.guarantee
}
func (p *recordingPublisher) Publish(_ context.Context, request PublicationDispatchRequest) PublicationResult {
	p.calls++
	p.request = request
	return p.result
}

func claimedPublicationFixture(t *testing.T) (audit.ReviewScope, PublicationAuthorization, PublicationClaim, PublicationAttemptAuthorization, PublicationHeadGate, time.Time) {
	t.Helper()
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	if _, err := RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at); err != nil {
		t.Fatal(err)
	}
	claim, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	if err != nil || !acquired {
		t.Fatalf("claim = (%#v,%t,%v)", claim, acquired, err)
	}
	attempt, _ := NewInitialPublicationAttemptAuthorization(authorization, claim)
	gate := currentHeadGateFixture(t, ledger, scope, authorization, claim, attempt, at.Add(2*time.Millisecond))
	return scope, authorization, claim, attempt, gate, at.Add(5 * time.Millisecond)
}

func TestDispatchClaimedPublicationUsesExactPublisherAndGrant(t *testing.T) {
	scope, authorization, claim, attempt, gate, at := claimedPublicationFixture(t)
	raw, _ := NewSuccessfulPublicationResult("external-comment-42")
	publisher := &recordingPublisher{publisherID: authorization.Plan().Target().PublisherID(), result: raw}
	result, err := DispatchClaimedPublication(context.Background(), publisher, scope, authorization, claim, attempt, gate, at)
	if err != nil {
		t.Fatal(err)
	}
	if publisher.calls != 1 || publisher.request.Authorization().Identity() != authorization.Identity() || publisher.request.Claim().Identity() != claim.Identity() || publisher.request.IdempotencyKey() != authorization.IdempotencyKey() || publisher.request.Validate() != nil || result.Identity() == "" || result.AuthorizationIdentity() != authorization.Identity() || result.ClaimIdentity() != claim.Identity() || result.HeadReconciliationIdentity() != gate.Reconciliation().Identity() || result.Status() != PublicationSucceeded || result.ExternalReferenceIdentity() == "" || result.Validate() != nil {
		t.Fatalf("publication dispatch failed: calls=%d request=%#v result=%#v", publisher.calls, publisher.request, result)
	}
	if strings.Contains(fmt.Sprintf("%v", result), "external-comment") || strings.Contains(fmt.Sprintf("%v", publisher.request), authorization.IdempotencyKey()) {
		t.Fatal("publication formatting leaked")
	}
}

func TestDispatchClaimedPublicationRejectsBeforePublisherCall(t *testing.T) {
	scope, authorization, claim, attempt, gate, at := claimedPublicationFixture(t)
	for _, test := range []struct {
		name          string
		ctx           context.Context
		publisher     Publisher
		authorization PublicationAuthorization
		claim         PublicationClaim
		attempt       PublicationAttemptAuthorization
		headGate      PublicationHeadGate
		at            time.Time
		want          error
	}{
		{"nil context", nil, &recordingPublisher{publisherID: "github"}, authorization, claim, attempt, gate, at, ErrInvalidPublisherContext},
		{"nil publisher", context.Background(), nil, authorization, claim, attempt, gate, at, ErrInvalidPublisher},
		{"wrong publisher", context.Background(), &recordingPublisher{publisherID: "gitlab"}, authorization, claim, attempt, gate, at, ErrPublicationPublisherMismatch},
		{"idempotency", context.Background(), &recordingPublisher{publisherID: "github", guarantee: 2}, authorization, claim, attempt, gate, at, ErrPublicationIdempotencyNotGuaranteed},
		{"claim", context.Background(), &recordingPublisher{publisherID: "github"}, authorization, PublicationClaim{}, attempt, gate, at, ErrInvalidPublicationClaim},
		{"expired", context.Background(), &recordingPublisher{publisherID: "github"}, authorization, claim, attempt, gate, time.UnixMilli(4_000_000), ErrPublicationNotAuthorized},
		{"old head check", context.Background(), &recordingPublisher{publisherID: "github"}, authorization, claim, attempt, gate, at.Add(3 * time.Second), ErrPublicationHeadNotCurrent},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := DispatchClaimedPublication(test.ctx, test.publisher, scope, test.authorization, test.claim, test.attempt, test.headGate, test.at)
			if !errors.Is(err, test.want) || result.Identity() != "" {
				t.Fatalf("DispatchClaimedPublication()=(%#v,%v),want %v", result, err, test.want)
			}
			if publisher, ok := test.publisher.(*recordingPublisher); ok && publisher.calls != 0 {
				t.Fatalf("publisher called %d times", publisher.calls)
			}
		})
	}
}

func TestDispatchClaimedPublicationRejectsMalformedResult(t *testing.T) {
	scope, authorization, claim, attempt, gate, at := claimedPublicationFixture(t)
	publisher := &recordingPublisher{publisherID: "github"}
	result, err := DispatchClaimedPublication(context.Background(), publisher, scope, authorization, claim, attempt, gate, at)
	if !errors.Is(err, ErrInvalidPublicationResult) || result.Identity() != "" || publisher.calls != 1 {
		t.Fatalf("malformed result=(%#v,%v),calls=%d", result, err, publisher.calls)
	}
}

func TestFailedPublicationResultUsesClosedClassification(t *testing.T) {
	result, err := NewFailedPublicationResult(PublicationFailureRateLimited, 900)
	if err != nil || result.Status() != PublicationFailed || result.Failure() != PublicationFailureRateLimited || result.RetryAfterMilliseconds() != 900 || result.Validate() != nil {
		t.Fatalf("failure result=(%#v,%v)", result, err)
	}
	if invalid, err := NewFailedPublicationResult(PublicationFailureTransient, 1); !errors.Is(err, ErrInvalidPublicationRetryAfter) || invalid.Identity() != "" {
		t.Fatalf("invalid retry after=(%#v,%v)", invalid, err)
	}
}

func TestRecordPublicationResultCompletesClaimOnce(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	_, _ = RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at)
	claim, acquired, _ := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	if !acquired {
		t.Fatal("claim not acquired")
	}
	attempt, _ := NewInitialPublicationAttemptAuthorization(authorization, claim)
	gate := currentHeadGateFixture(t, ledger, scope, authorization, claim, attempt, at.Add(2*time.Millisecond))
	raw, _ := NewSuccessfulPublicationResult("external-comment")
	publisher := &recordingPublisher{publisherID: "github", result: raw}
	result, _ := DispatchClaimedPublication(context.Background(), publisher, scope, authorization, claim, attempt, gate, at.Add(5*time.Millisecond))
	event, err := RecordPublicationResult(context.Background(), ledger, scope, authorization, claim, attempt, result, at.Add(6*time.Millisecond))
	if err != nil || event.Kind() != audit.EventPublicationCompleted || event.SubjectIdentity() != result.Identity() {
		t.Fatalf("completion=(%#v,%v)", event, err)
	}
	again, err := RecordPublicationResult(context.Background(), ledger, scope, authorization, claim, attempt, result, at.Add(7*time.Millisecond))
	if err != nil || again.Identity() != event.Identity() {
		t.Fatalf("idempotent completion=(%#v,%v)", again, err)
	}
	otherRaw, _ := NewSuccessfulPublicationResult("different-comment")
	otherPublisher := &recordingPublisher{publisherID: "github", result: otherRaw}
	other, _ := DispatchClaimedPublication(context.Background(), otherPublisher, scope, authorization, claim, attempt, gate, at.Add(5*time.Millisecond))
	if conflicting, err := RecordPublicationResult(context.Background(), ledger, scope, authorization, claim, attempt, other, at.Add(8*time.Millisecond)); !errors.Is(err, ErrPublicationCompletionConflict) || conflicting.Identity() != "" {
		t.Fatalf("conflicting completion=(%#v,%v)", conflicting, err)
	}
}

func TestDispatchClaimedPublicationRejectsStaleHead(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	_, _ = RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at)
	claim, _, _ := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	attempt, _ := NewInitialPublicationAttemptAuthorization(authorization, claim)
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	raw, _ := NewResolvedPublicationHeadObservation(otherHead)
	resolver := &recordingHeadResolver{resolverID: "github", observation: raw}
	observation, _ := ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, attempt, at.Add(2*time.Millisecond))
	reconciliation, _ := ReconcilePublicationHead(scope, authorization, claim, attempt, observation, at.Add(3*time.Millisecond))
	gate, _ := RecordPublicationHeadReconciliation(context.Background(), ledger, scope, authorization, claim, attempt, reconciliation, at.Add(4*time.Millisecond))
	resultRaw, _ := NewSuccessfulPublicationResult("must-not-publish")
	publisher := &recordingPublisher{publisherID: "github", result: resultRaw}
	result, err := DispatchClaimedPublication(context.Background(), publisher, scope, authorization, claim, attempt, gate, at.Add(5*time.Millisecond))
	if !errors.Is(err, ErrPublicationHeadNotCurrent) || result.Identity() != "" || publisher.calls != 0 {
		t.Fatalf("stale dispatch=(%#v,%v),calls=%d", result, err, publisher.calls)
	}
}

func TestDispatchClaimedPublicationRejectsCrossScopeBeforeEffect(t *testing.T) {
	scope, authorization, claim, attempt, gate, at := claimedPublicationFixture(t)
	other, _ := audit.NewReviewScope(scope.TenantID(), scope.RepositoryID(), "other-run")
	raw, _ := NewSuccessfulPublicationResult("external")
	publisher := &recordingPublisher{publisherID: authorization.Plan().Target().PublisherID(), result: raw}
	result, err := DispatchClaimedPublication(context.Background(), publisher, other, authorization, claim, attempt, gate, at)
	if !errors.Is(err, ErrInvalidPublicationClaim) || result.Identity() != "" || publisher.calls != 0 {
		t.Fatalf("result=(%#v,%v) calls=%d", result, err, publisher.calls)
	}
}
