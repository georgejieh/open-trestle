package review

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func failedPublicationAttemptFixture(t *testing.T, failure PublicationFailure, retryAfter uint32) (audit.Ledger, audit.ReviewScope, PublicationAuthorization, PublicationClaim, PublicationAttemptAuthorization, PublicationResult, time.Time) {
	t.Helper()
	ledger := audit.NewMemoryLedger()
	scope, authorization := authorizedPublicationFixture(t, ledger)
	at := time.UnixMilli(300)
	if _, err := RecordPublicationAuthorization(context.Background(), ledger, scope, authorization, at); err != nil {
		t.Fatal(err)
	}
	claim, acquired, err := ClaimPublication(context.Background(), ledger, scope, authorization, at.Add(time.Millisecond))
	if err != nil || !acquired {
		t.Fatal("claim unavailable")
	}
	attempt, err := NewInitialPublicationAttemptAuthorization(authorization, claim)
	if err != nil {
		t.Fatal(err)
	}
	gate := currentHeadGateFixture(t, ledger, scope, authorization, claim, attempt, at.Add(2*time.Millisecond))
	raw, err := NewFailedPublicationResult(failure, retryAfter)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &recordingPublisher{publisherID: "github", result: raw}
	result, err := DispatchClaimedPublication(context.Background(), publisher, scope, authorization, claim, attempt, gate, at.Add(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordPublicationResult(context.Background(), ledger, scope, authorization, claim, attempt, result, at.Add(6*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	return ledger, scope, authorization, claim, attempt, result, at.Add(7 * time.Millisecond)
}

func TestPublicationRetryAuthorizesBoundedSecondAttempt(t *testing.T) {
	ledger, scope, authorization, claim, first, result, evaluatedAt := failedPublicationAttemptFixture(t, PublicationFailureRateLimited, 900)
	policy, err := NewPublicationRetryPolicy(3, 100, 1_000)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := EvaluatePublicationRetry(policy, first, result, evaluatedAt)
	if err != nil || !decision.Allowed() || decision.Reason() != PublicationRetryRateLimited || decision.DelayMilliseconds() != 900 || decision.NextAttemptNumber() != 2 || decision.Validate() != nil {
		t.Fatalf("decision=(%#v,%v)", decision, err)
	}
	gate, err := RecordPublicationRetryDecision(context.Background(), ledger, scope, authorization, claim, first, result, decision, evaluatedAt.Add(time.Millisecond))
	if err != nil || !gate.AuthorizesRetry() || gate.EventIdentity() == "" || gate.Validate() != nil {
		t.Fatalf("retry gate=(%#v,%v)", gate, err)
	}
	second, err := NewRetryPublicationAttemptAuthorization(authorization, claim, first, gate)
	if err != nil || second.AttemptNumber() != 2 || second.PriorAttemptIdentity() != first.Identity() || second.RetryGateIdentity() != gate.Identity() || second.Ready(evaluatedAt) {
		t.Fatalf("second attempt=(%#v,%v)", second, err)
	}
	readyAt := decision.NotBefore()
	if !second.Ready(readyAt) {
		t.Fatal("second attempt not ready at bounded delay")
	}
	headGate := resolveHeadForAttempt(t, ledger, scope, authorization, claim, second, readyAt)
	raw, _ := NewSuccessfulPublicationResult("external-after-retry")
	publisher := &recordingPublisher{publisherID: "github", result: raw}
	published, err := DispatchClaimedPublication(context.Background(), publisher, scope, authorization, claim, second, headGate, readyAt.Add(3*time.Millisecond))
	if err != nil || published.Status() != PublicationSucceeded || published.AttemptIdentity() != second.Identity() || publisher.calls != 1 {
		t.Fatalf("retry dispatch=(%#v,%v),calls=%d", published, err, publisher.calls)
	}
	if _, err := RecordPublicationResult(context.Background(), ledger, scope, authorization, claim, second, published, readyAt.Add(4*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
}

func resolveHeadForAttempt(t *testing.T, ledger audit.Ledger, scope audit.ReviewScope, authorization PublicationAuthorization, claim PublicationClaim, attempt PublicationAttemptAuthorization, at time.Time) PublicationHeadGate {
	t.Helper()
	raw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	resolver := &recordingHeadResolver{resolverID: "github", observation: raw}
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

func TestPublicationRetryDeniesExhaustedPermanentAndExcessiveDelay(t *testing.T) {
	_, _, _, _, attempt, rateLimited, at := failedPublicationAttemptFixture(t, PublicationFailureRateLimited, 900)
	limitPolicy, _ := NewPublicationRetryPolicy(1, 100, 1_000)
	limited, err := EvaluatePublicationRetry(limitPolicy, attempt, rateLimited, at)
	if err != nil || limited.Allowed() || limited.Reason() != PublicationRetryAttemptLimit || limited.NextAttemptNumber() != 0 || limited.Validate() != nil {
		t.Fatalf("limited=(%#v,%v)", limited, err)
	}
	delayPolicy, _ := NewPublicationRetryPolicy(3, 100, 500)
	delayed, err := EvaluatePublicationRetry(delayPolicy, attempt, rateLimited, at)
	if err != nil || delayed.Allowed() || delayed.Reason() != PublicationRetryDelayLimit {
		t.Fatalf("delayed=(%#v,%v)", delayed, err)
	}
	ledger, scope, authorization, claim, attempt, permanent, at := failedPublicationAttemptFixture(t, PublicationFailureStaleHead, 0)
	policy, _ := NewPublicationRetryPolicy(3, 100, 1_000)
	denied, err := EvaluatePublicationRetry(policy, attempt, permanent, at)
	if err != nil || denied.Allowed() || denied.Reason() != PublicationRetryPermanentFailure {
		t.Fatalf("permanent=(%#v,%v)", denied, err)
	}
	if gate, err := RecordPublicationRetryDecision(context.Background(), ledger, scope, authorization, claim, attempt, permanent, denied, at.Add(time.Millisecond)); !errors.Is(err, ErrPublicationRetryNotAllowed) || gate.Identity() != "" {
		t.Fatalf("denied gate=(%#v,%v)", gate, err)
	}
}

func TestPublicationRetryRequiresRecordedFailureAndDelay(t *testing.T) {
	ledger, scope, authorization, claim, attempt, result, at := failedPublicationAttemptFixture(t, PublicationFailureTransient, 0)
	policy, _ := NewPublicationRetryPolicy(3, 500, 1_000)
	decision, _ := EvaluatePublicationRetry(policy, attempt, result, at)
	gate, err := RecordPublicationRetryDecision(context.Background(), ledger, scope, authorization, claim, attempt, result, decision, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewRetryPublicationAttemptAuthorization(authorization, claim, attempt, gate)
	raw, _ := NewResolvedPublicationHeadObservation(authorization.Plan().Target().HeadRevision())
	resolver := &recordingHeadResolver{resolverID: "github", observation: raw}
	if observation, err := ResolvePublicationHead(context.Background(), resolver, scope, authorization, claim, second, at.Add(100*time.Millisecond)); !errors.Is(err, ErrPublicationRetryNotAllowed) || observation.Identity() != "" || resolver.calls != 0 {
		t.Fatalf("early resolve=(%#v,%v),calls=%d", observation, err, resolver.calls)
	}

	freshLedger := audit.NewMemoryLedger()
	freshScope, freshAuthorization := authorizedPublicationFixture(t, freshLedger)
	base := time.UnixMilli(300)
	_, _ = RecordPublicationAuthorization(context.Background(), freshLedger, freshScope, freshAuthorization, base)
	freshClaim, _, _ := ClaimPublication(context.Background(), freshLedger, freshScope, freshAuthorization, base.Add(time.Millisecond))
	freshAttempt, _ := NewInitialPublicationAttemptAuthorization(freshAuthorization, freshClaim)
	freshGate := currentHeadGateFixture(t, freshLedger, freshScope, freshAuthorization, freshClaim, freshAttempt, base.Add(2*time.Millisecond))
	failureRaw, _ := NewFailedPublicationResult(PublicationFailureTransient, 0)
	publisher := &recordingPublisher{publisherID: "github", result: failureRaw}
	unrecorded, _ := DispatchClaimedPublication(context.Background(), publisher, freshScope, freshAuthorization, freshClaim, freshAttempt, freshGate, base.Add(5*time.Millisecond))
	freshDecision, _ := EvaluatePublicationRetry(policy, freshAttempt, unrecorded, base.Add(6*time.Millisecond))
	if retryGate, err := RecordPublicationRetryDecision(context.Background(), freshLedger, freshScope, freshAuthorization, freshClaim, freshAttempt, unrecorded, freshDecision, base.Add(7*time.Millisecond)); !errors.Is(err, ErrPublicationRetryNotRecorded) || retryGate.Identity() != "" {
		t.Fatalf("unrecorded retry=(%#v,%v)", retryGate, err)
	}
}

func TestPublicationRetryDecisionSerializesCompetingPolicies(t *testing.T) {
	ledger, scope, authorization, claim, attempt, result, at := failedPublicationAttemptFixture(t, PublicationFailureTransient, 0)
	firstPolicy, _ := NewPublicationRetryPolicy(3, 100, 1_000)
	secondPolicy, _ := NewPublicationRetryPolicy(3, 200, 1_000)
	first, _ := EvaluatePublicationRetry(firstPolicy, attempt, result, at)
	second, _ := EvaluatePublicationRetry(secondPolicy, attempt, result, at)
	decisions := []PublicationRetryDecision{first, second}
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, decision := range decisions {
		decision := decision
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := RecordPublicationRetryDecision(context.Background(), ledger, scope, authorization, claim, attempt, result, decision, at.Add(time.Millisecond))
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrPublicationRetryConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("results successes=%d conflicts=%d", successes, conflicts)
	}
}
