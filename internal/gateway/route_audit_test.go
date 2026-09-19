package gateway

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func TestRouteAuditRecordsCompleteSuccessfulAttempt(t *testing.T) {
	ctx := context.Background()
	ledger := audit.NewMemoryLedger()
	scope := newRoutingScope(t)
	request, fixture, _ := newInitialAttemptFixture(t)
	selectionEvent, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(1))
	if err != nil || selectionEvent.Sequence() != 1 || selectionEvent.Kind() != audit.EventRouteSelected || selectionEvent.SubjectIdentity() != fixture.selection.Identity() {
		t.Fatalf("selection event = (%#v, %v)", selectionEvent, err)
	}
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	claim, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, authorization, time.UnixMilli(2))
	if err != nil || !acquired || claim.Sequence() != 2 || claim.Kind() != audit.EventRouteAttemptClaimed || claim.SubjectIdentity() != authorization.Identity() {
		t.Fatalf("claim event = (%#v, %v)", claim, err)
	}
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: successfulDispatchResult(t)}
	result, _ := DispatchAuthorizedRoute(ctx, dispatcher, authorization, request)
	outcome, _ := NewRouteAttemptOutcomeFromDispatch(authorization, result, 4)
	dispatchEvent, err := RecordRouteDispatchCompleted(ctx, ledger, scope, authorization, result, outcome, time.UnixMilli(3))
	if err != nil || dispatchEvent.Sequence() != 3 || dispatchEvent.SubjectIdentity() != outcome.Identity() {
		t.Fatalf("dispatch event = (%#v, %v)", dispatchEvent, err)
	}
	duplicate, err := RecordRouteDispatchCompleted(ctx, ledger, scope, authorization, result, outcome, time.UnixMilli(30))
	if err != nil || duplicate.Identity() != dispatchEvent.Identity() {
		t.Fatalf("idempotent dispatch event = (%#v, %v)", duplicate, err)
	}
	otherOutcome, _ := NewRouteAttemptOutcomeFromDispatch(authorization, result, 5)
	if event, err := RecordRouteDispatchCompleted(ctx, ledger, scope, authorization, result, otherOutcome, time.UnixMilli(31)); !errors.Is(err, ErrRouteAuditTerminalConflict) || event.Identity() != "" {
		t.Fatalf("second terminal outcome = (%#v, %v)", event, err)
	}
	reconciliation, _ := ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
	costEvent, err := RecordRouteCostReconciliation(ctx, ledger, scope, authorization, outcome, reconciliation, time.UnixMilli(4))
	if err != nil || costEvent.Sequence() != 4 || costEvent.SubjectIdentity() != reconciliation.Identity() {
		t.Fatalf("cost event = (%#v, %v)", costEvent, err)
	}
	plan, _ := PlanRouteContinuation(fixture.selection, fixture.ranking, NewNoRouteRetryPolicy(), NewNoRouteFallbackPolicy(), authorization, outcome, reconciliation, []string{authorization.RouteRecordIdentity()})
	continuationEvent, err := RecordRouteContinuationPlan(ctx, ledger, scope, authorization, outcome, reconciliation, plan, time.UnixMilli(5))
	if err != nil || continuationEvent.Sequence() != 5 || continuationEvent.SubjectIdentity() != plan.Identity() {
		t.Fatalf("continuation event = (%#v, %v)", continuationEvent, err)
	}
	events, _ := ledger.Read(ctx, scope, 0, 10)
	if len(events) != 5 {
		t.Fatalf("event count = %d", len(events))
	}
	for index := 1; index < len(events); index++ {
		if events[index].PreviousIdentity() != events[index-1].Identity() {
			t.Fatalf("broken chain at event %d", index+1)
		}
	}
}

func TestClaimRouteAttemptIsIdempotentAndScopeBound(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope := newRoutingScope(t)
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if _, err := RecordRouteSelection(context.Background(), ledger, scope, fixture.selection, time.UnixMilli(1)); err != nil {
		t.Fatal(err)
	}
	first, acquired, err := ClaimRouteAttempt(context.Background(), ledger, scope, authorization, time.UnixMilli(2))
	if err != nil || !acquired {
		t.Fatal(err)
	}
	second, acquired, err := ClaimRouteAttempt(context.Background(), ledger, scope, authorization, time.UnixMilli(3))
	if err != nil || acquired || second.Identity() != first.Identity() {
		t.Fatalf("duplicate claim = (%#v, %v)", second, err)
	}
	events, _ := ledger.Read(context.Background(), scope, 0, 10)
	if len(events) != 2 {
		t.Fatalf("event count = %d", len(events))
	}
	otherScope, _ := audit.NewReviewScope("other-tenant", "repository", "review-run")
	if claim, acquired, err := ClaimRouteAttempt(context.Background(), ledger, otherScope, authorization, time.UnixMilli(3)); !errors.Is(err, ErrRouteAuditScopeMismatch) || acquired || claim.Identity() != "" {
		t.Fatalf("cross-scope claim = (%#v, %v)", claim, err)
	}
}

func TestConcurrentRouteAttemptClaimsReturnOneEvent(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope := newRoutingScope(t)
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	if _, err := RecordRouteSelection(context.Background(), ledger, scope, fixture.selection, time.UnixMilli(1)); err != nil {
		t.Fatal(err)
	}
	results := make(chan audit.Event, 2)
	errorsSeen := make(chan error, 2)
	acquiredSeen := make(chan bool, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			event, acquired, err := ClaimRouteAttempt(context.Background(), ledger, scope, authorization, time.UnixMilli(2))
			results <- event
			acquiredSeen <- acquired
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errorsSeen)
	close(acquiredSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	acquiredCount := 0
	for acquired := range acquiredSeen {
		if acquired {
			acquiredCount++
		}
	}
	if acquiredCount != 1 {
		t.Fatalf("acquired count = %d", acquiredCount)
	}
	identity := ""
	for event := range results {
		if identity == "" {
			identity = event.Identity()
		}
		if event.Identity() != identity {
			t.Fatal("concurrent claims returned different events")
		}
	}
	events, _ := ledger.Read(context.Background(), scope, 0, 10)
	if len(events) != 2 {
		t.Fatalf("event count = %d", len(events))
	}
}

func TestRouteAuditRejectsCrossWiredRecords(t *testing.T) {
	ledger := audit.NewMemoryLedger()
	scope := newRoutingScope(t)
	request, fixture, _ := newInitialAttemptFixture(t)
	authorization, _ := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
	rawFailure, _ := NewFailedRouteDispatchResult(RouteFailureTimeout, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
	dispatcher := &recordingRouteDispatcher{adapterID: authorization.RouteReference().AdapterID(), result: rawFailure}
	result, _ := DispatchAuthorizedRoute(context.Background(), dispatcher, authorization, request)
	outcome, _ := NewRouteAttemptOutcomeFromDispatch(authorization, result, 1)
	forged := outcome
	forged.authorizationIdentity = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	forged.identity = deriveRouteAttemptOutcomeIdentity(forged)
	if event, err := RecordRouteDispatchCompleted(context.Background(), ledger, scope, authorization, result, forged, time.UnixMilli(1)); !errors.Is(err, ErrRouteAuditRecordMismatch) || event.Identity() != "" {
		t.Fatalf("cross-wired dispatch event = (%#v, %v)", event, err)
	}
	if event, err := RecordRouteSelection(context.Background(), nil, scope, fixture.selection, time.UnixMilli(1)); !errors.Is(err, ErrInvalidRouteAuditLedger) || event.Identity() != "" {
		t.Fatalf("nil ledger = (%#v, %v)", event, err)
	}
}
