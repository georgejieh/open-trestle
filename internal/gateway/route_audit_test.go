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

// A valid audit.Event only proves the event encoding, not the route-selection parent contract.
func TestRouteSelectionRejectsExistingWrongParentsBeforeClaim(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			var ledger audit.Ledger = audit.NewMemoryLedger()
			if storage == "file" {
				file, err := audit.NewFileLedger(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
				ledger = file
			}
			ctx := context.Background()
			scope := newRoutingScope(t)
			request, fixture, _ := newInitialAttemptFixture(t)
			authorization, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
			if err != nil {
				t.Fatal(err)
			}
			parents := []string{fixture.selection.RoutingInputIdentity(), fixture.selection.SelectedRecordIdentity(), fixture.selection.RankingPolicyIdentity()}
			for i, parent := range parents {
				if parent == fixture.selection.SelectedRecordIdentity() {
					parents[i] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
					break
				}
			}
			wrong, err := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, fixture.selection.Identity(), parents, time.UnixMilli(1))
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Append(ctx, "", wrong); err != nil {
				t.Fatal(err)
			}
			if event, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(2)); !errors.Is(err, ErrRouteAuditRecordMismatch) || event.Identity() != "" {
				t.Fatalf("wrong-parent selection = (%#v, %v), want integrity error", event, err)
			}
			if event, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, authorization, time.UnixMilli(3)); !errors.Is(err, ErrRouteAuditRecordMismatch) || acquired || event.Identity() != "" {
				t.Fatalf("wrong-parent claim = (%#v, %t, %v), want denial", event, acquired, err)
			}
			events, err := ledger.Read(ctx, scope, 0, 10)
			if err != nil || len(events) != 1 {
				t.Fatalf("events = (%d, %v), want only forged selection", len(events), err)
			}
		})
	}
}

func TestRouteSelectionRejectsConflictingDuplicateAndKeepsExactIdempotence(t *testing.T) {
	ctx := context.Background()
	ledger := audit.NewMemoryLedger()
	scope := newRoutingScope(t)
	_, fixture, _ := newInitialAttemptFixture(t)
	first, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	same, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(2))
	if err != nil || same.Identity() != first.Identity() {
		t.Fatalf("exact idempotence = (%#v, %v)", same, err)
	}
	parents := []string{fixture.selection.RoutingInputIdentity(), fixture.selection.SelectedRecordIdentity(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	wrong, err := audit.NewEvent(scope, 2, first.Identity(), audit.EventRouteSelected, fixture.selection.Identity(), parents, time.UnixMilli(3))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(ctx, first.Identity(), wrong); err != nil {
		t.Fatal(err)
	}
	if event, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(4)); !errors.Is(err, ErrRouteAuditRecordMismatch) || event.Identity() != "" {
		t.Fatalf("conflicting duplicate = (%#v, %v), want integrity error", event, err)
	}
	otherScope, err := audit.NewReviewScope("other-tenant", "repository", "review-run")
	if err != nil {
		t.Fatal(err)
	}
	if event, err := RecordRouteSelection(ctx, ledger, otherScope, fixture.selection, time.UnixMilli(5)); !errors.Is(err, ErrRouteAuditScopeMismatch) || event.Identity() != "" {
		t.Fatalf("wrong scope = (%#v, %v)", event, err)
	}
}

// A fallback uses the original selection receipt, but its route is not the first selected record.
func TestRouteAuditClaimsFallbackAfterFailedInitialAttempt(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			var ledger audit.Ledger = audit.NewMemoryLedger()
			if storage == "file" {
				file, err := audit.NewFileLedger(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
				ledger = file
			}
			ctx := context.Background()
			scope := newRoutingScope(t)
			free := mustKnownFreePricing(t)
			primary := newFallbackRoute(t, 141_000, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier4, free)
			next := newFallbackRoute(t, 141_001, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, provider.RouteQualityTier3, free)
			fixture := newFallbackFixture(t, 0, next, primary)
			request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte("fallback payload"))
			if err != nil {
				t.Fatal(err)
			}
			initial, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			if _, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, initial, time.UnixMilli(2)); err != nil || !acquired {
				t.Fatalf("initial claim = (%t, %v)", acquired, err)
			}
			rawFailure, err := NewFailedRouteDispatchResult(RouteFailureConnection, RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := &recordingRouteDispatcher{adapterID: initial.RouteReference().AdapterID(), result: rawFailure}
			result, err := DispatchAuthorizedRoute(ctx, dispatcher, initial, request)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := NewRouteAttemptOutcomeFromDispatch(initial, result, 5)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RecordRouteDispatchCompleted(ctx, ledger, scope, initial, result, outcome, time.UnixMilli(3)); err != nil {
				t.Fatal(err)
			}
			reconciliation, err := ReconcileAuthorizedRouteAttemptCost(initial, outcome)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RecordRouteCostReconciliation(ctx, ledger, scope, initial, outcome, reconciliation, time.UnixMilli(4)); err != nil {
				t.Fatal(err)
			}
			policy, err := NewRouteFallbackPolicy(2, nil)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := PlanRouteAttemptFallback(fixture.selection, fixture.ranking, policy, initial, outcome, reconciliation, []string{initial.RouteRecordIdentity()})
			if err != nil || !decision.ShouldFallback() {
				t.Fatalf("fallback decision = (%#v, %v)", decision, err)
			}
			fallback, err := NewRouteFallbackAttemptAuthorization(initial, outcome, reconciliation, decision, fixture.selection, fixture.ranking)
			if err != nil {
				t.Fatal(err)
			}
			if fallback.SelectionReceiptIdentity() != initial.SelectionReceiptIdentity() || fallback.RouteRecordIdentity() == initial.RouteRecordIdentity() {
				t.Fatal("fixture did not change route under the same selection")
			}
			claim, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, fallback, time.UnixMilli(5))
			if err != nil || !acquired || claim.SubjectIdentity() != fallback.Identity() {
				t.Fatalf("fallback claim = (%#v, %t, %v)", claim, acquired, err)
			}
			duplicate, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, fallback, time.UnixMilli(6))
			if err != nil || acquired || duplicate.Identity() != claim.Identity() {
				t.Fatalf("fallback duplicate = (%#v, %t, %v)", duplicate, acquired, err)
			}
			head, _, err := ledger.Head(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			parents := []string{fixture.selection.RoutingInputIdentity(), fixture.selection.SelectedRecordIdentity(), fixture.selection.RankingPolicyIdentity()}
			secondSelection, err := audit.NewEvent(scope, head.Sequence()+1, head.Identity(), audit.EventRouteSelected, fixture.selection.Identity(), parents, time.UnixMilli(7))
			if err != nil {
				t.Fatal(err)
			}
			if err := ledger.Append(ctx, head.Identity(), secondSelection); err != nil {
				t.Fatal(err)
			}
			if event, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, fallback, time.UnixMilli(8)); !errors.Is(err, ErrRouteAuditRecordMismatch) || acquired || event.Identity() != "" {
				t.Fatalf("duplicate selection fallback claim = (%#v, %t, %v)", event, acquired, err)
			}
		})
	}
}

func TestRouteAuditClaimsSameRecordRetry(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			var ledger audit.Ledger = audit.NewMemoryLedger()
			if storage == "file" {
				file, err := audit.NewFileLedger(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := file.Close(); err != nil {
						t.Error(err)
					}
				})
				ledger = file
			}
			ctx := context.Background()
			scope := newRoutingScope(t)
			request, fixture, _ := newInitialAttemptFixture(t)
			initial, err := NewInitialRouteAttemptAuthorization(request, fixture.selection, fixture.ranking)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RecordRouteSelection(ctx, ledger, scope, fixture.selection, time.UnixMilli(1)); err != nil {
				t.Fatal(err)
			}
			if _, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, initial, time.UnixMilli(2)); err != nil || !acquired {
				t.Fatalf("initial claim = (%t, %v)", acquired, err)
			}
			usage, err := provider.NewRouteTokenUsage(0, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			rawFailure, err := NewFailedRouteDispatchResult(RouteFailureTimeout, RouteReplayNoSideEffect, usage, 0)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := &recordingRouteDispatcher{adapterID: initial.RouteReference().AdapterID(), result: rawFailure}
			result, err := DispatchAuthorizedRoute(ctx, dispatcher, initial, request)
			if err != nil {
				t.Fatal(err)
			}
			outcome, err := NewRouteAttemptOutcomeFromDispatch(initial, result, 10)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RecordRouteDispatchCompleted(ctx, ledger, scope, initial, result, outcome, time.UnixMilli(3)); err != nil {
				t.Fatal(err)
			}
			reconciliation, err := ReconcileAuthorizedRouteAttemptCost(initial, outcome)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RecordRouteCostReconciliation(ctx, ledger, scope, initial, outcome, reconciliation, time.UnixMilli(4)); err != nil {
				t.Fatal(err)
			}
			policy, err := NewRouteRetryPolicy(3, 100, 1_000, 0, 2_000)
			if err != nil {
				t.Fatal(err)
			}
			decision, err := EvaluateRouteAttemptRetry(policy, initial, outcome)
			if err != nil || !decision.ShouldRetry() {
				t.Fatalf("retry decision = (%#v, %v)", decision, err)
			}
			retry, err := NewRouteRetryAttemptAuthorization(initial, outcome, reconciliation, decision)
			if err != nil {
				t.Fatal(err)
			}
			if retry.RouteRecordIdentity() != initial.RouteRecordIdentity() {
				t.Fatal("retry changed selected record")
			}
			claim, acquired, err := ClaimRouteAttempt(ctx, ledger, scope, retry, time.UnixMilli(5))
			if err != nil || !acquired || claim.SubjectIdentity() != retry.Identity() {
				t.Fatalf("retry claim = (%#v, %t, %v)", claim, acquired, err)
			}
		})
	}
}
