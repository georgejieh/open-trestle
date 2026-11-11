package model

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// steppingClock is a fake clock that only a fake wait advances.
type steppingClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

// waitFor advances the clock by each delay instead of sleeping and records it.
func (c *steppingClock) waitFor(delays *[]time.Duration) routeWait {
	return func(_ context.Context, delay time.Duration) error {
		c.mu.Lock()
		c.at = c.at.Add(delay)
		c.mu.Unlock()
		*delays = append(*delays, delay)
		return nil
	}
}

// sequencedDispatcher answers each dispatch with the next result and records
// every authorization it was sent under.
type sequencedDispatcher struct {
	recordingDispatcher
	results        []gateway.RouteDispatchResult
	authorizations []string
}

func (d *sequencedDispatcher) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	d.authorizations = append(d.authorizations, request.Authorization().Identity())
	d.result = d.results[min(d.calls, len(d.results)-1)]
	return d.recordingDispatcher.DispatchRoute(ctx, request)
}

func rateLimited(t *testing.T, retryAfter uint32) gateway.RouteDispatchResult {
	t.Helper()
	result, err := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureRateLimited, gateway.RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), retryAfter)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type rateLimitRun struct {
	completion controlplane.TaskCompletion
	dispatcher *sequencedDispatcher
	delays     []time.Duration
	ledger     *audit.MemoryLedger
	scope      audit.ReviewScope
	initial    gateway.RouteAttemptAuthorization
	store      artifact.Store
	input      artifact.Artifact
	context    artifact.Artifact
	clock      *steppingClock
}

// runRateLimitedGeneration executes one generation attempt whose provider
// answers with results in turn, under ctx.
func runRateLimitedGeneration(t *testing.T, ctx context.Context, results ...gateway.RouteDispatchResult) rateLimitRun {
	t.Helper()
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &sequencedDispatcher{recordingDispatcher: recordingDispatcher{adapterID: "test-model"}, results: results}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	clock := &steppingClock{at: time.UnixMilli(200)}
	handler, err := newLegacyGenerationHandler(store, catalog, ledger, clock)
	if err != nil {
		t.Fatal(err)
	}
	run := rateLimitRun{dispatcher: dispatcher, ledger: ledger, scope: scope, initial: authorization, store: store, context: contextArtifact, clock: clock}
	handler.wait = clock.waitFor(&run.delays)
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	run.input = inputArtifact
	run.completion = handler.Execute(ctx, generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
	return run
}

// A request the provider rate-limited is retried on the same route inside the
// task attempt after its Retry-After, and the success settles from the usage
// it reported under the retry's own authorization, which kept the reservation.
func TestGenerationRetriesARateLimitedRequestThenSucceeds(t *testing.T) {
	run := runRateLimitedGeneration(t, context.Background(), rateLimited(t, 7_000), successfulProviderResult(t))
	if run.completion.Status() != controlplane.TaskCompletionSucceeded || run.dispatcher.calls != 2 || !slices.Equal(run.delays, []time.Duration{7 * time.Second}) {
		t.Fatalf("status=%s calls=%d delays=%v", run.completion.Status(), run.dispatcher.calls, run.delays)
	}
	if run.dispatcher.authorizations[0] != run.initial.Identity() || run.dispatcher.authorizations[1] == run.initial.Identity() {
		t.Fatal("the retry was not sent under its own authorization")
	}
	stored, err := run.store.Get(context.Background(), run.scope, run.completion.OutputIdentity(), run.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseGenerationResultArtifact(stored, run.input, run.context)
	if err != nil {
		t.Fatalf("the retried result did not read back: %v", err)
	}
	execution := result.RouteExecution()
	retry := execution.Authorization()
	if retry.Kind() != gateway.RouteAttemptRetry || retry.AttemptOrdinal() != 2 || !gateway.IsSameReservationRetryOf(run.initial, retry) || retry.ReservedCostMicroUSD() != run.initial.ReservedCostMicroUSD() {
		t.Fatalf("success authorization kind=%s ordinal=%d", retry.Kind(), retry.AttemptOrdinal())
	}
	if usage := execution.Outcome().Usage(); !usage.IsKnown() || usage.InputTokens() != 10 || usage.OutputTokens() != 5 || !execution.Reconciliation().ActualCost().IsKnown() {
		t.Fatal("the success did not settle from the usage it reported")
	}
	assertRecordedRateLimitAttempts(t, run, 2)
}

// Three rate limits exhaust the two retries and fail the task once as a
// transient provider rate limit.
func TestGenerationStopsAfterTwoRateLimitRetries(t *testing.T) {
	run := runRateLimitedGeneration(t, context.Background(), rateLimited(t, 2_000), rateLimited(t, 0), rateLimited(t, 3_000))
	if run.completion.Status() != controlplane.TaskCompletionFailed || run.completion.Failure() != controlplane.RunFailureTransient || run.completion.FailureReason() != controlplane.TaskFailureReasonProviderRateLimited || run.dispatcher.calls != 3 {
		t.Fatalf("failure=%s reason=%s calls=%d", run.completion.Failure(), run.completion.FailureReason(), run.dispatcher.calls)
	}
	// The second rate limit named no Retry-After, so its retry waited the
	// task's fixed delay.
	if !slices.Equal(run.delays, []time.Duration{2 * time.Second, time.Second}) {
		t.Fatalf("delays=%v", run.delays)
	}
	assertRecordedRateLimitAttempts(t, run, 3)
}

// A Retry-After that would end after the run deadline is not waited for: the
// task fails at once as a rate limit, with nothing retried.
func TestGenerationDoesNotWaitPastTheRunDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	run := runRateLimitedGeneration(t, ctx, rateLimited(t, 30_000), successfulProviderResult(t))
	if run.completion.Failure() != controlplane.RunFailureTransient || run.completion.FailureReason() != controlplane.TaskFailureReasonProviderRateLimited || run.dispatcher.calls != 1 || len(run.delays) != 0 {
		t.Fatalf("failure=%s calls=%d delays=%v", run.completion.Failure(), run.dispatcher.calls, run.delays)
	}
	assertRecordedRateLimitAttempts(t, run, 1)
}

// assertRecordedRateLimitAttempts reads the audit ledger back: each attempt is
// claimed, completed and settled once, each retry's claim binds the refused
// attempt's outcome and comes exactly its delay after that outcome.
func assertRecordedRateLimitAttempts(t *testing.T, run rateLimitRun, attempts int) {
	t.Helper()
	events, err := run.ledger.Read(context.Background(), run.scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var claims, completions []audit.Event
	reconciled := 0
	for _, event := range events {
		switch event.Kind() {
		case audit.EventRouteAttemptClaimed:
			claims = append(claims, event)
		case audit.EventRouteDispatchCompleted:
			completions = append(completions, event)
		case audit.EventRouteCostReconciled:
			reconciled++
		}
	}
	if len(claims) != attempts || len(completions) != attempts || reconciled != attempts {
		t.Fatalf("recorded %d claims, %d completions, %d settlements; want %d each", len(claims), len(completions), reconciled, attempts)
	}
	for index := range claims {
		if claims[index].SubjectIdentity() != run.dispatcher.authorizations[index] {
			t.Fatalf("claim %d is not the dispatched authorization", index)
		}
		if index == 0 {
			continue
		}
		if !slices.Contains(claims[index].CausalParentIdentities(), completions[index-1].SubjectIdentity()) {
			t.Fatalf("retry %d does not bind the refused attempt's outcome", index)
		}
		if gap := time.Duration(claims[index].OccurredAtUnixMilliseconds()-completions[index-1].OccurredAtUnixMilliseconds()) * time.Millisecond; gap != run.delays[index-1] {
			t.Fatalf("retry %d was claimed %v after the refusal, want %v", index, gap, run.delays[index-1])
		}
	}
}
