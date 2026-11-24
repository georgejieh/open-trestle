package model

import (
	"context"
	"slices"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func notJSONAnswer(t *testing.T) gateway.RouteDispatchResult {
	return providerAnswerResult(t, provider.ResponsePartAssistantText, provider.ResponseFinishStop, "<|message|>"+invalidAnswerLeak)
}

func exhaustedAnswer(t *testing.T) gateway.RouteDispatchResult {
	t.Helper()
	usage, _ := provider.NewRouteTokenUsage(10, 5, 0)
	result, err := gateway.NewFailedRouteDispatchResult(gateway.RouteFailureOutputExhausted, gateway.RouteReplayOutcomeUnknown, usage, 0)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// countingGate allows every retry and records what each reserves.
func countingGate(reserved *[]uint64, allow bool) AnswerRetryGate {
	return func(amount uint64) bool {
		*reserved = append(*reserved, amount)
		return allow
	}
}

// An answer that is not usable is sent once more under its own claimed,
// settled authorization; the retry's answer decides, and the rejected
// attempt stays recorded and settled.
func TestGenerationRetriesAnAnswerThatIsNotUsable(t *testing.T) {
	for name, first := range map[string]func(*testing.T) gateway.RouteDispatchResult{"not json": notJSONAnswer, "output exhausted": exhaustedAnswer} {
		t.Run(name, func(t *testing.T) {
			var reserved []uint64
			run := runGeneration(t, context.Background(), countingGate(&reserved, true), first(t), successfulProviderResult(t))
			if run.completion.Status() != controlplane.TaskCompletionSucceeded || run.dispatcher.calls != 2 || !slices.Equal(reserved, []uint64{run.initial.ReservedCostMicroUSD()}) {
				t.Fatalf("status=%s calls=%d reserved=%v", run.completion.Status(), run.dispatcher.calls, reserved)
			}
			if run.dispatcher.authorizations[1] == run.initial.Identity() || len(run.delays) != 0 {
				t.Fatal("the retry reused the first authorization or waited")
			}
			stored, err := run.store.Get(context.Background(), run.scope, run.completion.OutputIdentity(), run.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			result, err := ParseGenerationResultArtifact(stored, run.input, run.context)
			if err != nil {
				t.Fatalf("the retried result did not read back: %v", err)
			}
			if retry := result.RouteExecution().Authorization(); retry.Kind() != gateway.RouteAttemptRetry || retry.RouteAttemptOrdinal() != 2 || !gateway.IsSameReservationRetryOf(run.initial, retry) {
				t.Fatalf("retry kind=%s ordinal=%d", retry.Kind(), retry.RouteAttemptOrdinal())
			}
			assertAnswerRetryRecorded(t, run, 2)
		})
	}
}

// A second answer that is not usable fails the task as the first would have,
// with nothing sent a third time.
func TestGenerationAnswerRetryIsSentOnce(t *testing.T) {
	var reserved []uint64
	run := runGeneration(t, context.Background(), countingGate(&reserved, true), notJSONAnswer(t), notJSONAnswer(t), successfulProviderResult(t))
	if run.completion.FailureReason() != controlplane.TaskFailureReasonModelOutputInvalid || run.dispatcher.calls != 2 || len(reserved) != 1 {
		t.Fatalf("reason=%s calls=%d gate calls=%d", run.completion.FailureReason(), run.dispatcher.calls, len(reserved))
	}
	assertAnswerRetryRecorded(t, run, 2)
	run = runGeneration(t, context.Background(), countingGate(&reserved, true), notJSONAnswer(t), exhaustedAnswer(t))
	if run.completion.Failure() != controlplane.RunFailureInternal || run.completion.FailureReason() == controlplane.TaskFailureReasonModelOutputInvalid || run.dispatcher.calls != 2 {
		t.Fatalf("the second failure did not decide: reason=%s calls=%d", run.completion.FailureReason(), run.dispatcher.calls)
	}
}

// Without a gate, with a gate that refuses the spend, for a refusal, and for
// a provider refusal, nothing is sent again.
func TestGenerationDoesNotRetryOtherFailures(t *testing.T) {
	var reserved []uint64
	refusal := providerAnswerResult(t, provider.ResponsePartRefusal, provider.ResponseFinishStop, invalidAnswerLeak)
	payment, _ := gateway.NewFailedRouteDispatchResult(gateway.RouteFailurePaymentRequired, gateway.RouteReplayNoSideEffect, provider.NewUnknownRouteTokenUsage(), 0)
	for name, run := range map[string]rateLimitRun{
		"no gate":          runGeneration(t, context.Background(), nil, notJSONAnswer(t), successfulProviderResult(t)),
		"refused spend":    runGeneration(t, context.Background(), countingGate(&reserved, false), notJSONAnswer(t), successfulProviderResult(t)),
		"refusal":          runGeneration(t, context.Background(), countingGate(&reserved, true), refusal, successfulProviderResult(t)),
		"payment required": runGeneration(t, context.Background(), countingGate(&reserved, true), payment, successfulProviderResult(t)),
	} {
		if run.completion.Status() != controlplane.TaskCompletionFailed || run.dispatcher.calls != 1 {
			t.Fatalf("%s: status=%s calls=%d", name, run.completion.Status(), run.dispatcher.calls)
		}
	}
	if len(reserved) != 1 {
		t.Fatalf("the gate was asked %d times, want once (the refused spend)", len(reserved))
	}
}

// assertAnswerRetryRecorded reads the audit ledger back: each attempt is
// claimed, completed and settled once, and the retry's claim binds the
// rejected attempt's outcome.
func assertAnswerRetryRecorded(t *testing.T, run rateLimitRun, attempts int) {
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
	if !slices.Contains(claims[1].CausalParentIdentities(), completions[0].SubjectIdentity()) {
		t.Fatal("the retry does not bind the rejected attempt's outcome")
	}
}
