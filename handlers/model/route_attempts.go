package model

import (
	"context"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// routeAttempt is one claimed, dispatched, recorded and settled model request.
type routeAttempt struct {
	authorization  gateway.RouteAttemptAuthorization
	result         gateway.RouteDispatchResult
	outcome        gateway.RouteAttemptOutcome
	reconciliation gateway.RouteCostReconciliation
	// finished is when the attempt's dispatch returned.
	finished time.Time
}

// routeDispatch sends the task's one request under authorization.
type routeDispatch func(context.Context, gateway.RouteAttemptAuthorization) (gateway.RouteDispatchResult, error)

// routeWait waits out one retry delay unless ctx ends first.
type routeWait func(context.Context, time.Duration) error

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// settleRouteAttempts claims, dispatches, records and settles the task's model
// request under authorization, starting at started. When the provider refused
// it with a rate limit before processing it, the request is retried on the
// same route at most gateway.MaxRateLimitRetries times inside this task
// attempt: each retry is its own claimed and recorded route attempt that takes
// over the refused attempt's reservation, sent after the delay its retry
// decision allows (the provider's Retry-After, at least the task's fixed retry
// delay). A delay that would end after ctx's deadline is not waited for; the
// rate-limited attempt is returned instead. It returns the last settled
// attempt, or a failed completion when the task cannot continue.
func settleRouteAttempts(ctx context.Context, task controlplane.TaskExecutionRequest, ledger audit.Ledger, clock artifact.Clock, wait routeWait, authorization gateway.RouteAttemptAuthorization, started time.Time, dispatch routeDispatch) (routeAttempt, controlplane.TaskCompletion, bool) {
	if wait == nil {
		wait = waitForRetry
	}
	policy, err := gateway.NewRateLimitRetryPolicy(task.Task().RetryDelayMilliseconds())
	if err != nil {
		return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
	}
	scope := task.Plan().Scope()
	for {
		if _, acquired, err := gateway.ClaimRouteAttempt(ctx, ledger, scope, authorization, started); err != nil || !acquired {
			return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
		}
		result, err := dispatch(ctx, authorization)
		if err != nil {
			return routeAttempt{}, generationFailure(controlplane.RunFailurePolicy), false
		}
		finished := clock.Now().UTC()
		duration, ok := boundedDurationMilliseconds(started, finished)
		if !ok {
			return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
		}
		outcome, err := gateway.NewRouteAttemptOutcomeFromDispatch(authorization, result, duration)
		if err != nil {
			return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
		}
		if _, err := gateway.RecordRouteDispatchCompleted(ctx, ledger, scope, authorization, result, outcome, finished); err != nil {
			return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
		}
		reconciliation, err := gateway.ReconcileAuthorizedRouteAttemptCost(authorization, outcome)
		if err != nil {
			return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
		}
		if _, err := gateway.RecordRouteCostReconciliation(ctx, ledger, scope, authorization, outcome, reconciliation, finished); err != nil {
			return routeAttempt{}, generationFailure(controlplane.RunFailureInternal), false
		}
		if reconciliation.Status() == gateway.RouteCostBudgetExceeded {
			return routeAttempt{}, generationFailure(controlplane.RunFailurePolicy), false
		}
		attempt := routeAttempt{authorization: authorization, result: result, outcome: outcome, reconciliation: reconciliation, finished: finished}
		next, delay, retry := rateLimitRetry(policy, attempt)
		if !retry {
			return attempt, controlplane.TaskCompletion{}, true
		}
		if deadline, bounded := ctx.Deadline(); bounded && time.Until(deadline) < delay {
			return attempt, controlplane.TaskCompletion{}, true
		}
		if err := wait(ctx, delay); err != nil {
			return routeAttempt{}, generationFailure(controlplane.RunFailureCanceled), false
		}
		authorization, started = next, clock.Now().UTC()
	}
}

// settleAnswer settles the task's request as settleRouteAttempts does and
// reads the answer with parse. When the answer is not usable (answerRetry),
// the same request is sent once more and the retry's answer decides. It
// returns the attempt whose answer parse accepted, or the failed completion
// of the last attempt.
func settleAnswer(ctx context.Context, task controlplane.TaskExecutionRequest, ledger audit.Ledger, clock artifact.Clock, wait routeWait, gate AnswerRetryGate, authorization gateway.RouteAttemptAuthorization, started time.Time, dispatch routeDispatch, parse func(routeAttempt) error, observe AnswerRejectionObserver) (routeAttempt, controlplane.TaskCompletion, bool) {
	for retried := false; ; retried = true {
		attempt, failed, settled := settleRouteAttempts(ctx, task, ledger, clock, wait, authorization, started, dispatch)
		if !settled {
			return routeAttempt{}, failed, false
		}
		var rejected error
		if attempt.result.Status() != gateway.RouteDispatchFailed {
			if rejected = parse(attempt); rejected == nil {
				return attempt, controlplane.TaskCompletion{}, true
			}
		}
		if !retried {
			if next, ok := answerRetry(gate, attempt, rejected); ok {
				authorization, started = next, clock.Now().UTC()
				continue
			}
		}
		if rejected == nil {
			return routeAttempt{}, routeFailureCompletion(task, attempt.result), false
		}
		return routeAttempt{}, answerFailureCompletion(task, attempt.result.Response(), rejected, observe), false
	}
}

// AnswerRetryGate is asked, before a request whose answer was not usable is
// sent once more, whether the retry may spend what it reserves. It is not
// part of a handler's identity; the retry is recorded as its own claimed and
// settled route attempt.
type AnswerRetryGate func(reservedMicroUSD uint64) bool

// answerRetry returns the authorization of the one retry a settled attempt
// gets when its answer is not usable: an output_exhausted failure, or, with
// rejected set, an answer the review parser marked model_output_invalid for a
// reason other than a refusal after a normal stop. It is false without a
// gate, when the gate refuses the spend, or when the gateway grants none.
func answerRetry(gate AnswerRetryGate, attempt routeAttempt, rejected error) (gateway.RouteAttemptAuthorization, bool) {
	if gate == nil {
		return gateway.RouteAttemptAuthorization{}, false
	}
	if rejected == nil {
		if attempt.result.Status() != gateway.RouteDispatchFailed || attempt.result.Failure() != gateway.RouteFailureOutputExhausted {
			return gateway.RouteAttemptAuthorization{}, false
		}
	} else if problem, marked := review.ModelOutputProblemOf(rejected); !marked || problem == review.ModelOutputRefusal || attempt.result.Response().FinishReason() != provider.ResponseFinishStop {
		return gateway.RouteAttemptAuthorization{}, false
	}
	next, err := gateway.NewAnswerRetryAttemptAuthorization(attempt.authorization, attempt.outcome, attempt.reconciliation)
	if err != nil || !gate(next.ReservedCostMicroUSD()) {
		return gateway.RouteAttemptAuthorization{}, false
	}
	return next, true
}

// rateLimitRetry returns the takeover retry and its delay after a rate limit
// the provider refused before processing, or false for any other attempt or
// once the policy allows no further retry.
func rateLimitRetry(policy gateway.RouteRetryPolicy, attempt routeAttempt) (gateway.RouteAttemptAuthorization, time.Duration, bool) {
	if attempt.result.Status() != gateway.RouteDispatchFailed || attempt.outcome.Failure() != gateway.RouteFailureRateLimited || attempt.outcome.ReplaySafety() != gateway.RouteReplayNoSideEffect {
		return gateway.RouteAttemptAuthorization{}, 0, false
	}
	decision, err := gateway.EvaluateRouteAttemptRetry(policy, attempt.authorization, attempt.outcome)
	if err != nil || !decision.ShouldRetry() {
		return gateway.RouteAttemptAuthorization{}, 0, false
	}
	next, err := gateway.NewRateLimitedRetryAttemptAuthorization(attempt.authorization, attempt.outcome, attempt.reconciliation, decision)
	if err != nil {
		return gateway.RouteAttemptAuthorization{}, 0, false
	}
	return next, time.Duration(decision.MinimumDelayMilliseconds()) * time.Millisecond, true
}
