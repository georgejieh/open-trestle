package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const maxCoordinatorConflicts = 16

var (
	// ErrInvalidCoordinator identifies a missing coordinator.
	ErrInvalidCoordinator = errors.New("invalid review run coordinator")
	// ErrInvalidCoordinatorJournal identifies a missing durable journal.
	ErrInvalidCoordinatorJournal = errors.New("invalid coordinator run journal")
	// ErrRunNotOpened identifies a scope without an opened event stream.
	ErrRunNotOpened = errors.New("review run is not opened")
	// ErrReviewTaskNotFound identifies a task key outside the immutable plan.
	ErrReviewTaskNotFound = errors.New("review task not found")
	// ErrTaskAlreadyCompleted identifies a competing terminal result.
	ErrTaskAlreadyCompleted = errors.New("review task already completed")
	// ErrInvalidTaskLease identifies a malformed or forged worker capability.
	ErrInvalidTaskLease = errors.New("invalid review task lease")
	// ErrInvalidTaskLeaseIdentity identifies lease content inconsistent with its identity.
	ErrInvalidTaskLeaseIdentity = errors.New("invalid review task lease identity")
	// ErrInvalidTaskCompletion identifies malformed closed worker output.
	ErrInvalidTaskCompletion = errors.New("invalid review task completion")
	// ErrInvalidTaskCompletionIdentity identifies completion content inconsistent with its identity.
	ErrInvalidTaskCompletionIdentity = errors.New("invalid review task completion identity")
	// ErrCoordinatorContention identifies sustained compare-and-append conflicts.
	ErrCoordinatorContention = errors.New("review run coordinator contention")
	// ErrCoordinatorRandomness identifies failure to create a lease secret.
	ErrCoordinatorRandomness = errors.New("review run coordinator randomness")
	// ErrTaskLeaseRenewalLimit preserves journal capacity for task and run termination.
	ErrTaskLeaseRenewalLimit = errors.New("task lease renewal limit")
)

// TaskLease is a secret-bearing worker capability. Its formatting is always redacted.
type TaskLease struct {
	identity        string
	planIdentity    string
	taskKey         string
	taskIdentity    string
	handlerIdentity string
	workerIdentity  string
	token           string
	tokenIdentity   string
	eventIdentity   string
	attempt         uint8
	expiresAtMillis int64
}

func newTaskLease(plan ReviewRunPlan, event RunEvent, token string) (TaskLease, error) {
	lease := TaskLease{
		planIdentity: plan.Identity(), taskKey: event.TaskKey(), taskIdentity: event.TaskIdentity(),
		handlerIdentity: planTaskHandler(plan, event.TaskKey()), workerIdentity: event.WorkerIdentity(),
		token: token, tokenIdentity: event.LeaseTokenIdentity(), eventIdentity: event.Identity(),
		attempt: event.Attempt(), expiresAtMillis: event.leaseExpiresAtMillis,
	}
	lease.identity = deriveTaskLeaseIdentity(lease)
	if err := lease.Validate(); err != nil {
		return TaskLease{}, err
	}
	return lease, nil
}
func (l TaskLease) Identity() string        { return l.identity }
func (l TaskLease) PlanIdentity() string    { return l.planIdentity }
func (l TaskLease) TaskKey() string         { return l.taskKey }
func (l TaskLease) TaskIdentity() string    { return l.taskIdentity }
func (l TaskLease) HandlerIdentity() string { return l.handlerIdentity }
func (l TaskLease) WorkerIdentity() string  { return l.workerIdentity }
func (l TaskLease) Attempt() uint8          { return l.attempt }
func (l TaskLease) ExpiresAt() time.Time    { return runMillisToTime(l.expiresAtMillis) }
func (l TaskLease) EventIdentity() string   { return l.eventIdentity }
func (l TaskLease) Validate() error {
	validPlan := validControlPlaneDigest(l.planIdentity)
	validTask := validReviewTaskKey(l.taskKey) && validControlPlaneDigest(l.taskIdentity)
	validHandler := validControlPlaneDigest(l.handlerIdentity)
	validWorker := validWorkerIdentity(l.workerIdentity)
	validToken := validLeaseToken(l.token) && deriveLeaseTokenIdentity(l.token) == l.tokenIdentity
	validEvent := validControlPlaneDigest(l.eventIdentity)
	if !validPlan || !validTask || !validHandler || !validWorker || l.attempt == 0 || !validToken || !validEvent || !validRunMillis(l.expiresAtMillis) {
		return ErrInvalidTaskLease
	}
	if l.identity != deriveTaskLeaseIdentity(l) {
		return ErrInvalidTaskLeaseIdentity
	}
	return nil
}
func (l TaskLease) String() string   { return "review task lease" }
func (l TaskLease) GoString() string { return "controlplane.TaskLease{<redacted>}" }
func (l TaskLease) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review task lease", "controlplane.TaskLease{<redacted>}")
}

// TaskCompletionStatus identifies closed worker output.
type TaskCompletionStatus uint8

const (
	TaskCompletionSucceeded TaskCompletionStatus = iota + 1
	TaskCompletionFailed
)

func (s TaskCompletionStatus) String() string {
	switch s {
	case TaskCompletionSucceeded:
		return "succeeded"
	case TaskCompletionFailed:
		return "failed"
	default:
		return ""
	}
}
func (s TaskCompletionStatus) Validate() error {
	if s.String() == "" {
		return ErrInvalidTaskCompletion
	}
	return nil
}

// TaskCompletion is bounded worker output without provider error strings.
type TaskCompletion struct {
	identity       string
	planIdentity   string
	taskIdentity   string
	status         TaskCompletionStatus
	outputIdentity string
	failure        RunFailure
	reason         TaskFailureReason
	shortfall      TaskFailureContextShortfall
	// retryAfterMillis is the delay a provider asked for before another
	// attempt of a rate-limited model task; zero when it named none.
	retryAfterMillis uint32
}

func NewTaskSuccess(outputIdentity string) (TaskCompletion, error) {
	if !validControlPlaneDigest(outputIdentity) {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	completion := TaskCompletion{status: TaskCompletionSucceeded, outputIdentity: outputIdentity}
	completion.identity = deriveTaskCompletionIdentity(completion)
	return completion, nil
}
func NewTaskFailure(failure RunFailure) (TaskCompletion, error) {
	if failure.String() == "" {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	completion := TaskCompletion{status: TaskCompletionFailed, failure: failure}
	completion.identity = deriveTaskCompletionIdentity(completion)
	return completion, nil
}

// NewContextTaskFailureWithOutput binds a failed context result to one plan and task.
// The caller must verify the stored artifact kind, scope, and content before admission.
func NewContextTaskFailureWithOutput(failure RunFailure, plan ReviewRunPlan, task TaskDefinition, artifactIdentity string) (TaskCompletion, error) {
	if failure.String() == "" || plan.Validate() != nil || task.Validate() != nil || task.Kind() != TaskAssembleContext || !validControlPlaneDigest(artifactIdentity) {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	canonical, exists := plan.Task(task.Key())
	if !exists || canonical.Identity() != task.Identity() {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	completion := TaskCompletion{status: TaskCompletionFailed, failure: failure, outputIdentity: artifactIdentity, planIdentity: plan.Identity(), taskIdentity: task.Identity()}
	completion.identity = deriveTaskCompletionIdentity(completion)
	return completion, nil
}
func (c TaskCompletion) Identity() string             { return c.identity }
func (c TaskCompletion) Status() TaskCompletionStatus { return c.status }
func (c TaskCompletion) OutputIdentity() string       { return c.outputIdentity }
func (c TaskCompletion) Failure() RunFailure          { return c.failure }

// FailureReason returns the content-free reason of a failed source task, or zero.
func (c TaskCompletion) FailureReason() TaskFailureReason { return c.reason }

// ContextShortfall returns the counts of a route_context_insufficient refusal.
func (c TaskCompletion) ContextShortfall() (TaskFailureContextShortfall, bool) {
	return c.shortfall, c.shortfall.Present()
}

// RetryAfterMilliseconds returns the delay a provider asked for before
// another attempt of a rate-limited model task, or zero.
func (c TaskCompletion) RetryAfterMilliseconds() uint32 { return c.retryAfterMillis }
func (c TaskCompletion) Validate() error {
	if c.status == TaskCompletionSucceeded {
		if !validControlPlaneDigest(c.outputIdentity) || c.failure != 0 || c.reason != 0 || c.shortfall.Present() || c.planIdentity != "" || c.taskIdentity != "" {
			return ErrInvalidTaskCompletion
		}
	} else if c.status == TaskCompletionFailed && c.reason != 0 {
		if c.failure.String() == "" || c.reason.Validate() != nil || !taskFailureReasonFailureAllowed(c.reason, c.failure) || c.shortfall.Present() != (c.reason == TaskFailureReasonRouteContextInsufficient) || c.shortfall.Present() && !c.shortfall.valid() || c.outputIdentity != "" || !validControlPlaneDigest(c.planIdentity) || !validControlPlaneDigest(c.taskIdentity) {
			return ErrInvalidTaskCompletion
		}
	} else if c.status == TaskCompletionFailed {
		if c.failure.String() == "" || c.shortfall.Present() || (c.outputIdentity == "" && (c.planIdentity != "" || c.taskIdentity != "")) || (c.outputIdentity != "" && (!validControlPlaneDigest(c.outputIdentity) || !validControlPlaneDigest(c.planIdentity) || !validControlPlaneDigest(c.taskIdentity))) {
			return ErrInvalidTaskCompletion
		}
	} else {
		return ErrInvalidTaskCompletion
	}
	if c.retryAfterMillis != 0 && (c.reason != TaskFailureReasonProviderRateLimited || c.retryAfterMillis > maxReviewTaskRetryDelayMillis) {
		return ErrInvalidTaskCompletion
	}
	if c.identity != deriveTaskCompletionIdentity(c) {
		return ErrInvalidTaskCompletionIdentity
	}
	return nil
}
func (c TaskCompletion) String() string   { return "review task completion" }
func (c TaskCompletion) GoString() string { return "controlplane.TaskCompletion{<redacted>}" }
func (c TaskCompletion) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review task completion", "controlplane.TaskCompletion{<redacted>}")
}

// Coordinator performs optimistic, restartable review-run transitions.
type Coordinator struct {
	journal RunJournal
	random  io.Reader
}

func NewCoordinator(journal RunJournal) (*Coordinator, error) {
	return newCoordinator(journal, rand.Reader)
}

// WithPacketEffectSection cooperatively shares this coordinator's journal effect
// gate with a synchronous packet write. Only journals that explicitly expose the
// capability can prepare packets. An optional implementation must invoke the
// callback synchronously exactly once; this checks callback discipline, not
// owner provenance or that an arbitrary wrapper uses the same live journal.
func (c *Coordinator) WithPacketEffectSection(ctx context.Context, effect func() error) error {
	if c == nil || effect == nil {
		return ErrInvalidCoordinator
	}
	gated, ok := c.journal.(interface {
		WithEffectSection(context.Context, func() error) error
	})
	if !ok {
		return ErrInvalidCoordinatorJournal
	}
	// An optional wrapper is not provenance. Require that it synchronously
	// invokes the callback exactly once before reporting success. Protect this
	// state because a broken wrapper may call concurrently or after returning.
	var mu sync.Mutex
	calls, finished, returned := 0, false, false
	var callbackErr error
	invalid := false
	gateErr := gated.WithEffectSection(ctx, func() error {
		mu.Lock()
		if returned || calls != 0 {
			invalid = true
			mu.Unlock()
			return ErrInvalidCoordinatorJournal
		}
		calls++
		mu.Unlock()
		err := effect()
		mu.Lock()
		callbackErr = err
		finished = true
		mu.Unlock()
		return err
	})
	mu.Lock()
	returned = true
	valid := calls == 1 && finished && !invalid
	effectErr := callbackErr
	mu.Unlock()
	if !valid {
		return errors.Join(ErrInvalidCoordinatorJournal, gateErr, effectErr)
	}
	// An optional implementation may swallow an effect error. Never turn
	// that into success or claim that its return proves a shared owner gate.
	return errors.Join(gateErr, effectErr)
}
func newCoordinator(journal RunJournal, random io.Reader) (*Coordinator, error) {
	if isNilRunJournal(journal) {
		return nil, ErrInvalidCoordinatorJournal
	}
	if random == nil {
		return nil, ErrCoordinatorRandomness
	}
	return &Coordinator{journal: journal, random: random}, nil
}

func (c *Coordinator) Open(ctx context.Context, plan ReviewRunPlan, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if err := c.journal.SavePlan(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	for range maxCoordinatorConflicts {
		events, err := readAllRunEvents(ctx, c.journal, plan.Scope())
		if err != nil {
			return ReviewRunState{}, err
		}
		if len(events) != 0 {
			return ReplayReviewRun(plan, events)
		}
		event, err := NewRunEvent(plan, 1, "", RunEventOpened, TaskDefinition{}, 0, "", "", time.Time{}, "", 0, time.Time{}, at)
		if err != nil {
			return ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, "", event); err == nil {
			return ReplayReviewRun(plan, []RunEvent{event})
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}
func (c *Coordinator) Advance(ctx context.Context, plan ReviewRunPlan, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	for range maxReviewRunTasks + maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if !transitionTimeAllowed(state, at) {
			return ReviewRunState{}, ErrRunTransitionSequenceMismatch
		}
		if state.Status() != ReviewRunActive {
			return state, nil
		}
		var exhausted TaskRuntimeState
		for _, definition := range plan.Tasks() {
			runtime, _ := state.Task(definition.Key())
			if runtime.status == TaskRuntimeLeased && runtime.attempts == definition.MaxAttempts() && at.UnixMilli() >= runtime.leaseExpiresAtMillis && runtime.preparedEventIdentity == "" {
				exhausted = runtime
				break
			}
		}
		if exhausted.status == TaskRuntimeLeased {
			event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskFailed, exhausted.definition, exhausted.attempts, exhausted.leaseTokenIdentity, "", time.Time{}, "", RunFailureResourceLimit, time.Time{}, at)
			if err != nil {
				return ReviewRunState{}, err
			}
			if err := c.journal.Append(ctx, state.HeadIdentity(), event); err != nil && !errors.Is(err, ErrRunJournalHeadConflict) {
				return ReviewRunState{}, err
			}
			continue
		}
		ready := state.ReadyTasks(at)
		kind := RunEventTaskAvailable
		failure := RunFailure(0)
		var task TaskDefinition
		if len(ready) != 0 {
			task = ready[0]
		} else {
			skippable := state.SkippableTasks()
			if len(skippable) == 0 {
				return state, nil
			}
			task = skippable[0]
			kind = RunEventTaskSkipped
			failure = RunFailureDependency
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), kind, task, 0, "", "", time.Time{}, "", failure, time.Time{}, at)
		if err != nil {
			return ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err != nil {
			if errors.Is(err, ErrRunJournalHeadConflict) {
				continue
			}
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}

func (c *Coordinator) ClaimTask(ctx context.Context, plan ReviewRunPlan, taskKey, handlerIdentity, workerIdentity string, at time.Time) (TaskLease, bool, error) {
	if err := c.validate(ctx, plan); err != nil {
		return TaskLease{}, false, err
	}
	if !validWorkerIdentity(workerIdentity) {
		return TaskLease{}, false, ErrInvalidTaskLease
	}
	taskDefinition, exists := plan.Task(taskKey)
	if !exists {
		return TaskLease{}, false, ErrReviewTaskNotFound
	}
	if taskDefinition.HandlerIdentity() != handlerIdentity {
		return TaskLease{}, false, ErrInvalidReviewTaskHandler
	}
	if _, err := c.Advance(ctx, plan, at); err != nil {
		return TaskLease{}, false, err
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return TaskLease{}, false, err
		}
		if !transitionTimeAllowed(state, at) {
			return TaskLease{}, false, ErrRunTransitionSequenceMismatch
		}
		if state.Status() != ReviewRunActive {
			return TaskLease{}, false, ErrRunAlreadyTerminal
		}
		runtime, _ := state.Task(taskKey)
		claimable := runtime.Status() == TaskRuntimeAvailable
		expired := runtime.Status() == TaskRuntimeLeased && runtime.preparedEventIdentity == "" && at.UnixMilli() >= runtime.leaseExpiresAtMillis
		if !claimable && !expired {
			return TaskLease{}, false, nil
		}
		attempt := runtime.Attempts() + 1
		if attempt > runtime.Definition().MaxAttempts() {
			return TaskLease{}, false, ErrRunTransitionAttemptLimit
		}
		token, tokenIdentity, err := c.newLeaseToken()
		if err != nil {
			return TaskLease{}, false, err
		}
		expiresAt := at.Add(time.Duration(runtime.Definition().LeaseDurationMilliseconds()) * time.Millisecond)
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskLeased, runtime.Definition(), attempt, tokenIdentity, workerIdentity, expiresAt, "", 0, time.Time{}, at)
		if err != nil {
			return TaskLease{}, false, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err == nil {
			lease, leaseErr := newTaskLease(plan, event, token)
			return lease, true, leaseErr
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return TaskLease{}, false, err
		}
	}
	return TaskLease{}, false, ErrCoordinatorContention
}

func (c *Coordinator) RenewTaskLease(ctx context.Context, plan ReviewRunPlan, lease TaskLease, at time.Time) (TaskLease, ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return TaskLease{}, ReviewRunState{}, err
	}
	if err := lease.Validate(); err != nil {
		return TaskLease{}, ReviewRunState{}, err
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return TaskLease{}, ReviewRunState{}, err
		}
		if state.Status() != ReviewRunActive {
			return TaskLease{}, ReviewRunState{}, ErrRunAlreadyTerminal
		}
		if !transitionTimeAllowed(state, at) {
			return TaskLease{}, ReviewRunState{}, ErrRunTransitionSequenceMismatch
		}
		runtime, exists := state.Task(lease.TaskKey())
		if runtime.preparedEvent.Kind() == RunEventContextPacketPrepared {
			return TaskLease{}, ReviewRunState{}, ErrPreparedContextPacket
		}
		if !exists || lease.PlanIdentity() != plan.Identity() || lease.HandlerIdentity() != runtime.Definition().HandlerIdentity() || !runtimeMatchesLease(runtime, lease) || runtime.preparedEventIdentity != "" || at.UnixMilli() > runtime.leaseExpiresAtMillis {
			return TaskLease{}, ReviewRunState{}, ErrRunTransitionLeaseMismatch
		}
		expiresAt := at.Add(time.Duration(runtime.Definition().LeaseDurationMilliseconds()) * time.Millisecond)
		if expiresAt.UnixMilli() <= runtime.leaseExpiresAtMillis {
			current := lease
			current.eventIdentity = runtime.lastEventIdentity
			current.expiresAtMillis = runtime.leaseExpiresAtMillis
			current.identity = deriveTaskLeaseIdentity(current)
			if current.Validate() != nil {
				return TaskLease{}, ReviewRunState{}, ErrInvalidTaskLease
			}
			return current, state, nil
		}
		// Reserve one run terminal event and availability, lease, result per attempt.
		reserved := uint64(1)
		for _, task := range plan.Tasks() {
			reserved += 3 * uint64(task.MaxAttempts())
			if task.Kind() == TaskAssembleContext {
				reserved += 2 * uint64(task.MaxAttempts())
			}
		}
		if state.Revision()+1+reserved > maxRunJournalStreamEvents {
			return TaskLease{}, state, ErrTaskLeaseRenewalLimit
		}
		event, err := NewRunEvent(
			plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskLeaseRenewed,
			runtime.Definition(), runtime.Attempts(), runtime.leaseTokenIdentity,
			runtime.workerIdentity, expiresAt, "", 0, time.Time{}, at,
		)
		if err != nil {
			return TaskLease{}, ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err == nil {
			renewed, leaseErr := newTaskLease(plan, event, lease.token)
			if leaseErr != nil {
				return TaskLease{}, ReviewRunState{}, leaseErr
			}
			next, loadErr := c.load(ctx, plan)
			return renewed, next, loadErr
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return TaskLease{}, ReviewRunState{}, err
		}
	}
	return TaskLease{}, ReviewRunState{}, ErrCoordinatorContention
}

// CompleteTask records one leased attempt's completion with no run deadline.
func (c *Coordinator) CompleteTask(ctx context.Context, plan ReviewRunPlan, lease TaskLease, completion TaskCompletion, at time.Time) (ReviewRunState, error) {
	return c.CompleteTaskWithin(ctx, plan, lease, completion, at, time.Time{})
}

// CompleteTaskWithin records one leased attempt's completion. A retry after a
// rate-limited model attempt that named a Retry-After is scheduled at that
// delay, never past deadline when one is set; every other retry keeps the
// task's fixed delay.
func (c *Coordinator) CompleteTaskWithin(ctx context.Context, plan ReviewRunPlan, lease TaskLease, completion TaskCompletion, at, deadline time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if err := lease.Validate(); err != nil {
		return ReviewRunState{}, err
	}
	if err := completion.Validate(); err != nil {
		return ReviewRunState{}, err
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		runtime, exists := state.Task(lease.TaskKey())
		if !exists {
			return ReviewRunState{}, ErrReviewTaskNotFound
		}
		if completion.outputIdentity != "" && completion.Status() == TaskCompletionFailed && (runtime.Definition().Kind() != TaskAssembleContext || completion.planIdentity != plan.Identity() || completion.taskIdentity != runtime.Definition().Identity()) {
			return ReviewRunState{}, ErrInvalidTaskCompletion
		}
		if completion.reason != 0 && (!taskFailureReasonAllowed(runtime.Definition().Kind(), completion.reason, completion.shortfall) || completion.planIdentity != plan.Identity() || completion.taskIdentity != runtime.Definition().Identity()) {
			return ReviewRunState{}, ErrInvalidTaskCompletion
		}
		if runtime.Status() == TaskRuntimeSucceeded || runtime.Status() == TaskRuntimeFailed {
			if runtime.preparedInputTerminal {
				return ReviewRunState{}, ErrPreparedContextInput
			}
			if completedTaskMatches(runtime, lease, completion) {
				return state, nil
			}
			return ReviewRunState{}, ErrTaskAlreadyCompleted
		}
		if !runtimeMatchesLease(runtime, lease) {
			return ReviewRunState{}, ErrRunTransitionLeaseMismatch
		}
		if runtime.preparedEvent.Kind() == RunEventContextPacketPrepared {
			return ReviewRunState{}, ErrPreparedContextPacket
		}
		if runtime.preparedEvent.Kind() == RunEventContextInputPrepared {
			return ReviewRunState{}, ErrPreparedContextInput
		}
		if runtime.preparedEventIdentity != "" && (completion.Status() != TaskCompletionFailed || completion.OutputIdentity() != runtime.preparedEvent.OutputIdentity() || completion.Failure() != runtime.preparedEvent.Failure()) {
			return ReviewRunState{}, ErrPreparedContextAbstention
		}
		if !transitionTimeAllowed(state, at) {
			return ReviewRunState{}, ErrRunTransitionSequenceMismatch
		}
		if at.UnixMilli() > runtime.leaseExpiresAtMillis {
			return ReviewRunState{}, ErrRunTransitionLeaseMismatch
		}
		kind := RunEventTaskSucceeded
		output := completion.OutputIdentity()
		failure := RunFailure(0)
		retryAt := time.Time{}
		if completion.Status() == TaskCompletionFailed {
			kind = RunEventTaskFailed
			failure = completion.Failure()
			if failure.Retryable() && runtime.Attempts() < runtime.Definition().MaxAttempts() {
				retryAt = at.Add(taskRetryDelay(runtime.Definition(), completion, at, deadline))
			}
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), kind, runtime.Definition(), runtime.Attempts(), runtime.leaseTokenIdentity, "", time.Time{}, output, failure, retryAt, at)
		if err == nil && completion.reason != 0 {
			event, err = event.withFailureReason(runtime.Definition(), completion.reason, completion.shortfall)
		}
		if err == nil && completion.retryAfterMillis != 0 {
			event, err = event.withRetryAfter(completion.retryAfterMillis)
		}
		if err != nil {
			return ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err == nil {
			return c.load(ctx, plan)
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}

// SucceedRun records the exact final output after every task reaches an allowed terminal state.
func (c *Coordinator) SucceedRun(ctx context.Context, plan ReviewRunPlan, outputIdentity string, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if !validControlPlaneDigest(outputIdentity) {
		return ReviewRunState{}, ErrInvalidRunEventOutput
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() == ReviewRunSucceeded && state.OutputIdentity() == outputIdentity {
			return state, nil
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		derived, ready, deriveErr := state.TerminalCompletion()
		if deriveErr != nil || !ready || derived.Status() != TaskCompletionSucceeded || derived.OutputIdentity() != outputIdentity {
			return ReviewRunState{}, ErrRunTransitionInvalid
		}
		if !transitionTimeAllowed(state, at) || !state.canSucceed() {
			return ReviewRunState{}, ErrRunTransitionInvalid
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventSucceeded, TaskDefinition{}, 0, "", "", time.Time{}, outputIdentity, 0, time.Time{}, at)
		if err != nil {
			return ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err == nil {
			return c.load(ctx, plan)
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}

// FailRun records a final failure only after a required task is terminally blocked.
func (c *Coordinator) FailRun(ctx context.Context, plan ReviewRunPlan, failure RunFailure, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if failure.String() == "" {
		return ReviewRunState{}, ErrInvalidRunEventFailure
	}
	if _, err := c.Advance(ctx, plan, at); err != nil {
		return ReviewRunState{}, err
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() == ReviewRunFailed && state.Failure() == failure {
			return state, nil
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		derived, ready, deriveErr := state.TerminalCompletion()
		if deriveErr != nil || !ready || derived.Status() != TaskCompletionFailed || derived.Failure() != failure {
			return ReviewRunState{}, ErrRunTransitionInvalid
		}
		if !transitionTimeAllowed(state, at) || !state.canFail() {
			return ReviewRunState{}, ErrRunTransitionInvalid
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventFailed, TaskDefinition{}, 0, "", "", time.Time{}, "", failure, time.Time{}, at)
		if err != nil {
			return ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err == nil {
			return c.load(ctx, plan)
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}

// CancelRun records an explicit terminal cancellation and invalidates all active leases.
func (c *Coordinator) CancelRun(ctx context.Context, plan ReviewRunPlan, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() == ReviewRunCanceled {
			return state, nil
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		if !transitionTimeAllowed(state, at) {
			return ReviewRunState{}, ErrRunTransitionSequenceMismatch
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventCanceled, TaskDefinition{}, 0, "", "", time.Time{}, "", RunFailureCanceled, time.Time{}, at)
		if err != nil {
			return ReviewRunState{}, err
		}
		if err := c.journal.Append(ctx, state.HeadIdentity(), event); err == nil {
			return c.load(ctx, plan)
		} else if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}

func transitionTimeAllowed(state ReviewRunState, at time.Time) bool {
	return !at.IsZero() && at.UnixMilli() >= state.lastOccurredAtMillis && validRunMillis(at.UnixMilli())
}

// Receipt returns the current secret-free state for one exact run scope.
func (c *Coordinator) Receipt(ctx context.Context, scope audit.ReviewScope) (ReviewRunReceipt, error) {
	_, state, err := c.Resume(ctx, scope)
	if err != nil {
		return ReviewRunReceipt{}, err
	}
	return NewReviewRunReceipt(state)
}

// Resume loads a durably stored plan and reconstructs its current state.
func (c *Coordinator) Resume(ctx context.Context, scope audit.ReviewScope) (ReviewRunPlan, ReviewRunState, error) {
	if c == nil || isNilRunJournal(c.journal) {
		return ReviewRunPlan{}, ReviewRunState{}, ErrInvalidCoordinator
	}
	if isNilRunJournalContext(ctx) {
		return ReviewRunPlan{}, ReviewRunState{}, ErrInvalidRunJournalContext
	}
	if err := ctx.Err(); err != nil {
		return ReviewRunPlan{}, ReviewRunState{}, ErrRunJournalContextDone
	}
	if err := scope.Validate(); err != nil {
		return ReviewRunPlan{}, ReviewRunState{}, err
	}
	plan, found, err := c.journal.LoadPlan(ctx, scope)
	if err != nil {
		return ReviewRunPlan{}, ReviewRunState{}, err
	}
	if !found {
		return ReviewRunPlan{}, ReviewRunState{}, ErrRunNotOpened
	}
	state, err := c.load(ctx, plan)
	if err != nil {
		return ReviewRunPlan{}, ReviewRunState{}, err
	}
	return plan, state, nil
}

func (c *Coordinator) load(ctx context.Context, plan ReviewRunPlan) (ReviewRunState, error) {
	events, err := readAllRunEvents(ctx, c.journal, plan.Scope())
	if err != nil {
		return ReviewRunState{}, err
	}
	if len(events) == 0 {
		return ReviewRunState{}, ErrRunNotOpened
	}
	return ReplayReviewRun(plan, events)
}
func (c *Coordinator) validate(ctx context.Context, plan ReviewRunPlan) error {
	if c == nil || isNilRunJournal(c.journal) {
		return ErrInvalidCoordinator
	}
	if isNilRunJournalContext(ctx) {
		return ErrInvalidRunJournalContext
	}
	if err := ctx.Err(); err != nil {
		return ErrRunJournalContextDone
	}
	return plan.Validate()
}
func (c *Coordinator) newLeaseToken() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(c.random, bytes); err != nil {
		return "", "", ErrCoordinatorRandomness
	}
	token := hex.EncodeToString(bytes)
	if !validLeaseToken(token) {
		return "", "", ErrCoordinatorRandomness
	}
	return token, deriveLeaseTokenIdentity(token), nil
}
func readAllRunEvents(ctx context.Context, journal RunJournal, scope audit.ReviewScope) ([]RunEvent, error) {
	events := make([]RunEvent, 0)
	var after uint64
	for {
		page, err := journal.Read(ctx, scope, after, maxRunJournalReadLimit)
		if err != nil {
			return nil, err
		}
		if len(page) > maxRunJournalStreamEvents-len(events) {
			return nil, ErrRunJournalStreamTooLarge
		}
		events = append(events, page...)
		if len(page) < maxRunJournalReadLimit {
			return events, nil
		}
		nextAfter := page[len(page)-1].Sequence()
		if nextAfter <= after {
			return nil, ErrRunJournalSequenceMismatch
		}
		after = nextAfter
	}
}
func planTaskHandler(plan ReviewRunPlan, taskKey string) string {
	task, exists := plan.Task(taskKey)
	if !exists {
		return ""
	}
	return task.HandlerIdentity()
}
func runtimeMatchesLease(runtime TaskRuntimeState, lease TaskLease) bool {
	active := runtime.Status() == TaskRuntimeLeased
	matchingTask := runtime.Definition().Identity() == lease.TaskIdentity()
	matchingAttempt := runtime.Attempts() == lease.Attempt()
	matchingToken := runtime.leaseTokenIdentity == lease.tokenIdentity
	matchingWorker := runtime.workerIdentity == lease.workerIdentity
	return active && matchingTask && matchingAttempt && matchingToken && matchingWorker
}

// taskRetryDelay is the wait before a failed attempt's retry: the provider's
// Retry-After for a rate-limited model attempt that named one, which the
// completion already caps at the longest task retry delay, shortened so the
// retry is never later than deadline when one is set; otherwise the task's
// fixed retry delay.
func taskRetryDelay(task TaskDefinition, completion TaskCompletion, at, deadline time.Time) time.Duration {
	if completion.retryAfterMillis == 0 {
		return time.Duration(task.RetryDelayMilliseconds()) * time.Millisecond
	}
	delay := time.Duration(min(completion.retryAfterMillis, maxReviewTaskRetryDelayMillis)) * time.Millisecond
	if !deadline.IsZero() {
		delay = max(min(delay, deadline.Sub(at)), 0)
	}
	return delay
}

func completedTaskMatches(runtime TaskRuntimeState, lease TaskLease, completion TaskCompletion) bool {
	if runtime.Definition().Identity() != lease.TaskIdentity() || runtime.Attempts() != lease.Attempt() || runtime.leaseTokenIdentity != lease.tokenIdentity {
		return false
	}
	if runtime.Status() == TaskRuntimeSucceeded {
		return completion.Status() == TaskCompletionSucceeded && runtime.OutputIdentity() == completion.OutputIdentity()
	}
	return completion.Status() == TaskCompletionFailed && runtime.Failure() == completion.Failure() && runtime.FailureReason() == completion.FailureReason() && runtime.shortfall == completion.shortfall && runtime.retryAfterMillis == completion.retryAfterMillis && runtime.OutputIdentity() == completion.OutputIdentity()
}
func validLeaseToken(token string) bool {
	if len(token) != 64 || token != strings.ToLower(token) || strings.Trim(token, "0") == "" {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil
}
func deriveLeaseTokenIdentity(token string) string {
	digest := sha256.Sum256([]byte("open-trestle/task-lease/v1/" + token))
	return hex.EncodeToString(digest[:])
}
func deriveTaskLeaseIdentity(lease TaskLease) string {
	preimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Plan     string `json:"plan"`
		TaskKey  string `json:"task_key"`
		Task     string `json:"task"`
		Handler  string `json:"handler"`
		Worker   string `json:"worker"`
		Token    string `json:"token"`
		Event    string `json:"event"`
		Attempt  uint8  `json:"attempt"`
		Expires  int64  `json:"expires"`
	}{
		Contract: "open-trestle/task-lease", Version: 1,
		Plan: lease.planIdentity, TaskKey: lease.taskKey, Task: lease.taskIdentity,
		Handler: lease.handlerIdentity, Worker: lease.workerIdentity,
		Token: lease.tokenIdentity, Event: lease.eventIdentity,
		Attempt: lease.attempt, Expires: lease.expiresAtMillis,
	}
	return hashControlPlaneValue(preimage)
}
func deriveTaskCompletionIdentity(completion TaskCompletion) string {
	status := "failed"
	if completion.status == TaskCompletionSucceeded {
		status = "succeeded"
	}
	if completion.reason != 0 && completion.status == TaskCompletionFailed {
		return hashControlPlaneValue(struct {
			Contract   string                      `json:"contract"`
			Version    int                         `json:"version"`
			Status     string                      `json:"status"`
			Failure    string                      `json:"failure"`
			Reason     string                      `json:"reason"`
			Shortfall  *taskFailureShortfallRecord `json:"context_shortfall,omitempty"`
			Plan       string                      `json:"plan"`
			Task       string                      `json:"task"`
			RetryAfter uint32                      `json:"retry_after_milliseconds,omitempty"`
		}{"open-trestle/task-completion", 3, status, completion.failure.String(), completion.reason.String(), taskFailureShortfallToRecord(completion.shortfall), completion.planIdentity, completion.taskIdentity, completion.retryAfterMillis})
	}
	if completion.outputIdentity != "" && completion.status == TaskCompletionFailed {
		return hashControlPlaneValue(struct {
			Contract string `json:"contract"`
			Version  int    `json:"version"`
			Status   string `json:"status"`
			Output   string `json:"output"`
			Failure  string `json:"failure"`
			Plan     string `json:"plan"`
			Task     string `json:"task"`
		}{"open-trestle/task-completion", 2, status, completion.outputIdentity, completion.failure.String(), completion.planIdentity, completion.taskIdentity})
	}
	preimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Status   string `json:"status"`
		Output   string `json:"output"`
		Failure  string `json:"failure"`
	}{"open-trestle/task-completion", 1, status, completion.outputIdentity, completion.failure.String()}
	return hashControlPlaneValue(preimage)
}
func isNilRunJournal(journal RunJournal) bool {
	if journal == nil {
		return true
	}
	value := reflect.ValueOf(journal)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
