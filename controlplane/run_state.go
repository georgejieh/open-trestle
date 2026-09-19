package controlplane

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrRunEventPlanMismatch identifies an event from another immutable plan.
	ErrRunEventPlanMismatch = errors.New("run event plan mismatch")
	// ErrRunEventScopeMismatch identifies an event from another review scope.
	ErrRunEventScopeMismatch = errors.New("run event scope mismatch")
	// ErrRunTransitionSequenceMismatch identifies a gap, fork, or time reversal.
	ErrRunTransitionSequenceMismatch = errors.New("run transition sequence mismatch")
	// ErrRunTransitionInvalid identifies an event not allowed from current state.
	ErrRunTransitionInvalid = errors.New("invalid run transition")
	// ErrRunTransitionDependencyBlocked identifies work made available before its dependencies succeeded.
	ErrRunTransitionDependencyBlocked = errors.New("run transition dependency blocked")
	// ErrRunTransitionLeaseMismatch identifies a stale, expired, or foreign lease result.
	ErrRunTransitionLeaseMismatch = errors.New("run transition lease mismatch")
	// ErrRunTransitionAttemptLimit identifies work beyond its immutable retry bound.
	ErrRunTransitionAttemptLimit = errors.New("run transition attempt limit")
	// ErrRunAlreadyTerminal identifies an event after final run disposition.
	ErrRunAlreadyTerminal = errors.New("review run already terminal")
	// ErrInvalidReviewRunState identifies malformed reconstructed state.
	ErrInvalidReviewRunState = errors.New("invalid review run state")
)

// ReviewRunStatus identifies the durable overall run state.
type ReviewRunStatus uint8

const (
	ReviewRunActive ReviewRunStatus = iota + 1
	ReviewRunSucceeded
	ReviewRunFailed
	ReviewRunCanceled
)

func (s ReviewRunStatus) String() string {
	switch s {
	case ReviewRunActive:
		return "active"
	case ReviewRunSucceeded:
		return "succeeded"
	case ReviewRunFailed:
		return "failed"
	case ReviewRunCanceled:
		return "canceled"
	default:
		return ""
	}
}

// TaskRuntimeStatus identifies one task's reconstructed state.
type TaskRuntimeStatus uint8

const (
	TaskRuntimePending TaskRuntimeStatus = iota + 1
	TaskRuntimeAvailable
	TaskRuntimeLeased
	TaskRuntimeSucceeded
	TaskRuntimeFailed
	TaskRuntimeSkipped
)

func (s TaskRuntimeStatus) String() string {
	switch s {
	case TaskRuntimePending:
		return "pending"
	case TaskRuntimeAvailable:
		return "available"
	case TaskRuntimeLeased:
		return "leased"
	case TaskRuntimeSucceeded:
		return "succeeded"
	case TaskRuntimeFailed:
		return "failed"
	case TaskRuntimeSkipped:
		return "skipped"
	default:
		return ""
	}
}

// TaskRuntimeState is the current reconstructed state for one immutable task.
type TaskRuntimeState struct {
	definition           TaskDefinition
	status               TaskRuntimeStatus
	attempts             uint8
	leaseTokenIdentity   string
	workerIdentity       string
	leaseExpiresAtMillis int64
	outputIdentity       string
	failure              RunFailure
	retryAtMillis        int64
	lastEventRevision    uint64
	lastEventIdentity    string
	lastEventAtMillis    int64
}

func (s TaskRuntimeState) Definition() TaskDefinition { return s.definition }
func (s TaskRuntimeState) Key() string                { return s.definition.Key() }
func (s TaskRuntimeState) Status() TaskRuntimeStatus  { return s.status }
func (s TaskRuntimeState) Attempts() uint8            { return s.attempts }
func (s TaskRuntimeState) LeaseTokenIdentity() string { return s.leaseTokenIdentity }
func (s TaskRuntimeState) WorkerIdentity() string     { return s.workerIdentity }
func (s TaskRuntimeState) LeaseExpiresAt() time.Time  { return runMillisToTime(s.leaseExpiresAtMillis) }
func (s TaskRuntimeState) OutputIdentity() string     { return s.outputIdentity }
func (s TaskRuntimeState) Failure() RunFailure        { return s.failure }
func (s TaskRuntimeState) RetryAt() time.Time         { return runMillisToTime(s.retryAtMillis) }
func (s TaskRuntimeState) LastEventRevision() uint64  { return s.lastEventRevision }
func (s TaskRuntimeState) LastEventIdentity() string  { return s.lastEventIdentity }
func (s TaskRuntimeState) LastEventAt() time.Time     { return runMillisToTime(s.lastEventAtMillis) }
func (s TaskRuntimeState) RetryableAt(at time.Time) bool {
	return s.status == TaskRuntimeFailed && s.failure.Retryable() && s.attempts < s.definition.MaxAttempts() && s.retryAtMillis != 0 && at.UnixMilli() >= s.retryAtMillis
}
func (s TaskRuntimeState) String() string   { return "review task runtime state" }
func (s TaskRuntimeState) GoString() string { return "controlplane.TaskRuntimeState{<redacted>}" }
func (s TaskRuntimeState) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review task runtime state", "controlplane.TaskRuntimeState{<redacted>}")
}

// ReviewRunState is reconstructed solely from an immutable plan and journal events.
type ReviewRunState struct {
	plan                 ReviewRunPlan
	status               ReviewRunStatus
	revision             uint64
	headIdentity         string
	lastOccurredAtMillis int64
	tasks                map[string]TaskRuntimeState
	outputIdentity       string
	failure              RunFailure
}

// ReplayReviewRun validates the entire journal and reconstructs current state.
func ReplayReviewRun(plan ReviewRunPlan, events []RunEvent) (ReviewRunState, error) {
	if err := plan.Validate(); err != nil {
		return ReviewRunState{}, err
	}
	if len(events) == 0 {
		return ReviewRunState{}, ErrRunTransitionSequenceMismatch
	}
	state := ReviewRunState{plan: plan, tasks: make(map[string]TaskRuntimeState, plan.TaskCount())}
	for _, definition := range plan.Tasks() {
		state.tasks[definition.Key()] = TaskRuntimeState{definition: definition, status: TaskRuntimePending}
	}
	for index, event := range events {
		if err := event.Validate(); err != nil {
			return ReviewRunState{}, err
		}
		if event.PlanIdentity() != plan.Identity() {
			return ReviewRunState{}, ErrRunEventPlanMismatch
		}
		if event.Scope().Identity() != plan.Scope().Identity() {
			return ReviewRunState{}, ErrRunEventScopeMismatch
		}
		expectedSequence := uint64(index + 1)
		expectedPrevious := ""
		if index > 0 {
			expectedPrevious = events[index-1].Identity()
		}
		if event.Sequence() != expectedSequence || event.PreviousIdentity() != expectedPrevious || index > 0 && event.occurredAtMillis < state.lastOccurredAtMillis {
			return ReviewRunState{}, ErrRunTransitionSequenceMismatch
		}
		if state.status != 0 && state.status != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		if err := state.apply(event); err != nil {
			return ReviewRunState{}, err
		}
		state.revision = event.Sequence()
		state.headIdentity = event.Identity()
		state.lastOccurredAtMillis = event.occurredAtMillis
	}
	if err := state.Validate(); err != nil {
		return ReviewRunState{}, err
	}
	return state, nil
}

func (s *ReviewRunState) apply(event RunEvent) error {
	if event.Kind() == RunEventOpened {
		if event.Sequence() != 1 || s.status != 0 {
			return ErrRunTransitionInvalid
		}
		s.status = ReviewRunActive
		return nil
	}
	if s.status != ReviewRunActive {
		return ErrRunTransitionInvalid
	}
	if event.taskKey != "" {
		runtime, exists := s.tasks[event.TaskKey()]
		if !exists || runtime.definition.Identity() != event.TaskIdentity() {
			return ErrInvalidRunEventTask
		}
		if err := s.applyTaskEvent(event, &runtime); err != nil {
			return err
		}
		runtime.lastEventRevision = event.Sequence()
		runtime.lastEventIdentity = event.Identity()
		runtime.lastEventAtMillis = event.occurredAtMillis
		s.tasks[event.TaskKey()] = runtime
		return nil
	}
	switch event.Kind() {
	case RunEventSucceeded:
		if !s.canSucceed() {
			return ErrRunTransitionInvalid
		}
		s.status = ReviewRunSucceeded
		s.outputIdentity = event.OutputIdentity()
	case RunEventFailed:
		if !s.canFail() {
			return ErrRunTransitionInvalid
		}
		s.status = ReviewRunFailed
		s.failure = event.Failure()
	case RunEventCanceled:
		s.status = ReviewRunCanceled
		s.failure = RunFailureCanceled
	default:
		return ErrRunTransitionInvalid
	}
	return nil
}

func (s *ReviewRunState) applyTaskEvent(event RunEvent, runtime *TaskRuntimeState) error {
	switch event.Kind() {
	case RunEventTaskAvailable:
		pendingReady := runtime.status == TaskRuntimePending && s.dependenciesSatisfied(runtime.definition)
		retryReady := runtime.RetryableAt(event.OccurredAt())
		if !pendingReady && !retryReady {
			if runtime.status == TaskRuntimePending {
				return ErrRunTransitionDependencyBlocked
			}
			return ErrRunTransitionInvalid
		}
		runtime.status = TaskRuntimeAvailable
		runtime.retryAtMillis = 0
		runtime.failure = 0
	case RunEventTaskLeased:
		available := runtime.status == TaskRuntimeAvailable
		expired := runtime.status == TaskRuntimeLeased && event.occurredAtMillis >= runtime.leaseExpiresAtMillis
		if !available && !expired {
			return ErrRunTransitionInvalid
		}
		if event.Attempt() != runtime.attempts+1 || event.Attempt() > runtime.definition.MaxAttempts() {
			return ErrRunTransitionAttemptLimit
		}
		runtime.status = TaskRuntimeLeased
		runtime.attempts = event.Attempt()
		runtime.leaseTokenIdentity = event.LeaseTokenIdentity()
		runtime.workerIdentity = event.WorkerIdentity()
		runtime.leaseExpiresAtMillis = event.leaseExpiresAtMillis
	case RunEventTaskLeaseRenewed:
		matching := runtime.status == TaskRuntimeLeased && event.Attempt() == runtime.attempts && event.LeaseTokenIdentity() == runtime.leaseTokenIdentity && event.WorkerIdentity() == runtime.workerIdentity
		timely := event.occurredAtMillis <= runtime.leaseExpiresAtMillis && event.leaseExpiresAtMillis > runtime.leaseExpiresAtMillis
		if !matching || !timely {
			return ErrRunTransitionLeaseMismatch
		}
		runtime.leaseExpiresAtMillis = event.leaseExpiresAtMillis
	case RunEventTaskSucceeded:
		if !runtime.matchesLeaseResult(event) {
			return ErrRunTransitionLeaseMismatch
		}
		runtime.status = TaskRuntimeSucceeded
		runtime.outputIdentity = event.OutputIdentity()
		runtime.workerIdentity = ""
		runtime.leaseExpiresAtMillis = 0
	case RunEventTaskFailed:
		// The coordinator can settle an exhausted lease without reviving worker authority.
		exhaustedExpiry := runtime.status == TaskRuntimeLeased && runtime.attempts == runtime.definition.MaxAttempts() && event.Attempt() == runtime.attempts && event.LeaseTokenIdentity() == runtime.leaseTokenIdentity && event.occurredAtMillis >= runtime.leaseExpiresAtMillis && event.Failure() == RunFailureResourceLimit && event.retryAtMillis == 0
		if !runtime.matchesLeaseResult(event) && !exhaustedExpiry {
			return ErrRunTransitionLeaseMismatch
		}
		canRetry := event.Failure().Retryable() && runtime.attempts < runtime.definition.MaxAttempts()
		if canRetry != (event.retryAtMillis != 0) {
			return ErrRunTransitionInvalid
		}
		runtime.status = TaskRuntimeFailed
		runtime.failure = event.Failure()
		runtime.retryAtMillis = event.retryAtMillis
		runtime.workerIdentity = ""
		runtime.leaseExpiresAtMillis = 0
	case RunEventTaskSkipped:
		if runtime.status != TaskRuntimePending {
			return ErrRunTransitionInvalid
		}
		if event.Failure() == RunFailureDependency && !s.hasFailedDependency(runtime.definition) {
			return ErrRunTransitionDependencyBlocked
		}
		if event.Failure() == RunFailurePolicy && runtime.definition.Required() {
			return ErrRunTransitionInvalid
		}
		runtime.status = TaskRuntimeSkipped
		runtime.failure = event.Failure()
	default:
		return ErrRunTransitionInvalid
	}
	return nil
}
func (s TaskRuntimeState) matchesLeaseResult(event RunEvent) bool {
	return s.status == TaskRuntimeLeased && event.Attempt() == s.attempts && event.LeaseTokenIdentity() == s.leaseTokenIdentity && event.occurredAtMillis <= s.leaseExpiresAtMillis
}
func (s ReviewRunState) dependenciesSatisfied(task TaskDefinition) bool {
	for _, key := range task.Dependencies() {
		dependency := s.tasks[key]
		if dependency.status == TaskRuntimeSucceeded {
			continue
		}
		failedWithoutRetry := dependency.status == TaskRuntimeFailed && (!dependency.failure.Retryable() || dependency.attempts >= dependency.definition.MaxAttempts())
		terminalOptionalFailure := !dependency.definition.Required() && (dependency.status == TaskRuntimeSkipped || failedWithoutRetry)
		if !terminalOptionalFailure {
			return false
		}
	}
	return true
}
func (s ReviewRunState) hasFailedDependency(task TaskDefinition) bool {
	for _, key := range task.Dependencies() {
		runtime := s.tasks[key]
		terminalFailure := runtime.status == TaskRuntimeFailed && (!runtime.failure.Retryable() || runtime.attempts >= runtime.definition.MaxAttempts())
		if runtime.definition.Required() && (terminalFailure || runtime.status == TaskRuntimeSkipped) {
			return true
		}
	}
	return false
}
func (s ReviewRunState) canSucceed() bool {
	for _, task := range s.tasks {
		if task.definition.Required() && task.status != TaskRuntimeSucceeded {
			return false
		}
		if task.status != TaskRuntimeSucceeded && task.status != TaskRuntimeFailed && task.status != TaskRuntimeSkipped {
			return false
		}
	}
	return true
}
func (s ReviewRunState) canFail() bool {
	for _, task := range s.tasks {
		if task.definition.Required() && (task.status == TaskRuntimeFailed && !task.RetryableAt(time.UnixMilli(maxRunEventUnixMilliseconds)) || task.status == TaskRuntimeSkipped) {
			return true
		}
	}
	return false
}

func (s ReviewRunState) Plan() ReviewRunPlan       { return s.plan }
func (s ReviewRunState) Status() ReviewRunStatus   { return s.status }
func (s ReviewRunState) Revision() uint64          { return s.revision }
func (s ReviewRunState) HeadIdentity() string      { return s.headIdentity }
func (s ReviewRunState) OutputIdentity() string    { return s.outputIdentity }
func (s ReviewRunState) Failure() RunFailure       { return s.failure }
func (s ReviewRunState) LastOccurredAt() time.Time { return runMillisToTime(s.lastOccurredAtMillis) }
func (s ReviewRunState) Task(key string) (TaskRuntimeState, bool) {
	task, exists := s.tasks[key]
	return task, exists
}
func (s ReviewRunState) ReadyTasks(at time.Time) []TaskDefinition {
	if s.status != ReviewRunActive {
		return nil
	}
	ready := make([]TaskDefinition, 0)
	for _, definition := range s.plan.Tasks() {
		runtime := s.tasks[definition.Key()]
		if runtime.status == TaskRuntimePending && s.dependenciesSatisfied(definition) || runtime.RetryableAt(at) {
			ready = append(ready, definition)
		}
	}
	return ready
}
func (s ReviewRunState) SkippableTasks() []TaskDefinition {
	if s.status != ReviewRunActive {
		return nil
	}
	skippable := make([]TaskDefinition, 0)
	for _, definition := range s.plan.Tasks() {
		if s.tasks[definition.Key()].status == TaskRuntimePending && s.hasFailedDependency(definition) {
			skippable = append(skippable, definition)
		}
	}
	return skippable
}

// TerminalCompletion derives the only allowed final disposition from replayed task state.
func (s ReviewRunState) TerminalCompletion() (TaskCompletion, bool, error) {
	if s.Validate() != nil || s.status != ReviewRunActive {
		return TaskCompletion{}, false, ErrInvalidReviewRunState
	}
	if s.canFail() {
		var selected TaskRuntimeState
		found := false
		for _, definition := range s.plan.Tasks() {
			runtime := s.tasks[definition.Key()]
			terminalFailure := runtime.status == TaskRuntimeFailed && (!runtime.failure.Retryable() || runtime.attempts >= runtime.definition.MaxAttempts())
			terminalSkip := runtime.status == TaskRuntimeSkipped
			if !definition.Required() || !terminalFailure && !terminalSkip {
				continue
			}
			if !found || runtime.lastEventRevision < selected.lastEventRevision || runtime.lastEventRevision == selected.lastEventRevision && runtime.Key() < selected.Key() {
				selected, found = runtime, true
			}
		}
		if !found {
			return TaskCompletion{}, false, ErrInvalidReviewRunState
		}
		failure := selected.failure
		if selected.status == TaskRuntimeSkipped {
			failure = RunFailureDependency
		}
		completion, err := NewTaskFailure(failure)
		if err != nil {
			return TaskCompletion{}, false, ErrInvalidReviewRunState
		}
		return completion, true, nil
	}
	if !s.canSucceed() {
		return TaskCompletion{}, false, nil
	}
	resultTask, err := s.plan.ResultTask()
	if err != nil {
		return TaskCompletion{}, false, err
	}
	runtime, ok := s.Task(resultTask.Key())
	if !ok || runtime.status != TaskRuntimeSucceeded {
		return TaskCompletion{}, false, ErrInvalidReviewRunState
	}
	completion, err := NewTaskSuccess(runtime.outputIdentity)
	if err != nil {
		return TaskCompletion{}, false, ErrInvalidReviewRunState
	}
	return completion, true, nil
}

func (s ReviewRunState) String() string   { return "review run state" }
func (s ReviewRunState) GoString() string { return "controlplane.ReviewRunState{<redacted>}" }
func (s ReviewRunState) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review run state", "controlplane.ReviewRunState{<redacted>}")
}
func (s ReviewRunState) Validate() error {
	if err := s.plan.Validate(); err != nil {
		return err
	}
	if s.status.String() == "" || s.revision == 0 || !validControlPlaneDigest(s.headIdentity) || len(s.tasks) != s.plan.TaskCount() || !validRunMillis(s.lastOccurredAtMillis) {
		return ErrInvalidReviewRunState
	}
	for _, definition := range s.plan.Tasks() {
		runtime, exists := s.tasks[definition.Key()]
		validTaskEvent := runtime.status == TaskRuntimePending && runtime.lastEventRevision == 0 && runtime.lastEventIdentity == "" && runtime.lastEventAtMillis == 0 || runtime.status != TaskRuntimePending && runtime.lastEventRevision > 0 && runtime.lastEventRevision <= s.revision && validControlPlaneDigest(runtime.lastEventIdentity) && validRunMillis(runtime.lastEventAtMillis) && runtime.lastEventAtMillis <= s.lastOccurredAtMillis
		if !exists || runtime.definition.Identity() != definition.Identity() || runtime.status.String() == "" || runtime.attempts > definition.MaxAttempts() || !validTaskEvent {
			return ErrInvalidReviewRunState
		}
	}
	if s.status == ReviewRunSucceeded && !validControlPlaneDigest(s.outputIdentity) {
		return ErrInvalidReviewRunState
	}
	if (s.status == ReviewRunFailed || s.status == ReviewRunCanceled) && s.failure.String() == "" {
		return ErrInvalidReviewRunState
	}
	return nil
}
