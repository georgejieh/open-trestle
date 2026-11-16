// Package worker executes exact approved task handlers through scoped remote leases.
package worker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

const (
	minimumPollInterval    = 250 * time.Millisecond
	maximumPollInterval    = time.Minute
	minimumRenewalInterval = 10 * time.Millisecond
	maximumRenewalInterval = time.Minute
	minimumExecutionTime   = time.Second
	maximumExecutionTime   = 24 * time.Hour
)

var (
	// ErrInvalidWorker identifies missing control authority, scope, catalog, or bounds.
	ErrInvalidWorker = errors.New("invalid review worker")
	// ErrWorkerState identifies a cross-wired plan, receipt, task, or completion.
	ErrWorkerState = errors.New("invalid review worker state")
	// ErrWorkerLease identifies failed, expired, or cross-wired lease renewal.
	ErrWorkerLease = errors.New("review worker lease unavailable")
	// ErrWorkerDrain means a canceled handler still owns execution resources.
	ErrWorkerDrain = errors.New("review worker handler drain incomplete")
	// ErrWorkerExecution identifies invalid handler behavior or execution timeout.
	ErrWorkerExecution = errors.New("review worker execution failed")
)

// Control is the least authenticated control-plane authority used by a worker.
type Control interface {
	GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error)
	GetRunPlan(context.Context, audit.ReviewScope) (controlplane.ReviewRunPlan, error)
	ClaimTask(context.Context, audit.ReviewScope, string, string) (controlplane.TaskLease, error)
	RenewTaskLease(context.Context, audit.ReviewScope, controlplane.TaskLease) (controlplane.TaskLease, error)
	CompleteTask(context.Context, audit.ReviewScope, controlplane.TaskLease, controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error)
}

// NotificationControl supplies optional long-poll scheduling hints.
type NotificationControl interface {
	ClaimTaskNotification(context.Context, audit.ReviewScope, time.Duration, time.Duration) (controlplane.TaskNotificationLease, bool, error)
	AcknowledgeTaskNotification(context.Context, audit.ReviewScope, controlplane.TaskNotificationLease) error
}

// Options fixes one worker to one review and bounded timing behavior.
type Options struct {
	Scope                     audit.ReviewScope
	PollInterval              time.Duration
	RenewalInterval           time.Duration
	ExecutionTimeout          time.Duration
	NotificationWait          time.Duration
	NotificationLeaseDuration time.Duration
	Clock                     Clock
}

// OwnerContextSettler completes a context task inside the daemon-owned
// journal effect, without passing through generic CompleteTask.
type OwnerContextSettler interface {
	controlplane.TaskHandler
	ExecuteAndSettle(context.Context, controlplane.TaskExecutionRequest) error
}

// Runner claims and executes one task at a time from an exact handler catalog.
type Runner struct {
	control Control
	catalog controlplane.TaskHandlerCatalog
	options Options
	// step serializes runner bodies. It is a channel so a waiting body can
	// observe its own cancellation instead of blocking on a mutex it cannot
	// release.
	step        chan struct{}
	mu          sync.Mutex
	active      *handlerExecution
	terminalErr error
}

type handlerExecution struct {
	done         chan struct{}
	ownerResults chan error
}

// New constructs a worker without claiming work.
func New(control Control, catalog controlplane.TaskHandlerCatalog, options Options) (*Runner, error) {
	validPoll := options.PollInterval >= minimumPollInterval && options.PollInterval <= maximumPollInterval
	validRenewal := options.RenewalInterval >= minimumRenewalInterval && options.RenewalInterval <= maximumRenewalInterval
	validExecution := options.ExecutionTimeout >= minimumExecutionTime && options.ExecutionTimeout <= maximumExecutionTime
	notificationsDisabled := options.NotificationWait == 0 && options.NotificationLeaseDuration == 0
	notificationsEnabled := options.NotificationWait >= minimumPollInterval && options.NotificationWait <= maximumPollInterval && options.NotificationLeaseDuration >= options.ExecutionTimeout && options.NotificationLeaseDuration <= maximumExecutionTime
	if nilControl(control) || catalog.Validate() != nil || options.Scope.Validate() != nil || !validPoll || !validRenewal || !validExecution || options.RenewalInterval >= options.ExecutionTimeout || !notificationsDisabled && !notificationsEnabled {
		return nil, ErrInvalidWorker
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	if nilWorkerValue(options.Clock) {
		return nil, ErrInvalidWorker
	}
	runner := &Runner{control: control, catalog: catalog, options: options, step: make(chan struct{}, 1)}
	runner.step <- struct{}{}
	return runner, nil
}

// Run polls until the run or all of its tasks settle, or context is canceled.
func (r *Runner) Run(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidWorker
	}
	for {
		worked, settled, err := r.RunOnce(ctx)
		if err != nil {
			if ctx.Err() != nil && isPureContextCancellation(err) {
				return nil
			}
			return err
		}
		if settled || ctx.Err() != nil {
			return nil
		}
		if worked {
			continue
		}
		if notifications, ok := r.control.(NotificationControl); ok && r.options.NotificationWait > 0 {
			lease, found, notificationErr := notifications.ClaimTaskNotification(ctx, r.options.Scope, r.options.NotificationWait, r.options.NotificationLeaseDuration)
			if ctx.Err() != nil {
				if notificationErr != nil && !isPureContextCancellation(notificationErr) {
					return notificationErr
				}
				return nil
			}
			if notificationErr == nil && found {
				worked, settled, err = r.RunOnce(ctx)
				if err != nil {
					return err
				}
				_ = notifications.AcknowledgeTaskNotification(ctx, r.options.Scope, lease)
				if settled {
					return nil
				}
				if worked {
					continue
				}
			}
		}
		timer := time.NewTimer(r.options.PollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

// RunOnce observes state and executes at most one claimable matching task.
func (r *Runner) RunOnce(ctx context.Context) (bool, bool, error) {
	if r == nil || nilControl(r.control) || ctx == nil {
		return false, false, ErrInvalidWorker
	}
	if ctx.Err() != nil {
		return false, false, ctx.Err()
	}
	if !r.acquireStep(ctx) {
		return false, false, ctx.Err()
	}
	defer r.releaseStep()
	if err := r.handlerError(); err != nil {
		return false, false, err
	}
	if r.hasActiveHandler() {
		return false, false, ErrWorkerDrain
	}
	receipt, err := r.control.GetRun(ctx, r.options.Scope)
	if err != nil {
		return false, false, err
	}
	plan, err := r.control.GetRunPlan(ctx, r.options.Scope)
	if err != nil {
		return false, false, err
	}
	if !validWorkerSnapshot(receipt, plan, r.options.Scope) {
		return false, false, ErrWorkerState
	}
	if receipt.Status() != controlplane.ReviewRunActive || tasksSettled(receipt) {
		return false, true, nil
	}
	for _, taskReceipt := range receipt.Tasks() {
		handler, registered := r.catalog.Resolve(taskReceipt.HandlerIdentity())
		if !registered || handler.Kind() != taskReceipt.Kind() || !claimCandidate(taskReceipt) {
			continue
		}
		lease, err := r.control.ClaimTask(ctx, r.options.Scope, taskReceipt.Key(), taskReceipt.HandlerIdentity())
		if err != nil {
			if isClaimConflict(err) {
				continue
			}
			return false, false, err
		}
		if ctx.Err() != nil {
			return false, false, ctx.Err()
		}
		if !validLeaseForPlan(lease, plan, taskReceipt, r.options.Clock.Now().UTC()) {
			return false, false, ErrWorkerLease
		}
		completedReceipt, err := r.execute(ctx, plan, receipt, handler, lease)
		if err != nil {
			return false, false, err
		}
		if !validWorkerSnapshot(completedReceipt, plan, r.options.Scope) {
			return false, false, ErrWorkerState
		}
		return true, completedReceipt.Status() != controlplane.ReviewRunActive || tasksSettled(completedReceipt), nil
	}
	return false, false, nil
}

func (r *Runner) execute(ctx context.Context, plan controlplane.ReviewRunPlan, receipt controlplane.ReviewRunReceipt, handler controlplane.TaskHandler, lease controlplane.TaskLease) (result controlplane.ReviewRunReceipt, resultErr error) {
	task, found := plan.Task(lease.TaskKey())
	if !found {
		return controlplane.ReviewRunReceipt{}, ErrWorkerState
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromReceipt(plan, task, receipt)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, ErrWorkerState
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, ErrWorkerState
	}
	executionContext, cancel := context.WithTimeout(ctx, r.options.ExecutionTimeout)
	defer cancel()
	// Register synchronously. Wait must never miss an actually spawned handler.
	r.mu.Lock()
	if executionContext.Err() != nil {
		r.mu.Unlock()
		return result, executionContext.Err()
	}
	if r.active != nil {
		r.mu.Unlock()
		return result, ErrWorkerDrain
	}
	execution := &handlerExecution{done: make(chan struct{}), ownerResults: make(chan error, 1)}
	r.active = execution
	r.mu.Unlock()
	owner, ownerOnly := handler.(OwnerContextSettler)
	if ownerOnly && task.Kind() != controlplane.TaskAssembleContext {
		r.mu.Lock()
		close(execution.done)
		r.active = nil
		r.mu.Unlock()
		return controlplane.ReviewRunReceipt{}, ErrWorkerState
	}
	completions := make(chan controlplane.TaskCompletion, 1)
	ownerResults := execution.ownerResults
	go func() {
		defer close(execution.done)
		if ownerOnly {
			executeOwnerContext(executionContext, owner, request, ownerResults)
			return
		}
		executeHandler(executionContext, handler, request, completions)
	}()
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		if err := r.Wait(cleanup); err != nil {
			result = controlplane.ReviewRunReceipt{}
			if resultErr == nil {
				resultErr = err
			} else {
				resultErr = errors.Join(resultErr, err)
			}
		}
		resultErr = errors.Join(resultErr, r.handlerError())
	}()
	timer := time.NewTimer(r.options.RenewalInterval)
	defer timer.Stop()
	currentLease := lease
	for {
		select {
		case ownerErr := <-ownerResults:
			if executionContext.Err() != nil {
				return result, errors.Join(cancellationError(ctx), ownerErr)
			}
			if ownerErr != nil {
				return result, ownerErr
			}
			settled, err := r.control.GetRun(ctx, r.options.Scope)
			if err != nil {
				return controlplane.ReviewRunReceipt{}, err
			}
			taskReceipt, found := settled.Task(task.Key())
			settledInput := taskReceipt.Status() == controlplane.TaskRuntimeSucceeded
			settledAbstention := taskReceipt.Status() == controlplane.TaskRuntimeFailed && (taskReceipt.Failure() == controlplane.RunFailurePolicy || taskReceipt.Failure() == controlplane.RunFailureResourceLimit) && taskReceipt.OutputIdentity() != ""
			expiredOwner := taskReceipt.Status() == controlplane.TaskRuntimeFailed && taskReceipt.Failure() == controlplane.RunFailurePolicy && taskReceipt.OutputIdentity() == "" && !r.options.Clock.Now().UTC().Before(lease.ExpiresAt())
			// A route refusal is an ordinary outcome the owner records within its lease.
			refusedOwner := taskReceipt.Status() == controlplane.TaskRuntimeFailed && taskReceipt.Failure() == controlplane.RunFailurePolicy && taskReceipt.OutputIdentity() == "" && (taskReceipt.FailureReason() == controlplane.TaskFailureReasonRouteContextInsufficient || taskReceipt.FailureReason() == controlplane.TaskFailureReasonNoEligibleRoute)
			if !found || (!settledInput && !settledAbstention && !expiredOwner && !refusedOwner) || settledInput && taskReceipt.OutputIdentity() == "" {
				return controlplane.ReviewRunReceipt{}, ErrWorkerState
			}
			return settled, nil
		case completion := <-completions:
			if executionContext.Err() != nil {
				return result, cancellationError(ctx)
			}
			if completion.Validate() != nil {
				return controlplane.ReviewRunReceipt{}, ErrWorkerExecution
			}
			receipt, err := r.control.CompleteTask(ctx, r.options.Scope, currentLease, completion)
			if err != nil {
				return controlplane.ReviewRunReceipt{}, err
			}
			return receipt, nil
		case <-timer.C:
			if ownerOnly {
				timer.Reset(r.options.RenewalInterval)
				continue
			}
			if !r.options.Clock.Now().UTC().Before(currentLease.ExpiresAt()) {
				return controlplane.ReviewRunReceipt{}, ErrWorkerLease
			}
			renewed, err := r.control.RenewTaskLease(ctx, r.options.Scope, currentLease)
			if renewalBudgetRefused(err) {
				cancel()
				completion, _ := controlplane.NewTaskFailure(controlplane.RunFailureResourceLimit)
				receipt, completionErr := r.control.CompleteTask(ctx, r.options.Scope, currentLease, completion)
				if completionErr != nil {
					if isClaimConflict(completionErr) || errors.Is(completionErr, controlplane.ErrRunTransitionLeaseMismatch) || errors.Is(completionErr, controlplane.ErrRunAlreadyTerminal) || errors.Is(completionErr, controlplane.ErrTaskAlreadyCompleted) {
						return r.control.GetRun(ctx, r.options.Scope)
					}
					return controlplane.ReviewRunReceipt{}, completionErr
				}
				return receipt, nil
			}
			if err != nil {
				if isPureContextCancellation(err) {
					return controlplane.ReviewRunReceipt{}, err
				}
				return controlplane.ReviewRunReceipt{}, errors.Join(ErrWorkerLease, err)
			}
			if !sameLeaseAuthority(currentLease, renewed) {
				return controlplane.ReviewRunReceipt{}, ErrWorkerLease
			}
			currentLease = renewed
			timer.Reset(r.options.RenewalInterval)
		case <-executionContext.Done():
			return controlplane.ReviewRunReceipt{}, cancellationError(ctx)
		}
	}
}

// acquireStep serializes one runner body. The wait is context-selectable, so
// a canceled caller never blocks behind another body.
func (r *Runner) acquireStep(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case <-r.step:
		return true
	}
}

func (r *Runner) releaseStep() {
	r.step <- struct{}{}
}

func (r *Runner) hasActiveHandler() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		return false
	}
	select {
	case <-r.active.done:
		return false
	default:
		return true
	}
}

// handlerError collects an owner result only after the handler returned.
func (r *Runner) handlerError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != nil {
		select {
		case <-r.active.done:
			select {
			case err := <-r.active.ownerResults:
				if err != nil && !isPureContextCancellation(err) {
					r.terminalErr = errors.Join(r.terminalErr, err)
				}
			default:
			}
			r.active = nil
		default:
		}
	}
	return r.terminalErr
}

// Wait observes registered handlers only; it never cancels or starts execution.
// A failed drain retains resource ownership for a later explicit Wait.
func (r *Runner) Wait(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrInvalidWorker
	}
	r.mu.Lock()
	active := r.active
	r.mu.Unlock()
	if active == nil {
		return nil
	}
	select {
	case <-active.done:
		return nil
	default:
	}
	select {
	case <-active.done:
		return nil
	case <-ctx.Done():
		select {
		case <-active.done:
			return nil
		default:
			return ErrWorkerDrain
		}
	}
}

// cancellationError reports why an execution stopped. A canceled caller
// context is reported as that cancellation, so a caller can ignore it. An
// execution timeout stays an execution failure.
func cancellationError(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrWorkerExecution
}

// isPureContextCancellation reports whether err carries only context
// cancellation. An error that joins an independent fault with a cancellation
// is not pure, so the independent fault survives.
func isPureContextCancellation(err error) bool {
	return isPureError(err, context.Canceled) || isPureError(err, context.DeadlineExceeded)
}

// isPureError reports whether err carries only the target error. An error that
// joins the target with an independent error is not pure.
func isPureError(err error, target error) bool {
	if err == nil || target == nil {
		return false
	}
	visited := 0
	var walk func(error, int) bool
	walk = func(current error, depth int) bool {
		if current == nil || depth >= 64 || visited >= 256 {
			return false
		}
		visited++
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			any := false
			for _, child := range joined.Unwrap() {
				if child == nil {
					continue
				}
				if !walk(child, depth+1) {
					return false
				}
				any = true
			}
			return any
		}
		if single, ok := current.(interface{ Unwrap() error }); ok {
			return walk(single.Unwrap(), depth+1)
		}
		return current == target
	}
	return walk(err, 0)
}

func executeOwnerContext(ctx context.Context, handler OwnerContextSettler, request controlplane.TaskExecutionRequest, output chan<- error) {
	err := ErrWorkerExecution
	func() {
		defer func() {
			if recover() != nil {
				err = ErrWorkerExecution
			}
		}()
		err = handler.ExecuteAndSettle(ctx, request)
	}()
	output <- err
}

func executeHandler(ctx context.Context, handler controlplane.TaskHandler, request controlplane.TaskExecutionRequest, output chan<- controlplane.TaskCompletion) {
	completion := controlplane.TaskCompletion{}
	func() {
		defer func() {
			if recover() != nil {
				completion, _ = controlplane.NewTaskFailure(controlplane.RunFailureInternal)
			}
		}()
		completion = handler.Execute(ctx, request)
	}()
	output <- completion
}
func validWorkerSnapshot(receipt controlplane.ReviewRunReceipt, plan controlplane.ReviewRunPlan, scope audit.ReviewScope) bool {
	validContracts := receipt.Validate() == nil && plan.Validate() == nil
	validScope := receipt.Scope().Identity() == scope.Identity() && plan.Scope().Identity() == scope.Identity()
	validPlan := receipt.PlanIdentity() == plan.Identity() && receipt.TaskCount() == plan.TaskCount()
	if !validContracts || !validScope || !validPlan {
		return false
	}
	for _, taskReceipt := range receipt.Tasks() {
		task, found := plan.Task(taskReceipt.Key())
		if !found || task.Identity() != taskReceipt.TaskIdentity() || task.HandlerIdentity() != taskReceipt.HandlerIdentity() || task.Kind() != taskReceipt.Kind() {
			return false
		}
	}
	return true
}
func tasksSettled(receipt controlplane.ReviewRunReceipt) bool {
	for _, task := range receipt.Tasks() {
		switch task.Status() {
		case controlplane.TaskRuntimeSucceeded, controlplane.TaskRuntimeSkipped:
		case controlplane.TaskRuntimeFailed:
			if task.Failure().Retryable() && task.Attempts() < task.MaxAttempts() {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func claimCandidate(task controlplane.ReviewTaskReceipt) bool {
	availableOrLeased := task.Status() == controlplane.TaskRuntimeAvailable || task.Status() == controlplane.TaskRuntimeLeased
	retryable := task.Status() == controlplane.TaskRuntimeFailed && task.Failure().Retryable() && task.Attempts() < task.MaxAttempts()
	return availableOrLeased || retryable
}
func validLeaseForPlan(lease controlplane.TaskLease, plan controlplane.ReviewRunPlan, receipt controlplane.ReviewTaskReceipt, at time.Time) bool {
	validIdentity := lease.Validate() == nil && lease.PlanIdentity() == plan.Identity() && lease.TaskIdentity() == receipt.TaskIdentity()
	validTask := lease.TaskKey() == receipt.Key() && lease.HandlerIdentity() == receipt.HandlerIdentity()
	return validIdentity && validTask && lease.ExpiresAt().After(at)
}
func sameLeaseAuthority(previous, renewed controlplane.TaskLease) bool {
	validIdentity := renewed.Validate() == nil && previous.PlanIdentity() == renewed.PlanIdentity() && previous.TaskIdentity() == renewed.TaskIdentity()
	validTask := previous.TaskKey() == renewed.TaskKey() && previous.HandlerIdentity() == renewed.HandlerIdentity()
	validAuthority := previous.WorkerIdentity() == renewed.WorkerIdentity() && previous.Attempt() == renewed.Attempt()
	return validIdentity && validTask && validAuthority && (renewed.ExpiresAt().After(previous.ExpiresAt()) || renewed.Identity() == previous.Identity())
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

type conflictError interface {
	StatusCode() int
	Code() string
}

func renewalBudgetRefused(err error) bool {
	if errors.Is(err, controlplane.ErrTaskLeaseRenewalLimit) {
		return true
	}
	var conflict conflictError
	return errors.As(err, &conflict) && conflict.StatusCode() == 409 && conflict.Code() == "lease_renewal_limit"
}

func isClaimConflict(err error) bool {
	var conflict conflictError
	return errors.As(err, &conflict) && conflict.StatusCode() == 409 && conflict.Code() == "conflict"
}
func nilControl(control Control) bool {
	if control == nil {
		return true
	}
	value := reflect.ValueOf(control)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func (r *Runner) String() string   { return "review worker" }
func (r *Runner) GoString() string { return "worker.Runner{<redacted>}" }
func (r *Runner) Format(state fmt.State, verb rune) {
	value := "review worker"
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = "worker.Runner{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}
