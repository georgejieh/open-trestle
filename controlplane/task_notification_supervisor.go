package controlplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	minimumTaskNotificationReconcileInterval = time.Second
	maximumTaskNotificationReconcileInterval = 5 * time.Minute
	maximumTaskNotificationSupervisorRetries = 10
)

var (
	ErrInvalidTaskNotificationSupervisor     = errors.New("invalid task notification supervisor")
	ErrTaskNotificationSupervisorRunning     = errors.New("task notification supervisor already running")
	ErrTaskNotificationSupervisorUnavailable = errors.New("task notification supervisor unavailable")
)

type TaskNotificationSupervisorClock interface{ Now() time.Time }
type TaskNotificationSupervisorOptions struct {
	ReconcileInterval time.Duration
	MaximumRetries    uint8
	RetryDelay        time.Duration
	Clock             TaskNotificationSupervisorClock
}
type TaskNotificationSupervisor struct {
	scheduler     *TaskNotificationScheduler
	finalizer     *RunFinalizer
	waiter        TaskNotificationWaiter
	tenantID      string
	repositoryIDs []string
	options       TaskNotificationSupervisorOptions
	localWake     chan struct{}
	ready         chan struct{}
	readyOnce     sync.Once
	running       atomic.Bool
}

func NewTaskNotificationSupervisor(scheduler *TaskNotificationScheduler, waiter TaskNotificationWaiter, tenantID string, repositoryIDs []string, options TaskNotificationSupervisorOptions) (*TaskNotificationSupervisor, error) {
	repositories := append([]string(nil), repositoryIDs...)
	sort.Strings(repositories)
	validRepositories := len(repositories) > 0 && len(repositories) <= 256
	for index, repositoryID := range repositories {
		if !validRunPlanQuery(repositoryID) || index > 0 && repositoryID == repositories[index-1] {
			validRepositories = false
		}
	}
	valid := scheduler != nil && !isNilTaskNotificationWaiter(waiter) && validRunPlanQuery(tenantID) && validRepositories && options.ReconcileInterval >= minimumTaskNotificationReconcileInterval && options.ReconcileInterval <= maximumTaskNotificationReconcileInterval && options.MaximumRetries > 0 && options.MaximumRetries <= maximumTaskNotificationSupervisorRetries && options.RetryDelay >= 10*time.Millisecond && options.RetryDelay <= time.Minute && !nilTaskNotificationSupervisorClock(options.Clock)
	if !valid {
		return nil, ErrInvalidTaskNotificationSupervisor
	}
	finalizer, err := NewRunFinalizer(scheduler.journal)
	if err != nil {
		return nil, ErrInvalidTaskNotificationSupervisor
	}
	return &TaskNotificationSupervisor{scheduler: scheduler, finalizer: finalizer, waiter: waiter, tenantID: tenantID, repositoryIDs: repositories, options: options, localWake: make(chan struct{}, 1), ready: make(chan struct{})}, nil
}
func (s *TaskNotificationSupervisor) Ready() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.ready
}
func (s *TaskNotificationSupervisor) Notify(scope audit.ReviewScope) bool {
	if s == nil || scope.Validate() != nil || scope.TenantID() != s.tenantID || !notificationSupervisorAllowsRepository(s.repositoryIDs, scope.RepositoryID()) {
		return false
	}
	select {
	case s.localWake <- struct{}{}:
		return true
	default:
		return false
	}
}
func (s *TaskNotificationSupervisor) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidTaskNotificationSupervisor
	}
	if !s.running.CompareAndSwap(false, true) {
		return ErrTaskNotificationSupervisorRunning
	}
	defer s.running.Store(false)
	if err := s.reconcileWithRetry(ctx); err != nil {
		return err
	}
	s.readyOnce.Do(func() { close(s.ready) })
	waitFailures := uint8(0)
	for {
		result, err := s.wait(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			waitFailures++
			if waitFailures >= s.options.MaximumRetries {
				return ErrTaskNotificationSupervisorUnavailable
			}
			if !waitSupervisorDelay(ctx, s.options.RetryDelay, waitFailures) {
				return nil
			}
			continue
		}
		waitFailures = 0
		if result {
			if err := s.reconcileWithRetry(ctx); err != nil {
				return err
			}
		}
	}
}

// wait returns true for a queue, local, or periodic reconciliation wake.
func (s *TaskNotificationSupervisor) wait(ctx context.Context) (bool, error) {
	waitContext, cancel := context.WithTimeout(ctx, s.options.ReconcileInterval)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.waiter.WaitForTaskNotification(waitContext) }()
	select {
	case <-ctx.Done():
		cancel()
		<-result
		return false, nil
	case <-s.localWake:
		cancel()
		// This cancellation belongs to a valid local wake, not a failed wait.
		<-result
		return true, nil
	case err := <-result:
		if err == nil {
			return true, nil
		}
		if errors.Is(err, ErrTaskNotificationWaitCanceled) && waitContext.Err() != nil {
			return true, nil
		}
		return false, err
	}
}
func (s *TaskNotificationSupervisor) reconcileWithRetry(ctx context.Context) error {
	for attempt := uint8(1); attempt <= s.options.MaximumRetries; attempt++ {
		at := s.options.Clock.Now().UTC()
		succeeded := true
		for _, repositoryID := range s.repositoryIDs {
			if _, _, err := s.scheduler.ReconcileRepository(ctx, s.tenantID, repositoryID, at); err != nil {
				succeeded = false
				break
			}
			if _, _, err := s.finalizer.ReconcileRepository(ctx, s.tenantID, repositoryID, at); err != nil {
				succeeded = false
				break
			}
		}
		if succeeded {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if attempt == s.options.MaximumRetries {
			break
		}
		if !waitSupervisorDelay(ctx, s.options.RetryDelay, attempt) {
			return nil
		}
	}
	return ErrTaskNotificationSupervisorUnavailable
}
func waitSupervisorDelay(ctx context.Context, base time.Duration, attempt uint8) bool {
	delay := base << min(attempt-1, 6)
	if delay > time.Minute {
		delay = time.Minute
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
func notificationSupervisorAllowsRepository(repositories []string, candidate string) bool {
	index := sort.SearchStrings(repositories, candidate)
	return index < len(repositories) && repositories[index] == candidate
}

func isNilTaskNotificationWaiter(waiter TaskNotificationWaiter) bool {
	if waiter == nil {
		return true
	}
	value := reflect.ValueOf(waiter)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func nilTaskNotificationSupervisorClock(clock TaskNotificationSupervisorClock) bool {
	if clock == nil {
		return true
	}
	value := reflect.ValueOf(clock)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func (s *TaskNotificationSupervisor) String() string { return "task notification supervisor" }
func (s *TaskNotificationSupervisor) GoString() string {
	return "controlplane.TaskNotificationSupervisor{<redacted>}"
}
func (s *TaskNotificationSupervisor) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "task notification supervisor", "controlplane.TaskNotificationSupervisor{<redacted>}")
}
