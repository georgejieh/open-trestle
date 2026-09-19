package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

type notificationSupervisorClock struct{ at time.Time }

func (c notificationSupervisorClock) Now() time.Time { return c.at }

func TestTaskNotificationSupervisorReconcilesBeforeReadyAndStops(t *testing.T) {
	plan := runPlanFixture(t)
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	queue := NewMemoryTaskNotificationQueue()
	scheduler, _ := NewTaskNotificationScheduler(journal, queue)
	supervisor, err := NewTaskNotificationSupervisor(scheduler, queue, plan.Scope().TenantID(), []string{plan.Scope().RepositoryID()}, TaskNotificationSupervisorOptions{
		ReconcileInterval: time.Second, MaximumRetries: 2, RetryDelay: 10 * time.Millisecond,
		Clock: notificationSupervisorClock{time.UnixMilli(101)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-supervisor.Ready():
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	if err := supervisor.Run(context.Background()); !errors.Is(err, ErrTaskNotificationSupervisorRunning) {
		t.Fatalf("concurrent run=%v", err)
	}
	lease, found, err := queue.ClaimTaskNotification(context.Background(), plan.Scope(), "worker", time.UnixMilli(102), time.Second)
	if err != nil || !found || lease.Notification().TaskKey() != "source" {
		t.Fatalf("claim=(%#v,%v,%v)", lease, found, err)
	}
	if !supervisor.Notify(plan.Scope()) {
		t.Fatal("local wake rejected")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not stop")
	}
}

func TestTaskNotificationSupervisorRejectsCrossRepositoryWake(t *testing.T) {
	journal := NewMemoryRunJournal()
	queue := NewMemoryTaskNotificationQueue()
	scheduler, _ := NewTaskNotificationScheduler(journal, queue)
	supervisor, err := NewTaskNotificationSupervisor(scheduler, queue, "tenant", []string{"repository"}, TaskNotificationSupervisorOptions{
		ReconcileInterval: time.Second, MaximumRetries: 1, RetryDelay: 10 * time.Millisecond,
		Clock: notificationSupervisorClock{time.UnixMilli(101)},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := audit.NewReviewScope("tenant", "other", "run")
	if supervisor.Notify(other) {
		t.Fatal("cross repository wake accepted")
	}
}

func TestTaskNotificationSupervisorFinalizesSettledRunBeforeReady(t *testing.T) {
	plan, journal, _ := settledSingleTask(t, 0)
	queue := NewMemoryTaskNotificationQueue()
	scheduler, _ := NewTaskNotificationScheduler(journal, queue)
	supervisor, err := NewTaskNotificationSupervisor(scheduler, queue, plan.Scope().TenantID(), []string{plan.Scope().RepositoryID()}, TaskNotificationSupervisorOptions{
		ReconcileInterval: time.Second, MaximumRetries: 2, RetryDelay: 10 * time.Millisecond,
		Clock: notificationSupervisorClock{time.UnixMilli(103)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-supervisor.Ready():
	case <-time.After(time.Second):
		t.Fatal("not ready")
	}
	coordinator, _ := NewCoordinator(journal)
	receipt, err := coordinator.Receipt(context.Background(), plan.Scope())
	if err != nil || receipt.Status() != ReviewRunSucceeded {
		t.Fatalf("receipt=(%#v,%v)", receipt, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not stop")
	}
}

type startsAfterOwnedCancellation struct{}

func (startsAfterOwnedCancellation) WaitForTaskNotification(ctx context.Context) error {
	<-ctx.Done()
	return ErrInvalidTaskNotificationQueue
}

func TestLocalNotificationWakeDoesNotBecomeWaiterFailure(t *testing.T) {
	journal := NewMemoryRunJournal()
	queue := NewMemoryTaskNotificationQueue()
	scheduler, err := NewTaskNotificationScheduler(journal, queue)
	if err != nil {
		t.Fatal(err)
	}
	supervisor, err := NewTaskNotificationSupervisor(scheduler, startsAfterOwnedCancellation{}, "tenant", []string{"repo"}, TaskNotificationSupervisorOptions{ReconcileInterval: time.Second, MaximumRetries: 1, RetryDelay: 10 * time.Millisecond, Clock: notificationSupervisorClock{time.UnixMilli(101)}})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant", "repo", "run")
	if err != nil {
		t.Fatal(err)
	}
	if !supervisor.Notify(scope) {
		t.Fatal("wake not queued")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wake, err := supervisor.wait(ctx)
	if err != nil || !wake {
		t.Fatalf("owned cancellation treated as backend failure: wake=%t err=%v", wake, err)
	}
}

func TestMemoryNotificationWaitNormalizesAlreadyCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewMemoryTaskNotificationQueue().WaitForTaskNotification(ctx); !errors.Is(err, ErrTaskNotificationWaitCanceled) {
		t.Fatalf("pre-canceled wait=%v", err)
	}
}

type delayedStartSupervisorWaiter struct {
	calls  int
	second chan struct{}
}

func (w *delayedStartSupervisorWaiter) WaitForTaskNotification(ctx context.Context) error {
	w.calls++
	if w.calls == 2 {
		close(w.second)
	}
	<-ctx.Done()
	return ErrInvalidTaskNotificationQueue
}
func TestSupervisorContinuesAfterNotifyBeforeRun(t *testing.T) {
	queue := NewMemoryTaskNotificationQueue()
	scheduler, err := NewTaskNotificationScheduler(NewMemoryRunJournal(), queue)
	if err != nil {
		t.Fatal(err)
	}
	waiter := &delayedStartSupervisorWaiter{second: make(chan struct{})}
	supervisor, err := NewTaskNotificationSupervisor(scheduler, waiter, "tenant", []string{"repo"}, TaskNotificationSupervisorOptions{ReconcileInterval: time.Second, MaximumRetries: 1, RetryDelay: 10 * time.Millisecond, Clock: notificationSupervisorClock{time.UnixMilli(101)}})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant", "repo", "run")
	if !supervisor.Notify(scope) {
		t.Fatal("wake not queued")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	select {
	case <-waiter.second:
	case err := <-done:
		t.Fatalf("valid local wake stopped supervisor: %v", err)
	case <-ctx.Done():
		t.Fatal("supervisor failed to continue")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor failed to stop")
	}
}
