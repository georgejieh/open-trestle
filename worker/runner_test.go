package worker

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"sync"
	"testing"
	"time"
)

type coordinatorControl struct {
	mu                sync.Mutex
	coordinator       *controlplane.Coordinator
	plan              controlplane.ReviewRunPlan
	renews, completes int
}

func (c *coordinatorControl) GetRun(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	return c.coordinator.Receipt(ctx, scope)
}
func (c *coordinatorControl) GetRunPlan(context.Context, audit.ReviewScope) (controlplane.ReviewRunPlan, error) {
	return c.plan, nil
}
func (c *coordinatorControl) ClaimTask(ctx context.Context, _ audit.ReviewScope, key, handler string) (controlplane.TaskLease, error) {
	lease, _, err := c.coordinator.ClaimTask(ctx, c.plan, key, handler, "worker-1", time.Now().UTC())
	return lease, err
}
func (c *coordinatorControl) RenewTaskLease(ctx context.Context, _ audit.ReviewScope, lease controlplane.TaskLease) (controlplane.TaskLease, error) {
	renewed, _, err := c.coordinator.RenewTaskLease(ctx, c.plan, lease, time.Now().UTC())
	c.mu.Lock()
	c.renews++
	c.mu.Unlock()
	return renewed, err
}
func (c *coordinatorControl) CompleteTask(ctx context.Context, _ audit.ReviewScope, lease controlplane.TaskLease, completion controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error) {
	state, err := c.coordinator.CompleteTask(ctx, c.plan, lease, completion, time.Now().UTC())
	c.mu.Lock()
	c.completes++
	c.mu.Unlock()
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return controlplane.NewReviewRunReceipt(state)
}

type delayedHandler struct {
	identity string
	delay    time.Duration
}

func (h delayedHandler) HandlerIdentity() string     { return h.identity }
func (h delayedHandler) Kind() controlplane.TaskKind { return controlplane.TaskAcquireSource }
func (h delayedHandler) Execute(ctx context.Context, _ controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	select {
	case <-ctx.Done():
		completion, _ := controlplane.NewTaskFailure(controlplane.RunFailureCanceled)
		return completion
	case <-time.After(h.delay):
		completion, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		return completion
	}
}
func TestRunnerClaimsRenewsExecutesAndCompletesExactTask(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-worker")
	handler := delayedHandler{identity: strings.Repeat("d", 64), delay: 150 * time.Millisecond}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.identity, nil, 2, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second))
	_, _ = coordinator.Advance(context.Background(), plan, state.LastOccurredAt().Add(time.Millisecond))
	control := &coordinatorControl{coordinator: coordinator, plan: plan}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	worked, settled, err := runner.RunOnce(context.Background())
	if err != nil || !worked || !settled {
		t.Fatalf("run=(%v,%v,%v)", worked, settled, err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if control.renews == 0 || control.completes != 1 {
		t.Fatalf("renews=%d completes=%d", control.renews, control.completes)
	}
	receipt, err := coordinator.Receipt(context.Background(), scope)
	taskReceipt, _ := receipt.Task("source")
	if err != nil || taskReceipt.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatalf("receipt=(%#v,%v)", receipt, err)
	}
}
func TestRunnerRejectsPlanReceiptMismatch(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-worker")
	control, catalog := workerFixture(t, scope)
	other, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-other")
	control.plan = workerPlan(t, other, catalog)
	runner, _ := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: time.Second, ExecutionTimeout: time.Minute})
	if _, _, err := runner.RunOnce(context.Background()); err != ErrWorkerState {
		t.Fatalf("err=%v", err)
	}
}
func workerFixture(t *testing.T, scope audit.ReviewScope) (*coordinatorControl, controlplane.TaskHandlerCatalog) {
	t.Helper()
	handler := delayedHandler{identity: strings.Repeat("d", 64)}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	plan := workerPlan(t, scope, catalog)
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second))
	_, _ = coordinator.Advance(context.Background(), plan, state.LastOccurredAt().Add(time.Millisecond))
	return &coordinatorControl{coordinator: coordinator, plan: plan}, catalog
}
func workerPlan(t *testing.T, scope audit.ReviewScope, catalog controlplane.TaskHandlerCatalog) controlplane.ReviewRunPlan {
	t.Helper()
	handler, _ := catalog.Resolve(strings.Repeat("d", 64))
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.HandlerIdentity(), nil, 2, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	return plan
}

type workerSystemClock struct{}

func (workerSystemClock) Now() time.Time { return time.Now().UTC() }
func TestRepositorySupervisorDiscoversAndExecutesLocalRuns(t *testing.T) {
	journal := controlplane.NewMemoryRunJournal()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-local")
	handler := delayedHandler{identity: strings.Repeat("d", 64)}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	plan := workerPlan(t, scope, catalog)
	coordinator, _ := controlplane.NewCoordinator(journal)
	_, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	supervisor, err := NewRepositorySupervisor(journal, catalog, RepositorySupervisorOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, WorkerIdentity: "local-worker", PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second, Clock: workerSystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	worked, err := supervisor.RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("run=(%v,%v)", worked, err)
	}
	receipt, err := coordinator.Receipt(context.Background(), scope)
	task, _ := receipt.Task("source")
	if err != nil || task.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatalf("receipt=(%#v,%v)", receipt, err)
	}
}

type panicHandler struct{ identity string }

func (h panicHandler) HandlerIdentity() string     { return h.identity }
func (h panicHandler) Kind() controlplane.TaskKind { return controlplane.TaskAcquireSource }
func (h panicHandler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	panic("sensitive panic text")
}
func TestRunnerConvertsHandlerPanicToTypedFailure(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-panic")
	handler := panicHandler{identity: strings.Repeat("d", 64)}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.identity, nil, 2, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second))
	_, _ = coordinator.Advance(context.Background(), plan, state.LastOccurredAt().Add(time.Millisecond))
	control := &coordinatorControl{coordinator: coordinator, plan: plan}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	runner, _ := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second})
	worked, settled, err := runner.RunOnce(context.Background())
	if err != nil || !worked || settled {
		t.Fatalf("run=(%v,%v,%v)", worked, settled, err)
	}
	receipt, _ := coordinator.Receipt(context.Background(), scope)
	taskReceipt, _ := receipt.Task("source")
	if taskReceipt.Failure() != controlplane.RunFailureInternal {
		t.Fatalf("task=%#v", taskReceipt)
	}
}

type notificationCoordinatorControl struct {
	*coordinatorControl
	scheduler    *controlplane.TaskNotificationScheduler
	queue        *controlplane.MemoryTaskNotificationQueue
	claims, acks int
}

func (c *notificationCoordinatorControl) ClaimTaskNotification(ctx context.Context, scope audit.ReviewScope, wait, duration time.Duration) (controlplane.TaskNotificationLease, bool, error) {
	c.claims++
	if _, _, err := c.scheduler.ReconcileRun(ctx, scope, time.Now().UTC()); err != nil {
		return controlplane.TaskNotificationLease{}, false, err
	}
	return c.queue.ClaimTaskNotification(ctx, scope, "worker-1", time.Now().UTC(), duration)
}
func (c *notificationCoordinatorControl) AcknowledgeTaskNotification(ctx context.Context, _ audit.ReviewScope, lease controlplane.TaskNotificationLease) error {
	c.acks++
	return c.queue.AcknowledgeTaskNotification(ctx, lease, time.Now().UTC())
}
func TestRunnerUsesNotificationBeforePollingFallback(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-notified")
	handler := delayedHandler{identity: strings.Repeat("d", 64)}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.identity, nil, 1, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	queue := controlplane.NewMemoryTaskNotificationQueue()
	scheduler, _ := controlplane.NewTaskNotificationScheduler(journal, queue)
	base := &coordinatorControl{coordinator: coordinator, plan: plan}
	control := &notificationCoordinatorControl{coordinatorControl: base, scheduler: scheduler, queue: queue}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second, NotificationWait: 250 * time.Millisecond, NotificationLeaseDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if control.claims != 1 || control.acks != 1 || base.completes != 1 {
		t.Fatalf("claims=%d acks=%d completes=%d", control.claims, control.acks, base.completes)
	}
}
