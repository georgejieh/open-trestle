package worker

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
	"time"
)

type notificationFaultControl struct {
	*coordinatorControl
	cancel context.CancelFunc
	fault  error
}

func (c *notificationFaultControl) ClaimTaskNotification(context.Context, audit.ReviewScope, time.Duration, time.Duration) (controlplane.TaskNotificationLease, bool, error) {
	c.cancel()
	return controlplane.TaskNotificationLease{}, false, errors.Join(context.Canceled, c.fault)
}
func (*notificationFaultControl) AcknowledgeTaskNotification(context.Context, audit.ReviewScope, controlplane.TaskNotificationLease) error {
	return nil
}

func TestRunnerNotificationCancellationPreservesIndependentFault(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "notification-fault")
	handler := delayedHandler{identity: strings.Repeat("d", 64)}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.identity, nil, 1, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fault := errors.New("notification transport failure")
	control := &notificationFaultControl{coordinatorControl: &coordinatorControl{coordinator: coordinator, plan: plan}, cancel: cancel, fault: fault}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second, NotificationWait: 250 * time.Millisecond, NotificationLeaseDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); !errors.Is(err, fault) {
		t.Fatalf("notification failure lost: %v", err)
	}
}

func TestRepositorySupervisorReleasesIdleRunners(t *testing.T) {
	counter := &planStartCounter{}
	source, build := planHandlers(counter)
	source.block = false
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "idle-owner")
	supervisor, _ := supervisorFixture(t, controlplane.NewMemoryRunJournal(), []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
	if _, err := supervisor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	supervisor.lifecycleMu.Lock()
	retained := len(supervisor.runners)
	supervisor.lifecycleMu.Unlock()
	if retained != 0 {
		t.Fatalf("retained %d idle runners after operation return", retained)
	}
}

func TestRunnerRefusesPlanAccessWhilePreviousHandlerLives(t *testing.T) {
	counter := &planStartCounter{}
	source, build := planHandlers(counter)
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "runner-reentry")
	journal := &loadCountingJournal{RunJournal: controlplane.NewMemoryRunJournal()}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{source, build})
	plan := twoTaskPlan(t, scope)
	_, coordinator := supervisorFixture(t, journal, []controlplane.TaskHandler{source, build}, plan)
	if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	control, err := NewLocalControl(journal, workerSystemClock{}, "runner-reentry")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := runner.RunOnce(ctx); done <- err }()
	<-source.entered
	cancel()
	if err := <-done; !errors.Is(err, ErrWorkerDrain) {
		t.Fatalf("missing drain: %v", err)
	}
	defer func() { close(source.release); <-source.exited }()
	before := journal.loadCount()
	_, _, err = runner.RunOnce(context.Background())
	if !errors.Is(err, ErrWorkerDrain) {
		t.Errorf("reentry = %v", err)
	}
	if after := journal.loadCount(); after != before {
		t.Errorf("reentry touched plan under live handler: loads %d -> %d", before, after)
	}
}

func TestRepositorySupervisorRepeatedShutdownAfterDrainWithExpiredContext(t *testing.T) {
	counter := &planStartCounter{}
	source, build := planHandlers(counter)
	source.block = false
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "repeat-shutdown")
	supervisor, _ := supervisorFixture(t, controlplane.NewMemoryRunJournal(), []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
	if _, err := supervisor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := supervisor.Shutdown(ctx); err != nil {
		t.Fatalf("drained supervisor changed on repeat observation: %v", err)
	}
	if _, err := supervisor.RunOnce(context.Background()); !errors.Is(err, ErrRepositorySupervisorShutdown) {
		t.Fatalf("admission reopened: %v", err)
	}
}

type ownerCanceledFaultHandler struct {
	fault   error
	entered chan struct{}
	release chan struct{}
}

func (*ownerCanceledFaultHandler) HandlerIdentity() string { return strings.Repeat("d", 64) }
func (*ownerCanceledFaultHandler) Kind() controlplane.TaskKind {
	return controlplane.TaskAssembleContext
}
func (*ownerCanceledFaultHandler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	panic("owner settlement required")
}
func (h *ownerCanceledFaultHandler) ExecuteAndSettle(ctx context.Context, _ controlplane.TaskExecutionRequest) error {
	if h.entered != nil {
		close(h.entered)
	}
	<-ctx.Done()
	if h.release != nil {
		<-h.release
	}
	return h.fault
}

func TestRunnerPreservesOwnerSettlementFaultDuringCancellationDrain(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "owner-cancel-fault")
	fault := errors.New("owner settlement failed")
	handler := &ownerCanceledFaultHandler{fault: fault}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	task, err := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("a", 64), handler.HandlerIdentity(), []string{"b-build"}, 1, 0, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := controlplane.NewTaskDefinition("a-source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("e", 64), nil, 1, 0, 1000, true)
	build, _ := controlplane.NewTaskDefinition("b-build", controlplane.TaskBuildChange, strings.Repeat("a", 64), strings.Repeat("f", 64), []string{"a-source"}, 1, 0, 1000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source, build, task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, prerequisite := range []controlplane.TaskDefinition{source, build} {
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, prerequisite.Key(), prerequisite.HandlerIdentity(), "fixture-worker", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, success, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := New(&coordinatorControl{coordinator: coordinator, plan: plan}, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	// The execution deadline cancels the owner; its returned fault must survive the drain.
	if _, _, err := runner.RunOnce(context.Background()); !errors.Is(err, fault) {
		t.Fatalf("settlement fault lost after handler return: %v", err)
	}
}

func TestRepositorySupervisorRetainsLateOwnerFaultAfterDrain(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "owner-cancel-fault")
	fault := errors.New("owner settlement failed")
	handler := &ownerCanceledFaultHandler{fault: fault, entered: make(chan struct{}), release: make(chan struct{})}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	task, err := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("a", 64), handler.HandlerIdentity(), []string{"b-build"}, 1, 0, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := controlplane.NewTaskDefinition("a-source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("e", 64), nil, 1, 0, 1000, true)
	build, _ := controlplane.NewTaskDefinition("b-build", controlplane.TaskBuildChange, strings.Repeat("a", 64), strings.Repeat("f", 64), []string{"a-source"}, 1, 0, 1000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source, build, task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	for _, prerequisite := range []controlplane.TaskDefinition{source, build} {
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, prerequisite.Key(), prerequisite.HandlerIdentity(), "fixture-worker", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, success, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	supervisor, err := NewRepositorySupervisor(journal, catalog, RepositorySupervisorOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, WorkerIdentity: "late-owner", PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second, Clock: workerSystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := supervisor.RunOnce(ctx); done <- err }()
	<-handler.entered
	cancel()
	if err := <-done; !errors.Is(err, ErrWorkerDrain) {
		t.Fatalf("missing live ownership: %v", err)
	}
	expired, stop := context.WithCancel(context.Background())
	stop()
	if complete, err := supervisor.Finish(expired); complete || !errors.Is(err, ErrWorkerDrain) {
		t.Fatalf("premature completion: %v %v", complete, err)
	}
	close(handler.release)
	complete, err := supervisor.Finish(context.Background())
	if !complete || !errors.Is(err, fault) {
		t.Fatalf("late fault lost or mistaken for live work: %v %v", complete, err)
	}
	complete, err = supervisor.Finish(expired)
	if !complete || !errors.Is(err, fault) {
		t.Fatalf("repeat lost terminal result: %v %v", complete, err)
	}
}

type cyclicWorkerError struct{}

func (*cyclicWorkerError) Error() string   { return "cycle" }
func (e *cyclicWorkerError) Unwrap() error { return e }
func TestWorkerCancellationClassificationBoundsErrorTree(t *testing.T) {
	cycle := &cyclicWorkerError{}
	if isPureContextCancellation(cycle) {
		t.Fatal("cycle classified as pure cancellation")
	}
	if isPureContextCancellation(errors.Join(context.Canceled, cycle)) {
		t.Fatal("joined cycle classified as cancellation")
	}
	if !isPureContextCancellation(errors.Join(context.Canceled, context.Canceled)) {
		t.Fatal("pure cancellation rejected")
	}
	if isPureContextCancellation(errors.Join(context.Canceled, errors.New("independent"))) {
		t.Fatal("independent fault hidden")
	}
}
