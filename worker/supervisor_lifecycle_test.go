package worker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// planStartCounter counts handler starts and records the peak number of
// concurrent handlers for one plan.
type planStartCounter struct {
	mu     sync.Mutex
	starts int
	live   int
	peak   int
}

func (c *planStartCounter) enter() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts++
	c.live++
	if c.live > c.peak {
		c.peak = c.live
	}
	return c.starts
}

func (c *planStartCounter) leave() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.live--
}

func (c *planStartCounter) snapshot() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.starts, c.peak
}

// countingHandler counts starts. The first start of a blocking handler waits
// for release and ignores cancellation, so it outlives the call that started
// it.
type countingHandler struct {
	identity string
	kind     controlplane.TaskKind
	block    bool
	entered  chan struct{}
	release  chan struct{}
	exited   chan struct{}
	counter  *planStartCounter
	once     sync.Once
}

func (h *countingHandler) HandlerIdentity() string { return h.identity }
func (h *countingHandler) Kind() controlplane.TaskKind {
	return h.kind
}
func (h *countingHandler) Execute(ctx context.Context, _ controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	start := h.counter.enter()
	if h.block && start == 1 {
		h.once.Do(func() { close(h.entered) })
		defer close(h.exited)
		<-h.release
	}
	h.counter.leave()
	completion, _ := controlplane.NewTaskFailure(controlplane.RunFailureCanceled)
	return completion
}

// blockingDiscoveryJournal holds discovery open so a shutdown can be observed
// against a live operation.
type blockingDiscoveryJournal struct {
	controlplane.RunJournal
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	fault   error
}

func (j *blockingDiscoveryJournal) ListPlans(ctx context.Context, tenant, repository, after string, limit int) ([]controlplane.ReviewRunPlan, error) {
	j.once.Do(func() { close(j.entered) })
	<-j.release
	if j.fault != nil {
		return nil, j.fault
	}
	return j.RunJournal.ListPlans(ctx, tenant, repository, after, limit)
}

// loadCountingJournal counts plan loads so a test can observe whether a pass
// took over a plan.
type loadCountingJournal struct {
	controlplane.RunJournal
	mu    sync.Mutex
	loads int
}

func (j *loadCountingJournal) LoadPlan(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunPlan, bool, error) {
	j.mu.Lock()
	j.loads++
	j.mu.Unlock()
	return j.RunJournal.LoadPlan(ctx, scope)
}

func (j *loadCountingJournal) loadCount() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.loads
}

// cancelFaultControl cancels the caller and reports an independent receipt
// failure joined with the cancellation.
type cancelFaultControl struct {
	*coordinatorControl
	cancel context.CancelFunc
	fault  error
}

func (c *cancelFaultControl) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	c.cancel()
	return controlplane.ReviewRunReceipt{}, errors.Join(context.Canceled, c.fault)
}

// renewalFaultControl fails every lease renewal with an independent cause.
type renewalFaultControl struct {
	*coordinatorControl
	fault error
}

func (c *renewalFaultControl) RenewTaskLease(context.Context, audit.ReviewScope, controlplane.TaskLease) (controlplane.TaskLease, error) {
	return controlplane.TaskLease{}, c.fault
}

// twoTaskPlan builds one plan with a source task and a dependent build task,
// so a pass that takes over the plan can lease the plan's remaining work
// while the source handler is still live.
func twoTaskPlan(t *testing.T, scope audit.ReviewScope) controlplane.ReviewRunPlan {
	t.Helper()
	source, err := controlplane.NewTaskDefinition("a-source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 2, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	build, err := controlplane.NewTaskDefinition("b-build", controlplane.TaskBuildChange, strings.Repeat("f", 64), strings.Repeat("e", 64), []string{"a-source"}, 2, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source, build})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// supervisorFixture opens one plan and returns the supervisor that owns it
// together with the coordinator that owns the run state.
func supervisorFixture(t *testing.T, journal controlplane.RunJournal, handlers []controlplane.TaskHandler, plan controlplane.ReviewRunPlan) (*RepositorySupervisor, *controlplane.Coordinator) {
	t.Helper()
	catalog, err := controlplane.NewTaskHandlerCatalog(handlers)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	supervisor, err := NewRepositorySupervisor(journal, catalog, RepositorySupervisorOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, WorkerIdentity: "lifecycle-worker", PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second, Clock: workerSystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	return supervisor, coordinator
}

// planHandlers returns the two handlers of the two task plan. The source
// handler blocks on its first start; the build handler never blocks.
func planHandlers(counter *planStartCounter) (*countingHandler, *countingHandler) {
	source := &countingHandler{identity: strings.Repeat("d", 64), kind: controlplane.TaskAcquireSource, block: true, entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{}), counter: counter}
	build := &countingHandler{identity: strings.Repeat("e", 64), kind: controlplane.TaskBuildChange, counter: counter}
	return source, build
}

// TestRepositorySupervisorShutdownSealsLateAdmission proves that shutdown
// refuses later Run and RunOnce admission and that a late discovery cannot
// start a handler.
func TestRepositorySupervisorShutdownSealsLateAdmission(t *testing.T) {
	for _, useRun := range []bool{false, true} {
		name := "RunOnce"
		if useRun {
			name = "Run"
		}
		t.Run(name, func(t *testing.T) {
			journal := &blockingDiscoveryJournal{RunJournal: controlplane.NewMemoryRunJournal(), entered: make(chan struct{}), release: make(chan struct{})}
			counter := &planStartCounter{}
			source, build := planHandlers(counter)
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "late-admission")
			if err != nil {
				t.Fatal(err)
			}
			supervisor, _ := supervisorFixture(t, journal, []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
			done := make(chan error, 1)
			go func() {
				if useRun {
					done <- supervisor.Run(context.Background())
				} else {
					_, err := supervisor.RunOnce(context.Background())
					done <- err
				}
			}()
			select {
			case <-journal.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("discovery did not start")
			}
			bound, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer stop()
			if err := supervisor.Shutdown(bound); err == nil {
				t.Fatal("shutdown reported quiescence while discovery was live")
			}
			if _, err := supervisor.RunOnce(context.Background()); !errors.Is(err, ErrRepositorySupervisorShutdown) {
				t.Fatalf("RunOnce was admitted after shutdown: %v", err)
			}
			if err := supervisor.Run(context.Background()); !errors.Is(err, ErrRepositorySupervisorShutdown) {
				t.Fatalf("Run was admitted after shutdown: %v", err)
			}
			close(journal.release)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("discovery did not return")
			}
			wait, stopWait := context.WithTimeout(context.Background(), 3*time.Second)
			defer stopWait()
			if err := supervisor.Shutdown(wait); err != nil {
				t.Fatalf("shutdown did not observe the drained supervisor: %v", err)
			}
			if starts, _ := counter.snapshot(); starts != 0 {
				t.Fatalf("late discovery started a handler: starts=%d", starts)
			}
		})
	}
}

// TestRepositorySupervisorKeepsSingleRunnerUntilHandlerExit proves that a
// handler that outlives its RunOnce keeps sole ownership of its plan: a
// later pass must not load the plan, take over its remaining work, or settle
// the run before that handler exits.
func TestRepositorySupervisorKeepsSingleRunnerUntilHandlerExit(t *testing.T) {
	counter := &planStartCounter{}
	source, build := planHandlers(counter)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "single-runner")
	if err != nil {
		t.Fatal(err)
	}
	journal := &loadCountingJournal{RunJournal: controlplane.NewMemoryRunJournal()}
	supervisor, coordinator := supervisorFixture(t, journal, []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := supervisor.RunOnce(caller)
		done <- err
	}()
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrWorkerDrain) {
			t.Fatalf("escaped handler was not reported as an incomplete drain: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("RunOnce did not return a bounded drain")
	}
	base, err := coordinator.Receipt(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	baseTask, found := base.Task("b-build")
	if !found {
		t.Fatal("plan lost its remaining task")
	}
	loads := journal.loadCount()
	_, err = supervisor.RunOnce(context.Background())
	if taken := journal.loadCount() - loads; taken != 0 {
		t.Fatalf("a later pass took over the plan of a live handler: plan loads=%d", taken)
	}
	receipt, err := coordinator.Receipt(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status() != base.Status() {
		t.Fatalf("a later pass settled the run of a live handler: status=%v", receipt.Status())
	}
	remaining, found := receipt.Task("b-build")
	if !found {
		t.Fatal("plan lost its remaining task")
	}
	if remaining.Status() != baseTask.Status() {
		t.Fatalf("a later pass took over the remaining work of a live handler: status=%v", remaining.Status())
	}
	starts, peak := counter.snapshot()
	if starts != 1 {
		t.Fatalf("a later pass started a second handler: starts=%d", starts)
	}
	if peak != 1 {
		t.Fatalf("the plan ran more than one handler at a time: peak=%d", peak)
	}
	bound, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer stop()
	if err := supervisor.Shutdown(bound); !errors.Is(err, ErrWorkerDrain) {
		t.Fatalf("shutdown lost the escaped handler: %v", err)
	}
	close(source.release)
	wait, stopWait := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopWait()
	if err := supervisor.Shutdown(wait); err != nil {
		t.Fatalf("shutdown did not observe the drained handler: %v", err)
	}
	select {
	case <-source.exited:
	default:
		t.Fatal("shutdown returned before the handler exit")
	}
}

// TestRepositorySupervisorReleasesPlanAfterHandlerExit proves that the plan
// ownership of an escaped handler is released at the actual handler exit, so
// a later pass can take the plan over.
func TestRepositorySupervisorReleasesPlanAfterHandlerExit(t *testing.T) {
	counter := &planStartCounter{}
	source, build := planHandlers(counter)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "release-plan")
	if err != nil {
		t.Fatal(err)
	}
	journal := &loadCountingJournal{RunJournal: controlplane.NewMemoryRunJournal()}
	supervisor, _ := supervisorFixture(t, journal, []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := supervisor.RunOnce(caller)
		done <- err
	}()
	select {
	case <-source.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrWorkerDrain) {
			t.Fatalf("escaped handler was not reported as an incomplete drain: %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("RunOnce did not return a bounded drain")
	}
	loads := journal.loadCount()
	if _, err := supervisor.RunOnce(context.Background()); err != nil {
		t.Fatalf("later pass failed: %v", err)
	}
	if taken := journal.loadCount() - loads; taken != 0 {
		t.Fatalf("a later pass took over the plan of a live handler: plan loads=%d", taken)
	}
	close(source.release)
	select {
	case <-source.exited:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not exit")
	}
	loads = journal.loadCount()
	_, _ = supervisor.RunOnce(context.Background())
	if taken := journal.loadCount() - loads; taken == 0 {
		t.Fatal("the released plan was never loaded again")
	}
}

// TestRunnerRunPreservesJoinedFaultAlongsideCancellation proves that a
// cancellation joined with an independent fault keeps the fault.
func TestRunnerRunPreservesJoinedFaultAlongsideCancellation(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "joined-fault")
	if err != nil {
		t.Fatal(err)
	}
	control, catalog := workerFixture(t, scope)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fault := errors.New("independent receipt failure")
	runner, err := New(&cancelFaultControl{control, cancel, fault}, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); !errors.Is(err, fault) {
		t.Fatalf("independent fault was hidden by the cancellation: %v", err)
	}
}

// TestRepositorySupervisorRunPreservesJoinedFaultAlongsideCancellation proves
// that the supervisor keeps an independent discovery failure that was joined
// with a cancellation.
func TestRepositorySupervisorRunPreservesJoinedFaultAlongsideCancellation(t *testing.T) {
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	fault := errors.New("independent discovery failure")
	journal := &blockingDiscoveryJournal{RunJournal: controlplane.NewMemoryRunJournal(), entered: make(chan struct{}), release: make(chan struct{}), fault: errors.Join(context.Canceled, fault)}
	counter := &planStartCounter{}
	source, build := planHandlers(counter)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "joined-discovery")
	if err != nil {
		t.Fatal(err)
	}
	supervisor, _ := supervisorFixture(t, journal, []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(caller) }()
	select {
	case <-journal.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("discovery did not start")
	}
	cancel()
	close(journal.release)
	select {
	case err := <-done:
		if !errors.Is(err, fault) {
			t.Fatalf("independent discovery failure was hidden by the cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not return")
	}
}

// TestRunnerRenewalCauseSurvivesDrainError proves that the renewal cause and
// the drain error are both reported instead of one replacing the other.
func TestRunnerRenewalCauseSurvivesDrainError(t *testing.T) {
	handler := &cancellationDrainHandler{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "renewal-cause")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	plan := workerPlan(t, scope, catalog)
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("independent renewal fault")
	runner, err := New(&renewalFaultControl{&coordinatorControl{coordinator: coordinator, plan: plan}, fault}, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer close(handler.release)
	_, _, err = runner.RunOnce(context.Background())
	if !errors.Is(err, ErrWorkerLease) {
		t.Fatalf("lease failure was not reported: %v", err)
	}
	if !errors.Is(err, fault) {
		t.Fatalf("renewal cause was replaced: %v", err)
	}
	if !errors.Is(err, ErrWorkerDrain) {
		t.Fatalf("drain failure replaced the execution failure: %v", err)
	}
}
