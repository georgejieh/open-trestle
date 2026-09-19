package worker

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

type cancelAfterClaimControl struct {
	*LocalControl
	cancel context.CancelFunc
}

func (c *cancelAfterClaimControl) ClaimTask(ctx context.Context, scope audit.ReviewScope, key, handler string) (controlplane.TaskLease, error) {
	lease, err := c.LocalControl.ClaimTask(ctx, scope, key, handler)
	if err == nil {
		c.cancel()
	}
	return lease, err
}

func TestRunnerDrainsAlreadyStartedNonCooperativeWork(t *testing.T) {
	for _, useRun := range []bool{false, true} {
		name := "RunOnce"
		if useRun {
			name = "Run"
		}
		t.Run(name, func(t *testing.T) {
			handler := &cancellationDrainHandler{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-prespawn-drain")
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
			if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			local, err := NewLocalControl(journal, workerSystemClock{}, "worker-drain")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			control := local
			runner, err := New(control, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if useRun {
					done <- runner.Run(ctx)
				} else {
					_, _, err := runner.RunOnce(ctx)
					done <- err
				}
			}()
			select {
			case <-handler.entered:
			case <-time.After(time.Second):
				t.Fatal("handler never started")
			}
			cancel()
			released := false
			t.Cleanup(func() {
				cancel()
				if !released {
					close(handler.release)
				}
				cleanup, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				_ = runner.Wait(cleanup)
			})
			select {
			case err := <-done:
				if !errors.Is(err, ErrWorkerDrain) {
					t.Fatalf("pending non-cooperative work was hidden on cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("worker attempted an unbounded handler join")
			}
			wait, stop := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer stop()
			if err := runner.Wait(wait); !errors.Is(err, ErrWorkerDrain) {
				t.Fatal("Wait observed no registered work despite a pending handler")
			}
			select {
			case <-handler.entered:
			default:
				t.Fatal("registered handler did not start within bounded drain window")
			}
			close(handler.release)
			released = true
			waitAfterRelease, stopAfterRelease := context.WithTimeout(context.Background(), time.Second)
			defer stopAfterRelease()
			if err := runner.Wait(waitAfterRelease); err != nil {
				t.Fatal(err)
			}
			select {
			case <-handler.exited:
			default:
				t.Fatal("Wait returned before registered handler exit")
			}
		})
	}
}

func TestRunnerClaimCancellationSuppressesHandlerStart(t *testing.T) {
	for _, useRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "RunOnce", true: "Run"}[useRun], func(t *testing.T) {
			handler := &transientOnceHandler{}
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "no-late-start")
			catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
			plan := workerPlan(t, scope, catalog)
			journal := controlplane.NewMemoryRunJournal()
			coordinator, _ := controlplane.NewCoordinator(journal)
			if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			local, _ := NewLocalControl(journal, workerSystemClock{}, "no-start-worker")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner, err := New(&cancelAfterClaimControl{local, cancel}, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: time.Second, ExecutionTimeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if useRun {
				_ = runner.Run(ctx)
			} else {
				_, _, _ = runner.RunOnce(ctx)
			}
			if handler.calls.Load() != 0 {
				t.Fatal("known cancellation started a handler")
			}
			wait, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if err := runner.Wait(wait); err != nil {
				t.Fatal("empty handler drain failed", err)
			}
			if handler.calls.Load() != 0 {
				t.Fatal("handler started after cancellation return")
			}
		})
	}
}

type lateSuccessHandler struct{ entered, release chan struct{} }

func (h *lateSuccessHandler) HandlerIdentity() string     { return strings.Repeat("d", 64) }
func (h *lateSuccessHandler) Kind() controlplane.TaskKind { return controlplane.TaskAcquireSource }
func (h *lateSuccessHandler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	close(h.entered)
	<-h.release
	value, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	return value
}

func TestRunnerLateCompletionCannotReviveCanceledJournal(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-late-completion")
	if err != nil {
		t.Fatal(err)
	}
	handler := &lateSuccessHandler{make(chan struct{}), make(chan struct{})}
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
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	control, err := NewLocalControl(journal, workerSystemClock{}, "late-worker")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: time.Second, ExecutionTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-handler.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	terminal, err := coordinator.CancelRun(context.Background(), plan, time.Now().UTC())
	if err != nil {
		close(handler.release)
		t.Fatal(err)
	}
	cancel()
	close(handler.release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not stop after late completion")
	}
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := runner.Wait(wait); err != nil {
		t.Fatal(err)
	}
	_, replayed, err := coordinator.Resume(wait, scope)
	if err != nil || replayed.Status() != controlplane.ReviewRunCanceled || replayed.HeadIdentity() != terminal.HeadIdentity() || replayed.OutputIdentity() != "" {
		t.Fatal("late success changed terminal cancellation")
	}
}

type transientOnceHandler struct{ calls atomic.Int32 }

func (h *transientOnceHandler) HandlerIdentity() string     { return strings.Repeat("d", 64) }
func (h *transientOnceHandler) Kind() controlplane.TaskKind { return controlplane.TaskAcquireSource }
func (h *transientOnceHandler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if h.calls.Add(1) == 1 {
		value, _ := controlplane.NewTaskFailure(controlplane.RunFailureTransient)
		return value
	}
	value, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	return value
}

func TestForegroundRunnerRetriesOnlyDeterministicTaskThroughCoordinator(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-deterministic-retry")
	if err != nil {
		t.Fatal(err)
	}
	handler := &transientOnceHandler{}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.HandlerIdentity(), nil, 3, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := coordinator.Open(ctx, plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	control, err := NewLocalControl(journal, workerSystemClock{}, "retry-worker")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: time.Second, ExecutionTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	finalizer, err := controlplane.NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	state, _, err := finalizer.ReconcileRun(ctx, scope, time.Now().UTC())
	runtime, ok := state.Task("source")
	if err != nil || state.Status() != controlplane.ReviewRunSucceeded || !ok || runtime.Attempts() != 2 || handler.calls.Load() != 2 {
		t.Fatal("deterministic retry did not follow real coordinator attempt policy")
	}
}
