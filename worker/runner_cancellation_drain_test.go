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

type cancellationDrainHandler struct {
	entered  chan struct{}
	canceled chan struct{}
	release  chan struct{}
	exited   chan struct{}
}

func (h *cancellationDrainHandler) HandlerIdentity() string { return strings.Repeat("d", 64) }
func (h *cancellationDrainHandler) Kind() controlplane.TaskKind {
	return controlplane.TaskAcquireSource
}
func (h *cancellationDrainHandler) Execute(ctx context.Context, _ controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	close(h.entered)
	defer close(h.exited)
	<-ctx.Done()
	close(h.canceled)
	<-h.release
	completion, _ := controlplane.NewTaskFailure(controlplane.RunFailureCanceled)
	return completion
}

func TestRunnerCancellationWaitsForStartedHandlerCleanup(t *testing.T) {
	for _, once := range []bool{false, true} {
		name := "Run"
		if once {
			name = "RunOnce"
		}
		t.Run(name, func(t *testing.T) {
			handler := &cancellationDrainHandler{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-drain")
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
			state, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Advance(context.Background(), plan, state.LastOccurredAt().Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			control := &coordinatorControl{coordinator: coordinator, plan: plan}
			runner, err := New(control, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(handler.release) }) }
			done := make(chan error, 1)
			go func() {
				if once {
					_, _, err := runner.RunOnce(ctx)
					done <- err
				} else {
					done <- runner.Run(ctx)
				}
			}()
			t.Cleanup(func() {
				cancel()
				release()
				select {
				case <-handler.entered:
					select {
					case <-handler.exited:
					case <-time.After(2 * time.Second):
						t.Error("handler cleanup did not finish")
					}
				default:
				}
			})
			select {
			case <-handler.entered:
			case err := <-done:
				t.Fatalf("worker returned before starting handler: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("handler did not start")
			}
			cancel()
			select {
			case <-handler.canceled:
			case <-time.After(2 * time.Second):
				t.Fatal("caller cancellation did not reach handler")
			}
			select {
			case <-done:
				t.Fatal("worker returned while canceled handler still owned its resources")
			case <-time.After(100 * time.Millisecond):
			}
			release()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("worker did not return after bounded cleanup")
			}
			select {
			case <-handler.exited:
			default:
				t.Fatal("worker returned before handler exit barrier")
			}
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			state, err = coordinator.CancelRun(cleanup, plan, time.Now().UTC())
			if err != nil || state.Status() != controlplane.ReviewRunCanceled {
				t.Fatal("drained run could not record terminal cancellation")
			}
			finalizer, err := controlplane.NewRunFinalizer(journal)
			if err != nil {
				t.Fatal(err)
			}
			replayed, changed, err := finalizer.ReconcileRun(cleanup, scope, time.Now().UTC())
			if err != nil || changed || replayed.HeadIdentity() != state.HeadIdentity() {
				t.Fatal("finalizer changed terminal cancellation after drain")
			}
		})
	}
}

func TestRepositorySupervisorPreservesCancellationDrainFailure(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		name := "drained"
		if blocked {
			name = "blocked"
		}
		t.Run(name, func(t *testing.T) {
			handler := &cancellationDrainHandler{entered: make(chan struct{}), canceled: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "supervisor-cancel")
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
			supervisor, err := NewRepositorySupervisor(journal, catalog, RepositorySupervisorOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, WorkerIdentity: "drain-worker", PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second, Clock: workerSystemClock{}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(handler.release) }) }
			done := make(chan struct{})
			var runErr error
			go func() {
				runErr = supervisor.Run(ctx)
				close(done)
			}()
			t.Cleanup(func() {
				cancel()
				release()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("supervisor did not return during cleanup")
				}
				select {
				case <-handler.entered:
					select {
					case <-handler.exited:
					case <-time.After(3 * time.Second):
						t.Error("handler did not exit during cleanup")
					}
				default:
				}
			})
			select {
			case <-handler.entered:
			case <-done:
				t.Fatalf("supervisor returned before handler entry: %v", runErr)
			case <-time.After(3 * time.Second):
				t.Fatal("handler did not start")
			}
			cancel()
			select {
			case <-handler.canceled:
			case <-time.After(3 * time.Second):
				t.Fatal("handler did not observe cancellation")
			}
			if !blocked {
				release()
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("supervisor did not finish bounded drain")
			}
			if blocked {
				if !errors.Is(runErr, ErrWorkerDrain) {
					t.Fatalf("supervisor hid incomplete handler drain: %v", runErr)
				}
				select {
				case <-handler.exited:
					t.Fatal("blocked handler unexpectedly exited")
				default:
				}
			} else if runErr != nil {
				t.Fatalf("drained cancellation failed: %v", runErr)
			}
		})
	}
}
