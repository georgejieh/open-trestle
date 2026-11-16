package main

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/worker"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleSupervisor struct {
	run      func(context.Context) error
	shutdown func(context.Context) error
}

func (s lifecycleSupervisor) Run(ctx context.Context) error      { return s.run(ctx) }
func (s lifecycleSupervisor) Ready() <-chan struct{}             { return nil }
func (s lifecycleSupervisor) Shutdown(ctx context.Context) error { return s.shutdown(ctx) }

func TestDaemonCloseRetainsSupervisorHandler(t *testing.T) {
	release := make(chan struct{})
	var closed atomic.Int32
	d := &daemon{handlerDrainTimeout: 25 * time.Millisecond}
	d.supervisors = []daemonSupervisor{lifecycleSupervisor{shutdown: func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}}
	d.closers = append(d.closers, daemonCloserFunc(func() error { closed.Add(1); return nil }))
	err := d.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("close = %v, want incomplete supervisor drain", err)
	}
	if closed.Load() != 0 {
		t.Error("store closed before supervisor handler exited")
	}
	close(release)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("close count = %d", closed.Load())
	}
}

func TestDaemonCloseObservesBlockingCloser(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	d := &daemon{handlerDrainTimeout: 25 * time.Millisecond}
	d.closers = append(d.closers, daemonCloserFunc(func() error {
		calls.Add(1)
		close(entered)
		<-release
		return nil
	}))
	done := make(chan error, 1)
	go func() { done <- d.Close() }()
	<-entered
	observed := false
	select {
	case err := <-done:
		observed = true
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("close = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Close remained blocked in a closer instead of returning an owned incomplete shutdown")
	}
	close(release)
	// Join the caller even on the old implementation's blocking path.
	if !observed {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Close caller did not return")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("closer called %d times", calls.Load())
	}
}

func TestDaemonRuntimeIncompleteRetainsOwnerAndIndependentErrors(t *testing.T) {
	d := lifecycleBuiltDaemon(t)
	d.handlerDrainTimeout = 25 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	runFault := errors.New("independent supervisor failure")
	d.supervisors = []daemonSupervisor{lifecycleSupervisor{
		run: func(ctx context.Context) error {
			close(entered)
			<-ctx.Done()
			<-release
			return errors.Join(context.Canceled, runFault)
		},
		shutdown: func(context.Context) error { return nil },
	}}
	closed := make(chan struct{})
	d.closers = append(d.closers, daemonCloserFunc(func() error { close(closed); return nil }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.run(ctx, io.Discard) }()
	<-entered
	cancel()
	err := <-done
	var incomplete *daemonShutdownIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("run did not retain owner: %v", err)
	}
	select {
	case <-closed:
		t.Error("store closed before Run returned")
	default:
	}
	// A second observer stays bounded and keeps the same owner.
	observe, cancelObserve := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelObserve()
	if err := incomplete.Finish(observe); !errors.As(err, &incomplete) {
		t.Errorf("repeat lost owner: %v", err)
	}
	close(release)
	finish, cancelFinish := context.WithTimeout(context.Background(), time.Second)
	defer cancelFinish()
	err = incomplete.Finish(finish)
	if !errors.Is(err, runFault) {
		t.Fatalf("independent fault lost: %v", err)
	}
	var stillIncomplete *daemonShutdownIncomplete
	if errors.As(err, &stillIncomplete) {
		t.Fatalf("completed run still incomplete: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("store not closed after actual Run return")
	}
}

func TestDaemonInternalFailureCancelsRootAndRetainsJoinedFault(t *testing.T) {
	d := lifecycleBuiltDaemon(t)
	d.handlerDrainTimeout = 100 * time.Millisecond
	entered, canceled := make(chan struct{}), make(chan struct{})
	original := d.server.Handler
	d.server.Handler = d.admission.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}))
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		d.server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	<-entered
	fault := errors.New("independent internal failure")
	d.supervisors = []daemonSupervisor{lifecycleSupervisor{
		run:      func(context.Context) error { return errors.Join(context.Canceled, fault) },
		shutdown: func(context.Context) error { return nil },
	}}
	err := d.run(context.Background(), io.Discard)
	if !errors.Is(err, fault) {
		t.Errorf("internal failure lost: %v", err)
	}
	<-canceled
	<-returned
	d.server.Handler = original
}

func TestDaemonFinishRetainsFailedCloserResultWithoutRetry(t *testing.T) {
	fault := errors.New("closer failed")
	d := &daemon{}
	var order []int
	for i := 0; i < 3; i++ {
		d.closers = append(d.closers, daemonCloserFunc(func() error {
			order = append(order, i)
			if i == 1 {
				return fault
			}
			return nil
		}))
	}
	for range 2 {
		if err := d.Close(); !errors.Is(err, fault) {
			t.Fatalf("cleanup fault lost: %v", err)
		}
	}
	if !slices.Equal(order, []int{2, 1, 0}) {
		t.Fatalf("closer order/retry = %v", order)
	}
}

func lifecycleBuiltDaemon(t *testing.T) *daemon {
	t.Helper()
	d, err := buildDaemon(context.Background(), []string{"--listen", "127.0.0.1:0", "--state-dir", filepath.Join(t.TempDir(), "state"), "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			var incomplete *daemonShutdownIncomplete
			if errors.As(err, &incomplete) {
				t.Errorf("cleanup incomplete: %v", err)
			}
		}
	})
	return d
}

func TestDaemonAdmissionRetainsPostResponseAndSealsConcurrentEntry(t *testing.T) {
	admission := &daemonAdmission{}
	release, responded := make(chan struct{}), make(chan struct{})
	var starts atomic.Int32
	handler := admission.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		starts.Add(1)
		w.WriteHeader(http.StatusAccepted)
		close(responded)
		<-release
	}))
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	<-responded
	admission.seal()
	var late sync.WaitGroup
	for range 32 {
		late.Go(func() {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-a/repositories/repo-a/runs", nil))
			if recorder.Code != http.StatusServiceUnavailable || recorder.Body.Len() != 0 {
				t.Errorf("late admission response: %d %q", recorder.Code, recorder.Body.String())
			}
		})
	}
	late.Wait()
	if starts.Load() != 1 {
		t.Errorf("underlying starts=%d", starts.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := admission.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("post-response handler not retained: %v", err)
	}
	close(release)
	<-returned
	if err := admission.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonConcurrentFinishRemainsBounded(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	d := &daemon{handlerDrainTimeout: time.Second}
	d.closers = []io.Closer{daemonCloserFunc(func() error { calls.Add(1); close(entered); <-release; return nil })}
	first := make(chan error, 1)
	go func() { first <- d.Close() }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err := d.Finish(ctx)
	var incomplete *daemonShutdownIncomplete
	if !errors.As(err, &incomplete) {
		t.Errorf("concurrent observer lost owner: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := incomplete.Finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("close calls=%d", calls.Load())
	}
}

func TestDaemonCloseRetainsRealRepositoryWorkerAfterRunReturns(t *testing.T) {
	d := lifecycleBuiltDaemon(t)
	d.handlerDrainTimeout = 25 * time.Millisecond
	handler := &daemonBlockedTask{entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "shutdown-worker")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.HandlerIdentity(), nil, 1, 0, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	supervisor, err := worker.NewRepositorySupervisor(d.journal, catalog, worker.RepositorySupervisorOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, WorkerIdentity: "daemon-drain", PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 5 * time.Second, Clock: httpapi.SystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	d.supervisors = []daemonSupervisor{supervisor}
	closed := make(chan struct{})
	d.closers = append(d.closers, daemonCloserFunc(func() error { close(closed); return nil }))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(handler.release) }) }
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-handler.exited:
		case <-time.After(3 * time.Second):
			t.Error("worker handler cleanup did not exit")
		}
		_ = d.Close()
	})
	select {
	case <-handler.entered:
	case err := <-done:
		t.Fatalf("supervisor early return: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not enter")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, worker.ErrWorkerDrain) {
			t.Fatalf("missing drain error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return bounded drain result")
	}
	err = d.Close()
	var incomplete *daemonShutdownIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("daemon lost retained worker owner: %v", err)
	}
	select {
	case <-closed:
		t.Fatal("store closed below real worker")
	default:
	}
	release()
	finish, cancelFinish := context.WithTimeout(context.Background(), time.Second)
	defer cancelFinish()
	if err := incomplete.Finish(finish); err != nil {
		t.Fatal(err)
	}
	if err := supervisor.Run(context.Background()); !errors.Is(err, worker.ErrRepositorySupervisorShutdown) {
		t.Fatalf("late worker admission: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("stores not closed after actual handler exit")
	}
}

type daemonBlockedTask struct{ entered, release, exited chan struct{} }

func (*daemonBlockedTask) HandlerIdentity() string     { return strings.Repeat("d", 64) }
func (*daemonBlockedTask) Kind() controlplane.TaskKind { return controlplane.TaskAcquireSource }
func (h *daemonBlockedTask) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	close(h.entered)
	defer close(h.exited)
	<-h.release
	result, _ := controlplane.NewTaskFailure(controlplane.RunFailureCanceled)
	return result
}

func TestDaemonAdmissionCancellationDoesNotRetirePostResponseWork(t *testing.T) {
	runtime, cancelRuntime := context.WithCancel(context.Background())
	admission := &daemonAdmission{runtime: runtime}
	response, canceled, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	handler := admission.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		close(response)
		<-r.Context().Done()
		close(canceled)
		<-release
	}))
	go func() {
		defer close(returned)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/webhooks/github", nil))
	}()
	<-response
	admission.seal()
	cancelRuntime()
	<-canceled
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := admission.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("cancellation retired post-response work: %v", err)
	}
	close(release)
	<-returned
	if err := admission.drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type daemonFinishedFaultSupervisor struct {
	fault    error
	complete bool
}

func (*daemonFinishedFaultSupervisor) Run(context.Context) error { return nil }
func (*daemonFinishedFaultSupervisor) Ready() <-chan struct{}    { return nil }
func (s *daemonFinishedFaultSupervisor) Finish(context.Context) (bool, error) {
	return s.complete, s.fault
}
func TestDaemonFinishRetainsTerminalFaultWithoutRetainingLiveOwner(t *testing.T) {
	fault := errors.New("late owner settlement failed")
	supervisor := &daemonFinishedFaultSupervisor{fault: fault}
	var closes atomic.Int32
	d := &daemon{supervisors: []daemonSupervisor{supervisor}, closers: []io.Closer{daemonCloserFunc(func() error { closes.Add(1); return nil })}}
	err := d.Finish(context.Background())
	var incomplete *daemonShutdownIncomplete
	if !errors.As(err, &incomplete) || !errors.Is(err, fault) || closes.Load() != 0 {
		t.Fatalf("incomplete owner lost: %v closes=%d", err, closes.Load())
	}
	supervisor.complete = true
	for range 2 {
		err = d.Finish(context.Background())
		incomplete = nil
		if errors.As(err, &incomplete) || !errors.Is(err, fault) || closes.Load() != 1 {
			t.Fatalf("terminal fault mistaken for live work or lost: %v closes=%d", err, closes.Load())
		}
	}
}
