package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/georgejieh/open-trestle/worker"
)

// daemonAdmission seals root HTTP admission and counts admitted handlers.
// Shutdown seals admission, drains the admitted handlers, and only then lets
// owned stores close, so no store is closed underneath a live root handler.
type daemonAdmission struct {
	runtime context.Context
	mu      sync.Mutex
	sealed  bool
	active  int
	idle    chan struct{}
}

// enter admits a root handler. It reports false once admission is sealed.
func (a *daemonAdmission) enter() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sealed {
		return false
	}
	if a.active == 0 {
		a.idle = make(chan struct{})
	}
	a.active++
	return true
}

// leave records that an admitted root handler returned.
func (a *daemonAdmission) leave() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active--
	if a.active == 0 && a.idle != nil {
		close(a.idle)
		a.idle = nil
	}
}

// seal refuses further root handler admission.
func (a *daemonAdmission) seal() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sealed = true
}

// drain seals admission and waits until no admitted root handler is running
// or the context ends. Sealing first means no handler can start after the
// wait observes an empty admission, so a completed drain is a real bound.
// A nil admission has no admitted handlers and drains immediately.
func (a *daemonAdmission) drain(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.seal()
	a.mu.Lock()
	if a.active == 0 {
		a.mu.Unlock()
		return nil
	}
	idle := a.idle
	a.mu.Unlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// wrap counts every root handler invocation. Sealed admission is refused with
// a content-free 503 so no handler starts against closing stores.
func (a *daemonAdmission) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !a.enter() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer a.leave()
		if a != nil && a.runtime != nil {
			ctx, cancel := context.WithCancel(request.Context())
			stop := context.AfterFunc(a.runtime, cancel)
			defer stop()
			defer cancel()
			if a.runtime.Err() != nil {
				cancel()
			}
			request = request.WithContext(ctx)
		}
		next.ServeHTTP(writer, request)
	})
}

// daemonShutdownIncomplete retains the owner of every unfinished shutdown phase.
// Finish observes the same phase; it never repeats a partially attempted closer.
type daemonShutdownIncomplete struct {
	owner *daemon
	cause error
}

func (e *daemonShutdownIncomplete) Error() string {
	return fmt.Sprintf("daemon shutdown incomplete: %v", e.cause)
}
func (e *daemonShutdownIncomplete) Unwrap() error                    { return e.cause }
func (e *daemonShutdownIncomplete) Finish(ctx context.Context) error { return e.owner.Finish(ctx) }

type daemonRuntimeResult struct {
	done chan struct{}
	err  error
}

type daemonSupervisorFinish interface {
	Finish(context.Context) (bool, error)
}

type daemonSupervisorShutdown interface {
	Shutdown(context.Context) error
}

// Finish seals admission and observes actual users before starting the ordered,
// exactly-once closer phase. An incomplete error retains this owner for callers.
func (d *daemon) Finish(ctx context.Context) error {
	if d == nil {
		return nil
	}
	d.closeMu.Lock()
	d.finishStarted = true
	if d.finishGate == nil {
		d.finishGate = make(chan struct{}, 1)
	}
	gate := d.finishGate
	d.closeMu.Unlock()
	select {
	case gate <- struct{}{}:
		defer func() { <-gate }()
	case <-ctx.Done():
		return &daemonShutdownIncomplete{owner: d, cause: ctx.Err()}
	}
	d.admission.seal()
	if d.stopRuntime != nil {
		d.stopRuntime()
	}
	if d.shutdownDone == nil && d.server != nil {
		d.shutdownDone = make(chan struct{})
		go func() {
			shutdownContext, cancel := context.WithTimeout(context.Background(), daemonShutdownTimeout)
			defer cancel()
			d.shutdownErr = d.server.Shutdown(shutdownContext)
			close(d.shutdownDone)
		}()
	}
	var drainErr error
	var terminalErr error
	// Attempt every admission barrier even when another drain exhausts the budget.
	for _, supervisor := range d.supervisors {
		if finisher, ok := supervisor.(daemonSupervisorFinish); ok {
			complete, err := finisher.Finish(ctx)
			if complete {
				terminalErr = errors.Join(terminalErr, err)
			} else {
				drainErr = errors.Join(drainErr, err)
				if err == nil {
					drainErr = errors.Join(drainErr, worker.ErrWorkerDrain)
				}
			}
		} else if shutdown, ok := supervisor.(daemonSupervisorShutdown); ok {
			drainErr = errors.Join(drainErr, shutdown.Shutdown(ctx))
		}
	}
	drainErr = errors.Join(drainErr, d.admission.drain(ctx))
	for _, result := range d.runtimeResults {
		select {
		case <-result.done:
		case <-ctx.Done():
			drainErr = errors.Join(drainErr, ctx.Err())
		}
	}
	if d.shutdownDone != nil {
		select {
		case <-d.shutdownDone:
		case <-ctx.Done():
			drainErr = errors.Join(drainErr, ctx.Err())
		}
	}
	runtimeErr := errors.Join(d.runtimeError(), terminalErr)
	if drainErr != nil {
		return &daemonShutdownIncomplete{owner: d, cause: errors.Join(runtimeErr, drainErr)}
	}
	if d.closersDone == nil {
		d.closersDone = make(chan struct{})
		go func() {
			for index := len(d.closers) - 1; index >= 0; index-- {
				if d.closers[index] != nil {
					d.closeErr = errors.Join(d.closeErr, d.closers[index].Close())
				}
			}
			close(d.closersDone)
		}()
	}
	select {
	case <-d.closersDone:
		return errors.Join(runtimeErr, d.shutdownErr, d.closeErr)
	case <-ctx.Done():
		return &daemonShutdownIncomplete{owner: d, cause: errors.Join(runtimeErr, d.shutdownErr, ctx.Err())}
	}
}

func (d *daemon) runtimeError() error {
	var err error
	for _, result := range d.runtimeResults {
		select {
		case <-result.done:
			if !onlyDaemonStartupCancellation(result.err, context.Canceled) && !onlyDaemonStartupCancellation(result.err, http.ErrServerClosed) && !onlyDaemonStartupCancellation(result.err, worker.ErrRepositorySupervisorShutdown) {
				err = errors.Join(err, result.err)
			}
		default:
		}
	}
	return err
}
