package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDaemonCloseSealsRootAdmissionBeforeClosingStores(t *testing.T) {
	admission := &daemonAdmission{}
	sealed := admission.wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	admission.seal()
	recorder := httptest.NewRecorder()
	sealed.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("sealed admission status=%d want=%d", recorder.Code, http.StatusServiceUnavailable)
	}
}

func TestDaemonAdmissionDrainsAdmittedHandlers(t *testing.T) {
	admission := &daemonAdmission{}
	entered, release := make(chan struct{}), make(chan struct{})
	handler := admission.wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		<-release
		writer.WriteHeader(http.StatusOK)
	}))
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	}()
	<-entered
	admission.seal()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := admission.drain(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain error=%v want=%v", err, context.DeadlineExceeded)
	}
	close(release)
	<-finished
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := admission.drain(ctx); err != nil {
		t.Fatalf("drain after handler exit: %v", err)
	}
}

func TestDaemonCloseKeepsStoresOpenUntilHandlerDrains(t *testing.T) {
	d := &daemon{admission: &daemonAdmission{}, handlerDrainTimeout: 25 * time.Millisecond}
	entered, release := make(chan struct{}), make(chan struct{})
	d.server = &http.Server{Handler: d.admission.wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		<-release
		writer.WriteHeader(http.StatusOK)
	}))}
	closed := make(chan struct{})
	d.closers = append(d.closers, daemonCloserFunc(func() error { close(closed); return nil }))
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		d.server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	}()
	<-entered
	first := make(chan error, 1)
	go func() { first <- d.Close() }()
	select {
	case err := <-first:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("first close error=%v want=%v", err, context.DeadlineExceeded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first close did not finish")
	}
	select {
	case <-closed:
		t.Fatal("store cleanup began while the handler was still running")
	default:
	}
	close(release)
	<-finished
	if err := d.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("store cleanup did not run after the handler exited")
	}
}

func TestDaemonCloseWaitsForHandlerBehindHTTPServerShutdown(t *testing.T) {
	d := &daemon{admission: &daemonAdmission{}, handlerDrainTimeout: 250 * time.Millisecond}
	entered, release := make(chan struct{}), make(chan struct{})
	d.server = &http.Server{Handler: d.admission.wrap(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		<-release
		writer.WriteHeader(http.StatusOK)
	}))}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		d.server.Serve(listener)
	}()
	closed := make(chan struct{})
	d.closers = append(d.closers, daemonCloserFunc(func() error { close(closed); return nil }))
	request, err := http.NewRequest(http.MethodGet, "http://"+listener.Addr().String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr == nil {
			response.Body.Close()
		}
	}()
	<-entered
	shutdownContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	shutdownErr := d.server.Shutdown(shutdownContext)
	cancel()
	if shutdownErr == nil {
		t.Fatal("expected the HTTP shutdown deadline to expire while the handler was live")
	}
	select {
	case <-closed:
		t.Fatal("store cleanup began while the handler behind the HTTP server was still running")
	default:
	}
	close(release)
	<-requestDone
	<-served
	if err := d.Close(); err != nil {
		t.Fatalf("close after handler exit: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("store cleanup did not run after the handler exited")
	}
}
