package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonCloseRetainsBlockedResponseHandler(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	d, err := buildDaemon(context.Background(), []string{"--listen", "127.0.0.1:0", "--state-dir", root, "--tenant", "tenant-a", "--repository", "repo-a"}, daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		select {
		case <-returned:
		case <-time.After(time.Second):
			t.Error("root handler cleanup did not complete")
		}
		if err := d.Close(); err != nil {
			t.Errorf("daemon cleanup: %v", err)
		}
	})
	closed := make(chan struct{})
	d.closers = append(d.closers, daemonCloserFunc(func() error { close(closed); return nil }))
	// Hold the actual root handler in its response writer before ServeHTTP returns.
	response := &lifecycleBlockingWriter{ResponseRecorder: httptest.NewRecorder(), entered: entered, release: release}
	go func() {
		defer close(returned)
		d.server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter")
	}
	done := make(chan error, 1)
	go func() { done <- d.Close() }()
	select {
	case <-closed:
		t.Error("store cleanup began while root handler was still executing")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("handler did not return")
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("close did not finish")
	}
}

type lifecycleBlockingWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
}

func (w *lifecycleBlockingWriter) WriteHeader(status int) {
	w.ResponseRecorder.WriteHeader(status)
	close(w.entered)
	<-w.release
}
