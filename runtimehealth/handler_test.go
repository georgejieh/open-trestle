package runtimehealth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerReportsContentFreeLivenessAndReadiness(t *testing.T) {
	ready := make(chan struct{})
	handler, err := New([]<-chan struct{}{ready})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path   string
		status int
		body   string
	}{{"/healthz", http.StatusOK, `{"contract":"open-trestle/health","schema_version":1,"status":"live"}`}, {"/readyz", http.StatusServiceUnavailable, `{"contract":"open-trestle/health","schema_version":1,"status":"not_ready"}`}} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != test.status || recorder.Body.String() != test.body || recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s=%d %q", test.path, recorder.Code, recorder.Body.String())
		}
	}
	close(ready)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"contract":"open-trestle/health","schema_version":1,"status":"ready"}` {
		t.Fatalf("ready=%d %q", recorder.Code, recorder.Body.String())
	}
}
func TestHandlerRejectsMethodsQueriesAndInvalidChecks(t *testing.T) {
	if _, err := New([]<-chan struct{}{nil}); err != ErrInvalidHealthHandler {
		t.Fatalf("nil=%v", err)
	}
	handler, _ := New(nil)
	for _, request := range []*http.Request{httptest.NewRequest(http.MethodPost, "/healthz", nil), httptest.NewRequest(http.MethodGet, "/readyz?detail=true", nil)} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code < 400 {
			t.Fatalf("status=%d", recorder.Code)
		}
	}
}
