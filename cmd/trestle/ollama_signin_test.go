package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// All Ollama daemons below are in-process loopback httptest servers with
// synthetic model lists. No test contacts a real Ollama daemon or Ollama Cloud.

// TestMain keeps every test in this package away from a real local Ollama
// daemon: by default the tags read finds no daemon, the sign-in probe fails,
// no ollama command is found and none is run. Tests that exercise the
// production readers install them explicitly against a fake daemon.
func TestMain(m *testing.M) {
	ollamaReadTags = func(context.Context, string) ([]ollamaTag, error) { return nil, errOllamaTagsUnavailable }
	ollamaSigninProbe = func(context.Context, string, string) (ollamaProbeOutcome, string) {
		return ollamaProbeFailed, "no daemon in tests"
	}
	ollamaLookPath = func() (string, error) { return "", errors.New("ollama is not installed in tests") }
	ollamaRunSigninChild = func(context.Context) error { return errors.New("ollama signin is not run in tests") }
	os.Exit(m.Run())
}

func TestOllamaTagsReaderIsBoundedToLoopbackTagsDocuments(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"not found":           http.NotFound,
		"not a tags document": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"data":[]}`)) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://ollama.com/api/tags", http.StatusFound)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte(" "), ollamaTagsMaxBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			if _, err := readOllamaDaemonTags(context.Background(), server.URL+"/v1"); !errors.Is(err, errOllamaTagsUnavailable) {
				t.Fatalf("tags reader accepted %s: %v", name, err)
			}
		})
	}
	for _, endpoint := range []string{"https://ollama.com/v1", "http://localhost:11434/v1", "http://192.0.2.1:11434/v1"} {
		if _, err := readOllamaDaemonTags(context.Background(), endpoint); !errors.Is(err, errOllamaTagsUnavailable) {
			t.Fatalf("tags reader contacted a non-loopback address %s", endpoint)
		}
	}
}
