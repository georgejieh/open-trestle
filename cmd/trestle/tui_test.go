package main

import (
	"bytes"
	"encoding/json"
	"github.com/georgejieh/open-trestle/controlplane"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunTUIUsesAuthenticatedDaemonReceipt(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	runResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-tui", "run": json.RawMessage(encodedReceipt)})
	errorResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-diag", "error": map[string]any{"code": "diagnostics_not_found", "message": "verified diagnostics not found"}})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Error("authorization missing")
		}
		writer.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(request.URL.Path, "/diagnostics") {
			writer.WriteHeader(http.StatusNotFound)
			_, _ = writer.Write(errorResponse)
			return
		}
		_, _ = writer.Write(runResponse)
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	var stdout, stderr bytes.Buffer
	exit := runTUI([]string{"--server", server.URL, "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--plain", "--once"}, strings.NewReader(""), &stdout, &stderr)
	if exit != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	if requests != 2 || !strings.Contains(stdout.String(), "OPEN TRESTLE") || !strings.Contains(stdout.String(), "No verified diagnostic snapshot") {
		t.Fatalf("requests=%d output=%s", requests, stdout.String())
	}
}
func TestRunTUIRejectsMissingCredentialAndUnsafeOptions(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	var stdout, stderr bytes.Buffer
	args := []string{"--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--plain", "--once"}
	if exit := runTUI(args, strings.NewReader(""), &stdout, &stderr); exit != 2 || !strings.Contains(stderr.String(), "OPEN_TRESTLE_API_TOKEN") {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	stderr.Reset()
	if exit := runTUI(append(args, "--refresh", "1ms"), strings.NewReader(""), &stdout, &stderr); exit != 2 || !strings.Contains(stderr.String(), "invalid terminal interface") {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
}
