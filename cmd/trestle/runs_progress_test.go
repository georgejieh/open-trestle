package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestRunStatusProgressUsesBoundReceiptWithoutDiagnosticRead(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	axes := map[string]any{}
	for _, name := range []string{"change", "deterministic", "context", "verification"} {
		axes[name] = map[string]any{"state": "not_run"}
	}
	response, _ := json.Marshal(map[string]any{"contract": "open-trestle/run-progress-response", "schema_version": 1, "request_id": "request-progress", "run": json.RawMessage(encodedReceipt), "progress": axes})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/progress" || r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	var stdout, stderr bytes.Buffer
	args := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL, "--format", "progress"}
	if exit := run(args, &stdout, &stderr); exit != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr.String())
	}
	var output struct {
		Run      json.RawMessage `json:"run"`
		Progress map[string]struct {
			State string `json:"state"`
		} `json:"progress"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	parsed, err := controlplane.ParseReviewRunReceipt(output.Run)
	if err != nil || parsed.Identity() != receipt.Identity() || len(output.Progress) != 4 || output.Progress["context"].State != "not_run" || strings.Contains(stdout.String(), "diagnostics") || requests != 1 || stderr.Len() != 0 {
		t.Fatalf("output=%s stderr=%s requests=%d", stdout.String(), stderr.String(), requests)
	}
}

func TestRunCancelRefusesProgressFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"runs", "cancel", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--format", "progress"}, &stdout, &stderr); exit != 2 || stdout.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q", exit, stdout.String())
	}
}
