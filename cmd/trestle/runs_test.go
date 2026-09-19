package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func remotePlanAndReceipt(t *testing.T) (controlplane.ReviewRunPlan, controlplane.ReviewRunReceipt) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	return plan, receipt
}
func TestRunRemoteCommandsUseDaemonContracts(t *testing.T) {
	plan, receipt := remotePlanAndReceipt(t)
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	response, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-1", "run": json.RawMessage(encodedReceipt)})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Errorf("authorization missing")
		}
		if requests == 1 {
			writer.WriteHeader(http.StatusAccepted)
		}
		_, _ = writer.Write(response)
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_URL", server.URL)
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	encodedPlan, _ := controlplane.EncodeReviewRunPlan(plan)
	planPath := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(planPath, encodedPlan, 0o600); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{{"runs", "submit", "--plan", planPath}, {"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}, {"runs", "cancel", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}}
	for _, command := range commands {
		var stdout, stderr bytes.Buffer
		if exit := run(command, &stdout, &stderr); exit != 0 {
			t.Fatalf("%v exit=%d stderr=%q", command, exit, stderr.String())
		}
		parsed, err := controlplane.ParseReviewRunReceipt(bytes.TrimSpace(stdout.Bytes()))
		if err != nil || parsed.Identity() != receipt.Identity() {
			t.Fatalf("%v output=(%s,%v)", command, stdout.String(), err)
		}
		if stderr.Len() != 0 {
			t.Fatalf("%v stderr=%q", command, stderr.String())
		}
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}
func TestRunRemoteRejectsMissingCredentialAndUnsafePlanInput(t *testing.T) {
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "")
	var stdout, stderr bytes.Buffer
	if exit := run([]string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a"}, &stdout, &stderr); exit != 2 || !strings.Contains(stderr.String(), "OPEN_TRESTLE_API_TOKEN") {
		t.Fatalf("missing token=(%d,%q)", exit, stderr.String())
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "plan.json")
	_ = os.WriteFile(target, []byte("{}"), 0o600)
	link := filepath.Join(directory, "plan-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	stdout.Reset()
	stderr.Reset()
	if exit := run([]string{"runs", "submit", "--plan", link}, &stdout, &stderr); exit != 1 || !strings.Contains(stderr.String(), "regular file") {
		t.Fatalf("symlink=(%d,%q)", exit, stderr.String())
	}
}
