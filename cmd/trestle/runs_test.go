package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
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

func TestRunStatusExportsSameStoredDeterministicSetAsJSONAndSARIF(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	analysisIdentity := strings.Repeat("8", 64)
	changeIdentity := strings.Repeat("7", 64)
	sourceCheck := diagnostics.DeterministicCheck{}
	// Use the canonical source-check identity for one failed exact match.
	check, err := diagnostics.NewDeterministicCheck("24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b", analysisIdentity, changeIdentity, diagnostics.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	_ = sourceCheck
	observation, _ := diagnostics.NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64), analysisIdentity, check.Identity(), "Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.", diagnostics.SeverityWarning, "main.go", 3, 3, []string{strings.Repeat("4", 64), strings.Repeat("9", 64)})
	set, err := diagnostics.NewSetWithDeterministicObservations(receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	encodedReceipt, _ := controlplane.EncodeReviewRunReceipt(receipt)
	encodedSet, _ := diagnostics.EncodeSet(set)
	runResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-run", "run": json.RawMessage(encodedReceipt)})
	diagnosticResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-diagnostics", "diagnostics": json.RawMessage(encodedSet)})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(request.URL.Path, "/diagnostics") {
			_, _ = writer.Write(diagnosticResponse)
		} else {
			_, _ = writer.Write(runResponse)
		}
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	base := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL}
	var jsonOut, jsonErr bytes.Buffer
	if exit := run(append(base, "--format", "json"), &jsonOut, &jsonErr); exit != 0 || !bytes.Equal(bytes.TrimSpace(jsonOut.Bytes()), encodedSet) {
		t.Fatalf("json=(%d,%s,%s)", exit, jsonOut.Bytes(), jsonErr.Bytes())
	}
	var sarifOut, sarifErr bytes.Buffer
	if exit := run(append(base, "--format", "sarif"), &sarifOut, &sarifErr); exit != 0 || !bytes.Contains(sarifOut.Bytes(), []byte(`"uri":"main.go"`)) || !bytes.Contains(sarifOut.Bytes(), []byte(observation.Identity())) || !bytes.Contains(sarifOut.Bytes(), []byte(strings.Repeat("4", 64))) || !bytes.Contains(sarifOut.Bytes(), []byte(strings.Repeat("9", 64))) || !bytes.Contains(sarifOut.Bytes(), []byte("human review is required")) || bytes.Contains(sarifOut.Bytes(), []byte(`"trestleStatus":"verified"`)) {
		t.Fatalf("sarif=(%d,%s,%s)", exit, sarifOut.Bytes(), sarifErr.Bytes())
	}
	var sarif struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID       string            `json:"ruleId"`
				Fingerprints map[string]string `json:"fingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifOut.Bytes(), &sarif); err != nil {
		t.Fatalf("decode v6 SARIF: %v", err)
	}
	if len(sarif.Runs) != 1 || len(sarif.Runs[0].Tool.Driver.Rules) != 1 || sarif.Runs[0].Tool.Driver.Rules[0].ID != "static-debug-output" || len(sarif.Runs[0].Results) != 1 || sarif.Runs[0].Results[0].RuleID != "static-debug-output" || sarif.Runs[0].Results[0].Fingerprints["openTrestleObservationId/v1"] != observation.Identity() {
		t.Fatalf("v6 observation rule/fingerprint not preserved: %+v", sarif.Runs)
	}
}
