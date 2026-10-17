package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestRunStatusStoredReopenedV1RemainsAdvisory(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-v1-reopened")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	historicalFinding, err := diagnostics.NewFinding(
		strings.Repeat("a", 64), strings.Repeat("b", 64), "Historical finding", "Recorded legacy evidence.",
		diagnostics.SeverityWarning, "main.go", 4, 4, []string{strings.Repeat("c", 64)},
	)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSet(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), []diagnostics.Finding{historicalFinding})
	if err != nil || set.SchemaVersion() != 1 {
		t.Fatalf("historical set: %v", err)
	}
	canonical, err := diagnostics.EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "diagnostics")
	writer, err := diagnostics.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if inserted, err := writer.PutDiagnosticSet(ctx, set); err != nil || !inserted {
		t.Fatalf("put=%t err=%v", inserted, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := diagnostics.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stored, err := reopened.GetDiagnosticSet(ctx, scope)
	if err != nil || stored.Identity() != set.Identity() {
		t.Fatalf("reopened set: %v", err)
	}
	token := "01234567890123456789012345678901"
	principal, err := httpapi.NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: token, Principal: principal}})
	if err != nil {
		t.Fatal(err)
	}
	serverHandler, err := httpapi.NewServerWithDiagnostics(coordinator, authenticator, httpapi.SystemClock{}, reopened)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(serverHandler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, token, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	fromAPI, err := api.GetDiagnosticSet(ctx, scope)
	if err != nil || fromAPI.Identity() != set.Identity() {
		t.Fatalf("API diagnostic set: %v", err)
	}
	t.Setenv("OPEN_TRESTLE_API_TOKEN", token)
	args := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-v1-reopened", "--server", server.URL}
	invoke := func(format string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if exit := run(append(append([]string{}, args...), "--format", format), &stdout, &stderr); exit != 0 || stderr.Len() > 0 {
			t.Fatalf("%s: exit=%d stderr=%q", format, exit, stderr.String())
		}
		return stdout.Bytes()
	}
	jsonOutput := invoke("json")
	if !bytes.Equal(jsonOutput, append(append([]byte{}, canonical...), '\n')) {
		t.Fatal("reopened CLI JSON changed canonical bytes")
	}
	sarifOutput := invoke("sarif")
	var log struct {
		Runs []struct {
			Properties struct {
				Status string `json:"trestleStatus"`
				Reason string `json:"trestleReason"`
				SetID  string `json:"trestleDiagnosticSetId"`
			} `json:"properties"`
			Results []struct {
				Fingerprints map[string]string `json:"fingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarifOutput, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF runs=%d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Properties.SetID != set.Identity() || run.Properties.Status != "inconclusive" ||
		!strings.Contains(run.Properties.Reason, "source coverage unavailable") || len(run.Results) != 1 {
		t.Fatalf("historical SARIF changed authority: %+v", run)
	}
	if run.Results[0].Fingerprints["openTrestleVerifiedFindingId/v1"] != historicalFinding.Identity() {
		t.Fatalf("historical SARIF finding identity changed: %+v", run.Results[0])
	}
}
