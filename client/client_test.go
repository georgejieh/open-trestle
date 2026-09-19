package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/runtimeadmin"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const clientTestToken = "01234567890123456789012345678901"

func clientReceipt(t *testing.T) controlplane.ReviewRunReceipt {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	state, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
func responseBody(t *testing.T, receipt controlplane.ReviewRunReceipt) []byte {
	t.Helper()
	encoded, _ := controlplane.EncodeReviewRunReceipt(receipt)
	body, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-1", "run": json.RawMessage(encoded)})
	return body
}
func TestClientUsesAuthenticatedVersionedContracts(t *testing.T) {
	receipt := clientReceipt(t)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		if request.Header.Get("Authorization") != "Bearer "+clientTestToken || request.Header.Get("Accept") != "application/json" {
			t.Errorf("headers=%v", request.Header)
		}
		switch requests {
		case 1:
			if request.Method != http.MethodPost || request.URL.Path != "/api/v1/runs" || request.Header.Get("Content-Type") != "application/json" {
				t.Errorf("submit=%s %s", request.Method, request.URL)
			}
			writer.WriteHeader(http.StatusAccepted)
		case 2:
			if request.Method != http.MethodGet || request.URL.Path != "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a" {
				t.Errorf("status=%s %s", request.Method, request.URL)
			}
		case 3:
			if request.Method != http.MethodPost || request.URL.Path != "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/cancel" {
				t.Errorf("cancel=%s %s", request.Method, request.URL)
			}
		}
		_, _ = writer.Write(responseBody(t, receipt))
	}))
	defer server.Close()
	client, err := New(server.URL, clientTestToken, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	planEncodedTask, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(receipt.Scope(), strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{planEncodedTask})
	submitted, err := client.SubmitRun(context.Background(), plan)
	if err != nil || submitted.Identity() != receipt.Identity() {
		t.Fatalf("submit=(%#v,%v)", submitted, err)
	}
	observed, err := client.GetRun(context.Background(), receipt.Scope())
	if err != nil || observed.Identity() != receipt.Identity() {
		t.Fatalf("status=(%#v,%v)", observed, err)
	}
	canceled, err := client.CancelRun(context.Background(), receipt.Scope())
	if err != nil || canceled.Identity() != receipt.Identity() {
		t.Fatalf("cancel=(%#v,%v)", canceled, err)
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
	if fmt.Sprintf("%#v", client) != "client.Client{<redacted>}" {
		t.Fatalf("client leaked: %#v", client)
	}
}
func TestNewRejectsUnsafeEndpointAndCredential(t *testing.T) {
	tests := []struct{ name, url, token string }{{"scheme", "ftp://127.0.0.1", clientTestToken}, {"remote plaintext", "http://example.com", clientTestToken}, {"userinfo", "https://user@example.com", clientTestToken}, {"query", "https://example.com?x=1", clientTestToken}, {"path", "https://example.com/base", clientTestToken}, {"token", "https://example.com", "short"}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := New(test.url, test.token, nil)
			if !errors.Is(err, ErrInvalidClient) || got != nil {
				t.Fatalf("client=(%#v,%v)", got, err)
			}
		})
	}
}
func TestClientReturnsBoundedSanitizedAPIErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"contract":"open-trestle/api-response","schema_version":1,"request_id":"request-1","error":{"code":"forbidden","message":"No access."}}`))
	}))
	defer server.Close()
	client, _ := New(server.URL, clientTestToken, server.Client())
	_, err := client.GetRun(context.Background(), clientReceipt(t).Scope())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode() != http.StatusForbidden || apiErr.Code() != "forbidden" || strings.Contains(err.Error(), clientTestToken) {
		t.Fatalf("error=%#v", err)
	}
}
func TestClientDoesNotForwardCredentialsAcrossRedirects(t *testing.T) {
	redirected := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected = true }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, _ := New(source.URL, clientTestToken, source.Client())
	_, err := client.GetRun(context.Background(), clientReceipt(t).Scope())
	if !errors.Is(err, ErrRedirectRejected) || redirected {
		t.Fatalf("redirect=(%v,%t)", err, redirected)
	}
}

func TestClientReadsScopedVerifiedDiagnostics(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	omission, _ := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 172)
	check, _ := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	set, _ := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 2, 1, 1, 173, 1, 172, []diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{check}, nil)
	encoded, _ := diagnostics.EncodeSet(set)
	body, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-1", "diagnostics": json.RawMessage(encoded)})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	client, _ := New(server.URL, clientTestToken, server.Client())
	got, err := client.GetDiagnosticSet(context.Background(), scope)
	if err != nil || got.Identity() != set.Identity() || got.SchemaVersion() != 5 || len(got.OmissionSummaries()) != 1 || len(got.DeterministicChecks()) != 1 || got.OmissionSummaries()[0].Count() != 172 || got.CandidateCount() != 2 || got.RejectedCount() != 1 || got.InconclusiveCount() != 1 || got.SourceAnalyzedCount() != 173 || got.SourceSelectedCount() != 1 || got.SourceOmittedCount() != 172 {
		t.Fatalf("set=(%#v,%v)", got, err)
	}
}

func TestClientReadsExactReviewRunPlan(t *testing.T) {
	receipt := clientReceipt(t)
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(receipt.Scope(), strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	encoded, _ := controlplane.EncodeReviewRunPlan(plan)
	body, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-plan", "plan": json.RawMessage(encoded)})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/plan") || request.Method != http.MethodGet {
			t.Errorf("request=%s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	apiClient, _ := New(server.URL, clientTestToken, server.Client())
	loaded, err := apiClient.GetRunPlan(context.Background(), plan.Scope())
	if err != nil || loaded.Identity() != plan.Identity() {
		t.Fatalf("plan=(%#v,%v)", loaded, err)
	}
}

func TestClientReadsScopedRuntimeStatus(t *testing.T) {
	configuration, _ := runtimeadmin.NewConfiguration(runtimeadmin.ConfigurationOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, MetadataBackend: runtimeadmin.MetadataLocal, ArtifactBackend: runtimeadmin.ArtifactLocal, ArtifactProtection: runtimeadmin.ProtectionProcessPrivate, NotificationBackend: runtimeadmin.NotificationProcessLocal, RateLimitBackend: runtimeadmin.RateLimitProcessLocal, ReviewMode: runtimeadmin.ReviewDisabled})
	ready := make(chan struct{})
	close(ready)
	service, _ := runtimeadmin.NewService(configuration, []runtimeadmin.ReadinessProbe{{Name: "api", Ready: ready}})
	snapshot, _ := service.Snapshot("tenant-a", "repo-a", time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC))
	encoded, _ := json.Marshal(snapshot)
	body, _ := json.Marshal(map[string]any{"contract": "open-trestle/runtime-status-response", "schema_version": 1, "request_id": "request-1", "status": json.RawMessage(encoded)})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/tenants/tenant-a/repositories/repo-a/runtime" {
			t.Errorf("request=%s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	apiClient, _ := New(server.URL, clientTestToken, server.Client())
	got, err := apiClient.GetRuntimeStatus(context.Background(), "tenant-a", "repo-a")
	if err != nil || got.Identity() != snapshot.Identity() {
		t.Fatalf("status: %v", err)
	}
}
func TestClientRejectsCrossWiredRuntimeStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"contract":"open-trestle/runtime-status-response","schema_version":1,"request_id":"request-1","status":{}}`))
	}))
	defer server.Close()
	apiClient, _ := New(server.URL, clientTestToken, server.Client())
	if _, err := apiClient.GetRuntimeStatus(context.Background(), "tenant-a", "repo-a"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v", err)
	}
}
