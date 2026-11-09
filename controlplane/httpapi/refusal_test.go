package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/webhook"
)

type fixedRefusals struct{ record webhook.RefusalRecord }

func (r fixedRefusals) DeliveryRefusal(_ context.Context, scope audit.ReviewScope) (webhook.RefusalRecord, bool, error) {
	if scope.ReviewRunID() != "webhook-"+r.record.DeduplicationKey() {
		return webhook.RefusalRecord{}, false, nil
	}
	return r.record, true, nil
}

// A refused delivery has no run; the refusal route reports its recorded,
// content-free reason under the same scope and capability as run reads.
func TestServerReportsADeliveryRefusal(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant", "repository")
	delivery, err := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"secret":"payload"}`), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := webhook.NewStoredDelivery(delivery, time.UnixMilli(1000))
	record, err := webhook.NewRefusalRecord(stored, strings.Repeat("d", 64), webhook.RefusalReasonRetriesExhausted, time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	principal, _ := NewPrincipal("operator", "tenant", []string{"repository"}, []Capability{CapabilityRunRead})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	base, err := NewServer(coordinator, authenticator, fixedClock{time.UnixMilli(500)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.WithDeliveryRefusals(nil); err == nil {
		t.Fatal("nil refusal reader accepted")
	}
	server, err := base.WithDeliveryRefusals(fixedRefusals{record: record})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/tenants/tenant/repositories/repository/runs/webhook-" + delivery.DeduplicationKey() + "/refusal"
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, authenticatedRequest(http.MethodGet, path, nil))
	var response struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Refusal       json.RawMessage `json:"refusal"`
	}
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &response) != nil || response.Contract != "open-trestle/delivery-refusal-response" || response.SchemaVersion != 1 {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	parsed, err := webhook.ParseRefusalRecord(response.Refusal)
	if err != nil || parsed.Identity() != record.Identity() || parsed.Reason() != webhook.RefusalReasonRetriesExhausted || strings.Contains(recorder.Body.String(), "payload") {
		t.Fatalf("refusal=%v body=%s", err, recorder.Body.String())
	}
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "controlplane", "delivery-refusal-response-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			Refusal struct {
				Required []string `json:"required"`
			} `json:"refusal"`
		} `json:"properties"`
	}
	var envelope, refusal map[string]json.RawMessage
	if json.Unmarshal(schemaBytes, &schema) != nil || json.Unmarshal(recorder.Body.Bytes(), &envelope) != nil || json.Unmarshal(response.Refusal, &refusal) != nil || len(envelope) != len(schema.Required) || len(refusal) != len(schema.Properties.Refusal.Required) {
		t.Fatal("response does not match its published schema shape")
	}
	for _, key := range schema.Properties.Refusal.Required {
		if _, ok := refusal[key]; !ok {
			t.Fatalf("refusal lacks %s", key)
		}
	}
	for _, c := range []struct {
		request *http.Request
		server  *Server
		status  int
	}{
		{httptest.NewRequest(http.MethodGet, path, nil), server, http.StatusUnauthorized},
		{authenticatedRequest(http.MethodGet, strings.Replace(path, "tenants/tenant", "tenants/tenant-b", 1), nil), server, http.StatusForbidden},
		{authenticatedRequest(http.MethodPost, path, nil), server, http.StatusMethodNotAllowed},
		{authenticatedRequest(http.MethodGet, strings.Replace(path, delivery.DeduplicationKey(), strings.Repeat("b", 64), 1), nil), server, http.StatusNotFound},
		{authenticatedRequest(http.MethodGet, path, nil), base, http.StatusNotFound},
	} {
		recorder := httptest.NewRecorder()
		c.server.ServeHTTP(recorder, c.request)
		if recorder.Code != c.status {
			t.Fatalf("%s %s status=%d want %d", c.request.Method, c.request.URL.Path, recorder.Code, c.status)
		}
	}
}
