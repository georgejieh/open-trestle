package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimeadmin"
)

func runtimeStatusServer(t *testing.T, capabilities []Capability) *Server {
	t.Helper()
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, capabilities)
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	configuration, err := runtimeadmin.NewConfiguration(runtimeadmin.ConfigurationOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a", "repo-b"}, MetadataBackend: runtimeadmin.MetadataLocal, ArtifactBackend: runtimeadmin.ArtifactLocal, ArtifactProtection: runtimeadmin.ProtectionProcessPrivate, NotificationBackend: runtimeadmin.NotificationProcessLocal, RateLimitBackend: runtimeadmin.RateLimitProcessLocal, ReviewMode: runtimeadmin.ReviewDisabled})
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	close(ready)
	service, _ := runtimeadmin.NewService(configuration, []runtimeadmin.ReadinessProbe{{Name: "task_notifications", Ready: ready}})
	journal := controlplane.NewMemoryRunJournal()
	server, err := NewServerWithAdministration(journal, authenticator, fixedClock{at: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)}, service)
	if err != nil {
		t.Fatal(err)
	}
	return server
}
func TestServerReturnsScopedRuntimeStatus(t *testing.T) {
	server := runtimeStatusServer(t, []Capability{CapabilityRuntimeRead})
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runtime", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Status        json.RawMessage `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Contract != "open-trestle/runtime-status-response" || envelope.SchemaVersion != 1 || envelope.RequestID == "" {
		t.Fatalf("envelope: %v %#v", err, envelope)
	}
	snapshot, err := runtimeadmin.DecodeSnapshot(envelope.Status)
	if err != nil || snapshot.RepositoryID() != "repo-a" || !snapshot.Ready() {
		t.Fatalf("snapshot: %v", err)
	}
	if strings.Contains(response.Body.String(), "repo-b") {
		t.Fatal("another repository leaked")
	}
}
func TestServerEnforcesRuntimeStatusAuthority(t *testing.T) {
	path := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runtime"
	denied := runtimeStatusServer(t, []Capability{CapabilityRunRead})
	response := httptest.NewRecorder()
	denied.ServeHTTP(response, authenticatedRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("read capability status=%d", response.Code)
	}
	server := runtimeStatusServer(t, []Capability{CapabilityRuntimeRead})
	cases := []struct {
		method, path string
		body         []byte
		status       int
	}{{http.MethodGet, "https://trestle.test/api/v1/tenants/other/repositories/repo-a/runtime", nil, http.StatusForbidden}, {http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-b/runtime", nil, http.StatusForbidden}, {http.MethodPost, path, nil, http.StatusMethodNotAllowed}, {http.MethodGet, path, []byte("x"), http.StatusBadRequest}}
	for _, test := range cases {
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, authenticatedRequest(test.method, test.path, test.body))
		if recorder.Code != test.status {
			t.Fatalf("%s %s status=%d body=%s", test.method, test.path, recorder.Code, recorder.Body.String())
		}
	}
}
