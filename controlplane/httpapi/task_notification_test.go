package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerOffersAuthenticatedTaskNotificationLease(t *testing.T) {
	plan := apiPlan(t)
	journal := controlplane.NewMemoryRunJournal()
	queue := controlplane.NewMemoryTaskNotificationQueue()
	principal, _ := NewPrincipal("worker-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunWrite, CapabilityTaskClaim})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	server, err := NewServerWithRuntimeServices(journal, authenticator, fixedClock{time.UnixMilli(1000)}, diagnostics.NewMemoryStore(), queue)
	if err != nil {
		t.Fatal(err)
	}
	encodedPlan, _ := controlplane.EncodeReviewRunPlan(plan)
	submit := httptest.NewRecorder()
	server.ServeHTTP(submit, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", encodedPlan))
	if submit.Code != http.StatusAccepted {
		t.Fatalf("submit=%d %s", submit.Code, submit.Body.String())
	}
	claimBody, _ := json.Marshal(taskNotificationClaimRequestRecord{Contract: "open-trestle/task-notification-claim-request", SchemaVersion: 1, WaitMilliseconds: 0, LeaseDurationMilliseconds: 1000})
	path := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/worker/notifications/claim"
	claim := httptest.NewRecorder()
	server.ServeHTTP(claim, authenticatedRequest(http.MethodPost, path, claimBody))
	if claim.Code != http.StatusOK {
		t.Fatalf("claim=%d %s", claim.Code, claim.Body.String())
	}
	var response apiResponseRecord
	if err := json.Unmarshal(claim.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	lease, err := controlplane.ParseTaskNotificationLease(response.Lease)
	if err != nil || lease.WorkerIdentity() != "worker-1" || lease.Notification().TaskKey() != "source" {
		t.Fatalf("lease=(%#v,%v)", lease, err)
	}
	encodedLease, _ := controlplane.EncodeTaskNotificationLease(lease)
	ackPath := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/worker/notifications/acknowledge"
	ack := httptest.NewRecorder()
	server.ServeHTTP(ack, authenticatedRequest(http.MethodPost, ackPath, encodedLease))
	if ack.Code != http.StatusNoContent || ack.Body.Len() != 0 {
		t.Fatalf("ack=%d %s", ack.Code, ack.Body.String())
	}
	stale := httptest.NewRecorder()
	server.ServeHTTP(stale, authenticatedRequest(http.MethodPost, ackPath, encodedLease))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale=%d %s", stale.Code, stale.Body.String())
	}
}
