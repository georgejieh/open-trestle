package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestFullLocalServerRefusesDirectWorkerAndFinalizerMutation(t *testing.T) {
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	principal, _ := NewPrincipal("worker-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityTaskClaim, CapabilityRunWrite})
	auth, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	server, err := NewServerWithLocalFullReview(coordinator, auth, fixedClock{at: time.UnixMilli(1000)}, &localFullAdmitterStub{coordinator: coordinator, plan: apiPlan(t)})
	if err != nil {
		t.Fatal(err)
	}
	scope := apiPlan(t).Scope()
	claim := httptest.NewRecorder()
	server.handleWorkerOperation(context.Background(), claim, httptest.NewRequest(http.MethodPost, "https://trestle.test/", nil), "test", principal, scope, "source", "claim", time.UnixMilli(1000))
	if claim.Code != http.StatusForbidden {
		t.Fatalf("direct worker status=%d", claim.Code)
	}
	finalize := httptest.NewRecorder()
	server.finalizeRun(context.Background(), finalize, httptest.NewRequest(http.MethodPost, "https://trestle.test/", nil), "test", scope, time.UnixMilli(1000))
	if finalize.Code != http.StatusForbidden {
		t.Fatalf("direct finalizer status=%d", finalize.Code)
	}
}
