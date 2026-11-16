package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// webhookScopedPlan is apiPlan in the run ID webhook intake opens for a
// delivery.
func webhookScopedPlan(t *testing.T) controlplane.ReviewRunPlan {
	t.Helper()
	plan := apiPlan(t)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "webhook-"+strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := controlplane.NewReviewRunPlan(scope, plan.RequestIdentity(), plan.PolicyIdentity(), plan.Mode(), plan.Tasks())
	if err != nil {
		t.Fatal(err)
	}
	return scoped
}

// Run IDs in the webhook delivery namespace belong to webhook intake: a
// run_write caller cannot open a delivery's run scope ahead of intake, with a
// caller-authored plan or with a local review intent.
func TestServerRefusesCallerRunsInTheWebhookNamespace(t *testing.T) {
	plan := webhookScopedPlan(t)
	refused := func(t *testing.T, server *Server, body []byte) {
		t.Helper()
		response := httptest.NewRecorder()
		server.ServeHTTP(response, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", body))
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response.Body.Bytes()).Code != "invalid_request" {
			t.Fatalf("webhook run ID submission=%d body=%s", response.Code, response.Body.String())
		}
		status := httptest.NewRecorder()
		server.ServeHTTP(status, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/"+plan.Scope().ReviewRunID(), nil))
		if status.Code != http.StatusNotFound {
			t.Fatalf("a caller opened a webhook run scope: status=%d", status.Code)
		}
	}
	t.Run("plan", func(t *testing.T) {
		server, _ := apiServer(t)
		encoded, err := controlplane.EncodeReviewRunPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		refused(t, server, encoded)
	})
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead, CapabilityRunWrite})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	repository, _ := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	t.Run("local deterministic intent", func(t *testing.T) {
		coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
		admitter := &localReviewAdmitterStub{coordinator: coordinator, plan: plan}
		server, err := NewServerWithLocalDeterministicReview(coordinator, authenticator, fixedClock{at: time.UnixMilli(1000)}, admitter)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := runtimecatalog.NewLocalDeterministicReviewIntent(plan.Scope(), repository, base, head, time.UnixMilli(1000))
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := runtimecatalog.EncodeLocalDeterministicReviewIntent(intent)
		refused(t, server, encoded)
		if admitter.calls != 0 {
			t.Fatal("a webhook run ID reached the local review admitter")
		}
	})
	t.Run("local full intent", func(t *testing.T) {
		coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
		admitter := &localFullAdmitterStub{coordinator: coordinator, plan: plan}
		server, err := NewServerWithLocalFullReview(coordinator, authenticator, fixedClock{at: time.UnixMilli(1000)}, admitter)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := runtimecatalog.NewLocalFullReviewIntent(plan.Scope(), repository, base, head, strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), time.UnixMilli(1000))
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := runtimecatalog.EncodeLocalFullReviewIntent(intent)
		refused(t, server, encoded)
		if admitter.calls != 0 {
			t.Fatal("a webhook run ID reached the local full review admitter")
		}
	})
}
