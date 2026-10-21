//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonLocalModelAdmissionRefusalsAndRestartReplay(t *testing.T) {
	ctx := context.Background()
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	build := func() *daemon {
		t.Helper()
		d, err := buildDaemonWithDependencies(ctx, args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := build()
	t.Cleanup(func() { d.Close() })
	server := httptest.NewServer(d.server.Handler)
	t.Cleanup(func() { server.Close() })
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	makeIntent := func(run, tenant, repoID string, revision evidence.RevisionIdentity, at time.Time) runtimecatalog.LocalFullReviewIntent {
		t.Helper()
		scope, err := audit.NewReviewScope(tenant, repoID, run)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, revision, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), at)
		if err != nil {
			t.Fatal(err)
		}
		return intent
	}
	assertNoPlan := func(intent runtimecatalog.LocalFullReviewIntent) {
		t.Helper()
		if _, found, err := d.journal.LoadPlan(ctx, intent.Scope()); err != nil || found {
			t.Fatalf("refused request opened plan: found=%t err=%v", found, err)
		}
	}
	assertAPIError := func(err error, status int, code string) {
		t.Helper()
		var apiErr *client.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode() != status || apiErr.Code() != code {
			t.Fatalf("API error=%v want status=%d code=%s", err, status, code)
		}
	}
	assertNoDispatch := func() {
		t.Helper()
		for _, index := range []int{1, 2} {
			if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if calls, _, _, failures := fake.generation.snapshot(); calls != 0 || len(failures) != 0 {
			t.Fatalf("generation calls=%d failures=%v", calls, failures)
		}
		if calls, _, _, failures := fake.verification.snapshot(); calls != 0 || len(failures) != 0 {
			t.Fatalf("verification calls=%d failures=%v", calls, failures)
		}
	}
	objects := daemonTestFlagValue(t, args, "--local-git-objects-root")
	otherHead := daemonTestRevision(t, objects, []byte("package main\nfunc main() { /* distinct admitted head */ }\n"))
	now := time.Now().UTC()
	unauthenticated := makeIntent("run-unauthenticated", "tenant-a", "repo-a", head, now)
	wrongCredential, err := client.NewLocal(server.URL, strings.Repeat("x", 32), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrongCredential.SubmitLocalFullReview(ctx, unauthenticated)
	assertAPIError(err, http.StatusUnauthorized, "unauthenticated")
	assertNoPlan(unauthenticated)
	refused := []runtimecatalog.LocalFullReviewIntent{unauthenticated}
	for _, scope := range []struct{ run, tenant, repository string }{{"run-other-tenant", "tenant-b", "repo-a"}, {"run-other-repository", "tenant-a", "repo-b"}} {
		intent := makeIntent(scope.run, scope.tenant, scope.repository, head, now)
		_, err := api.SubmitLocalFullReview(ctx, intent)
		assertAPIError(err, http.StatusForbidden, "forbidden")
		assertNoPlan(intent)
		refused = append(refused, intent)
	}
	stale := makeIntent("run-stale", "tenant-a", "repo-a", head, now.Add(-10*time.Minute))
	_, err = api.SubmitLocalFullReview(ctx, stale)
	assertAPIError(err, http.StatusConflict, "stale_request")
	assertNoPlan(stale)
	malformed := makeIntent("run-malformed", "tenant-a", "repo-a", head, now)
	encoded, err := runtimecatalog.EncodeLocalFullReviewIntent(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"schema_version":1`)) {
		t.Fatal("expected schema version missing from fixture")
	}
	encoded = bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":99`), 1)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/runs", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+getenv("OPEN_TRESTLE_API_TOKEN"))
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed response status=%d read=%v close=%v", response.StatusCode, readErr, closeErr)
	}
	assertNoPlan(malformed)
	refused = append(refused, stale, malformed)
	assertNoDispatch()

	intent := makeIntent("run-replay", "tenant-a", "repo-a", head, time.Now().UTC())
	before, err := api.SubmitLocalFullReview(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := api.GetRunPlan(ctx, intent.Scope())
	if err != nil {
		t.Fatal(err)
	}
	conflict := makeIntent("run-replay", "tenant-a", "repo-a", otherHead, intent.CreatedAt())
	_, err = api.SubmitLocalFullReview(ctx, conflict)
	assertAPIError(err, http.StatusConflict, "conflict")
	replayed, err := api.SubmitLocalFullReview(ctx, intent)
	if err != nil || replayed.Identity() != before.Identity() {
		t.Fatalf("active replay changed receipt: %v", err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d = build()
	server = httptest.NewServer(d.server.Handler)
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	for _, rejected := range refused {
		assertNoPlan(rejected)
	}
	_, err = api.SubmitLocalFullReview(ctx, conflict)
	assertAPIError(err, http.StatusConflict, "conflict")
	reopened, err := api.SubmitLocalFullReview(ctx, intent)
	if err != nil || reopened.Identity() != before.Identity() {
		t.Fatalf("restart replay changed receipt: %v", err)
	}
	afterPlan, err := api.GetRunPlan(ctx, intent.Scope())
	if err != nil || afterPlan.Identity() != plan.Identity() {
		t.Fatalf("restart replay changed plan: %v", err)
	}
	changed := makeIntent("run-new-head", "tenant-a", "repo-a", otherHead, time.Now().UTC())
	newRun, err := api.SubmitLocalFullReview(ctx, changed)
	if err != nil || newRun.PlanIdentity() == before.PlanIdentity() {
		t.Fatalf("new scope/head did not create distinct plan: %v", err)
	}
	if calls, _, _, failures := fake.generation.snapshot(); calls != 0 || len(failures) != 0 {
		t.Fatalf("admission dispatched generation: calls=%d failures=%v", calls, failures)
	}
	if calls, _, _, failures := fake.verification.snapshot(); calls != 0 || len(failures) != 0 {
		t.Fatalf("admission dispatched verifier: calls=%d failures=%v", calls, failures)
	}
}
