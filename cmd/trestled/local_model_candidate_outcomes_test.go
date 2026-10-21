//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonLocalModelWorkersEmptyAndMalformedCandidates(t *testing.T) {
	for _, mode := range []string{"empty", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			fake.generation.generationOutcome = mode
			args = append(args, "--local-model-workers")
			build := func() *daemon {
				t.Helper()
				d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
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
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-candidates-"+mode)
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{1, 2, 1} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			final, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			if len(final.Findings()) != 0 || final.VerifiedCount() != 0 {
				t.Fatal("empty or invalid candidates promoted findings")
			}
			if mode == "empty" && (final.Outcome() != diagnostics.FinalOutcomeCompleted || final.CandidateCount() != 0 || final.VerifiedSetIdentity() == "") {
				receipt, _ := api.GetRun(context.Background(), scope)
				for _, task := range receipt.Tasks() {
					t.Logf("task=%s state=%s failure=%s", task.Key(), task.Status(), task.Failure())
				}
				t.Fatalf("empty result=%s", final.Outcome())
			}
			if mode == "malformed" && (final.Outcome() != diagnostics.FinalOutcomeInconclusive || final.VerifiedSetIdentity() != "") {
				t.Fatalf("malformed result=%s", final.Outcome())
			}
			receipt, err := api.GetRun(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			candidate, _ := receipt.Task("candidates")
			if mode == "malformed" && (candidate.Status() != controlplane.TaskRuntimeFailed || candidate.OutputIdentity() != "") {
				t.Fatal("malformed candidates persisted output")
			}
			progress, err := api.GetRunProgress(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "empty" && (progress.Progress.Verification.Verified == nil || *progress.Progress.Verification.Verified != 0) {
				t.Fatal("empty verification did not expose measured zero")
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "malformed" {
				restarted, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
				if restarted != nil {
					restarted.Close()
					t.Fatal("unproven failed model history admitted")
				}
				if !errors.Is(err, errHistoricalInputIntentQuarantinedAtStartup) {
					t.Fatalf("failed model startup refusal=%v", err)
				}
				if calls, _, _, failures := fake.generation.snapshot(); calls != 1 || len(failures) != 0 {
					t.Fatalf("malformed generation calls=%d failures=%v", calls, failures)
				}
				if calls, _, _, failures := fake.verification.snapshot(); calls != 0 || len(failures) != 0 {
					t.Fatalf("malformed verification calls=%d failures=%v", calls, failures)
				}
				return
			}
			d = build()
			server = httptest.NewServer(d.server.Handler)
			api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{1, 2} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			after, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil || after.Identity() != final.Identity() {
				t.Fatalf("restart changed result: %v", err)
			}
			if calls, _, _, failures := fake.generation.snapshot(); calls != 1 || len(failures) != 0 {
				t.Fatalf("generation calls=%d failures=%v", calls, failures)
			}
			wantVerification := 1
			if mode == "malformed" {
				wantVerification = 0
			}
			if calls, _, _, failures := fake.verification.snapshot(); calls != wantVerification || len(failures) != 0 {
				t.Fatalf("verification calls=%d want=%d failures=%v", calls, wantVerification, failures)
			}
		})
	}
}
