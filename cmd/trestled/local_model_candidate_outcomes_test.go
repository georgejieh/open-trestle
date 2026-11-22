//go:build unix

package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestDaemonLocalModelWorkersEmptyAndMalformedCandidates(t *testing.T) {
	t.Parallel()
	cliPath := filepath.Join(t.TempDir(), "trestle")
	buildCLI := exec.Command("go", "build", "-o", cliPath, "../trestle")
	if output, err := buildCLI.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v %s", err, output)
	}
	for _, mode := range []string{"empty", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			fake.generation.generationOutcome = mode
			args = append(args, "--local-model-workers")
			build := func() *daemon {
				t.Helper()
				d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
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
			command := func(args []string) []byte {
				t.Helper()
				cmd := exec.Command(cliPath, args...)
				cmd.Env = append(os.Environ(), "OPEN_TRESTLE_API_TOKEN="+getenv("OPEN_TRESTLE_API_TOKEN"))
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("CLI result: %v %s", err, output)
				}
				return bytes.TrimSpace(output)
			}
			assertParity := func(scope audit.ReviewScope, set diagnostics.Set) {
				t.Helper()
				cliArgs := []string{"--server", server.URL}
				packagedAssertResultParity(t, command, cliArgs, scope, set)
				if set.VerifiedSetIdentity() != "" {
					packagedAssertProgressParity(t, command, cliArgs, scope, api, &set)
					return
				}
				progress := packagedAssertProgressParity(t, command, cliArgs, scope, api, nil)
				coverage := progress.Progress.Verification
				if coverage.State != "unavailable" || coverage.Candidates != nil || coverage.Verified != nil || coverage.Rejected != nil || coverage.Inconclusive != nil {
					t.Fatal("failed generation invented verification counts")
				}
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
			assertParity(scope, final)
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
			if mode == "malformed" {
				var ledger *audit.FileLedger
				for _, closer := range d.closers {
					if value, ok := closer.(*audit.FileLedger); ok {
						ledger = value
					}
				}
				if ledger == nil {
					t.Fatal("daemon audit ledger missing")
				}
				events, err := ledger.Read(context.Background(), scope, 0, 64)
				if err != nil {
					t.Fatal(err)
				}
				contextTask, _ := receipt.Task("context")
				inputArtifact, err := d.artifactStore.Get(context.Background(), scope, contextTask.OutputIdentity(), time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
				if err != nil {
					t.Fatal(err)
				}
				contextArtifact, err := d.artifactStore.Get(context.Background(), scope, input.ContextArtifactIdentity(), time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				found := 0
				for _, event := range events {
					if event.Kind() != audit.EventGenerationRejected {
						continue
					}
					found++
					value, err := d.artifactStore.Get(context.Background(), scope, event.SubjectIdentity(), time.Now().UTC())
					if err != nil {
						t.Fatal(err)
					}
					rejection, err := modelhandler.ParseGenerationRejectionArtifact(value, inputArtifact, contextArtifact)
					if err != nil || rejection.Attempt().Authorization().Identity() != input.Authorization().Identity() || rejection.HandlerIdentity() != candidate.HandlerIdentity() {
						t.Fatalf("stored rejection lineage: %v", err)
					}
					facts, err := d.journal.(*controlplane.FileRunJournal).InspectHistoricalContextPackets(context.Background())
					if err != nil || len(facts) != 1 {
						t.Fatalf("rejection historical facts: %v", err)
					}
					linked, ok := facts[0].LinkedInputEvent()
					if !ok {
						t.Fatal("rejection input link missing")
					}
					requestArtifact, err := d.artifactStore.Get(context.Background(), scope, input.SanitizedRequestArtifactIdentity(), time.Now().UTC())
					if err != nil {
						t.Fatal(err)
					}
					sanitized, err := review.ParseSanitizedModelRequest(requestArtifact.Payload())
					if err != nil {
						t.Fatal(err)
					}
					request, err := sanitized.ProviderRequest()
					if err != nil {
						t.Fatal(err)
					}
					pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
					if err != nil {
						t.Fatal(err)
					}
					route, err := runtimecatalog.PlanLocalGenerationRoute(context.Background(), scope, request, policy, inventory, pair)
					if err != nil {
						t.Fatal(err)
					}
					receiptArtifact, err := d.artifactStore.Get(context.Background(), scope, input.SanitizedEgressReceiptArtifactIdentity(), time.Now().UTC())
					if err != nil {
						t.Fatal(err)
					}
					testGenerationRejectionAuditProof(t, events, value, inputArtifact, contextArtifact, requestArtifact, receiptArtifact, linked.InputDescriptor(), route, candidate.HandlerIdentity(), time.Now().UTC())
					testGenerationRejectionJournal(t, facts[0], events, time.Now().UTC())
					testGenerationRejectionPhysical(t, facts[0], inventory, policy, candidate.HandlerIdentity(), args, repository)
					testGenerationRejectionLateClock(t, d, args, getenv, facts[0], repository)
				}
				if found != 1 {
					t.Fatalf("rejection events=%d", found)
				}
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "malformed" {
				testGenerationRejectionStartupRefusals(t, args, getenv, scope)
				d = build()
				server = httptest.NewServer(d.server.Handler)
				api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
				if err != nil {
					t.Fatal(err)
				}
				after, err := api.GetDiagnosticSet(context.Background(), scope)
				if err != nil || after.Identity() != final.Identity() {
					t.Fatalf("first reopen changed rejected result: %v", err)
				}
				assertParity(scope, after)
				fake.generation.generationOutcome = "empty"
				laterScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-after-rejected-generation")
				later, err := runtimecatalog.NewLocalFullReviewIntent(laterScope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := api.SubmitLocalFullReview(context.Background(), later); err != nil {
					t.Fatal(err)
				}
				for _, index := range []int{1, 2, 1} {
					if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				laterFinal, err := api.GetDiagnosticSet(context.Background(), laterScope)
				if err != nil || laterFinal.Outcome() != diagnostics.FinalOutcomeCompleted || laterFinal.CandidateCount() != 0 || laterFinal.VerifiedSetIdentity() == "" {
					t.Fatalf("later run: %v", err)
				}
				assertParity(laterScope, laterFinal)
				server.Close()
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
				d = build()
				server = httptest.NewServer(d.server.Handler)
				defer server.Close()
				api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
				if err != nil {
					t.Fatal(err)
				}
				for _, index := range []int{1, 2} {
					if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				for _, wanted := range []struct {
					scope    audit.ReviewScope
					identity string
				}{{scope, final.Identity()}, {laterScope, laterFinal.Identity()}} {
					got, err := api.GetDiagnosticSet(context.Background(), wanted.scope)
					if err != nil || got.Identity() != wanted.identity {
						t.Fatalf("second reopen changed result: %v", err)
					}
					assertParity(wanted.scope, got)
				}
				if calls, _, _, failures := fake.generation.snapshot(); calls != 2 || len(failures) != 0 {
					t.Fatalf("generation calls=%d failures=%v", calls, failures)
				}
				if calls, _, _, failures := fake.verification.snapshot(); calls != 1 || len(failures) != 0 {
					t.Fatalf("verification calls=%d failures=%v", calls, failures)
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
			assertParity(scope, after)
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
