//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

// Local review artifacts are retained for 24 hours. A run the journal already
// settled must not stop the daemon from starting once that retention lapses,
// and its receipt and result must stay readable and unchanged. That holds for
// a run whose model requests the provider rate-limited and the handler
// retried on the same route, completed or rejected by document shape.
func TestDaemonLocalModelWorkersSettledRunsStartAfterRetention(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"completed", "verification-rejected", "verification-inconclusive", "generation-empty", "generation-malformed", "canceled-after-context", "completed-after-rate-limits", "generation-malformed-after-rate-limits"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			switch mode {
			case "verification-rejected", "verification-inconclusive":
				fake.verification.verificationOutcome = mode[len("verification-"):]
			case "generation-empty", "generation-malformed":
				fake.generation.generationOutcome = mode[len("generation-"):]
			case "completed-after-rate-limits":
				fake.generation.rateLimits, fake.verification.rateLimits = 2, 1
			case "generation-malformed-after-rate-limits":
				fake.generation.rateLimits, fake.generation.generationOutcome = 2, "malformed"
			}
			args = append(args, "--local-model-workers")
			clock := &daemonFakeHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
			statePath := daemonTestFlagValue(t, args, "--state-dir")
			d, api, server := startContextRefusalDaemon(t, args, getenv, clock)
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-"+mode)
			if err != nil {
				t.Fatal(err)
			}
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
				t.Fatal(err)
			}
			passes := []int{1, 2, 1}
			if mode == "canceled-after-context" {
				passes = []int{1}
			}
			for _, index := range passes {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
					t.Fatalf("supervisor %d: %v", index, err)
				}
			}
			if mode == "canceled-after-context" {
				if _, err := api.CancelRun(context.Background(), scope); err != nil {
					t.Fatal(err)
				}
				for _, index := range []int{1, 2} {
					if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
						t.Fatalf("cancel supervisor %d: %v", index, err)
					}
				}
			}
			receipt, err := api.GetRun(context.Background(), scope)
			if err != nil || receipt.Status() == controlplane.ReviewRunActive {
				t.Fatalf("run not settled: status=%v err=%v", receipt.Status(), err)
			}
			final, err := api.GetDiagnosticSet(context.Background(), scope)
			if err != nil {
				t.Fatalf("no final result: %v", err)
			}
			if strings.HasPrefix(mode, "completed") && (receipt.Status() != controlplane.ReviewRunSucceeded || final.Outcome() != diagnostics.FinalOutcomeCompleted) {
				t.Fatalf("completed fixture status=%v outcome=%s", receipt.Status(), final.Outcome())
			}
			generationCalls, _, _, _ := fake.generation.snapshot()
			verificationCalls, _, _, _ := fake.verification.snapshot()
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			// A retried run also restarts while its artifacts are retained,
			// where startup proves the tail from their bytes.
			advances := []time.Duration{25 * time.Hour}
			if strings.HasSuffix(mode, "after-rate-limits") {
				// The fixture retains a packet for an hour.
				advances = []time.Duration{time.Minute, 25 * time.Hour}
			}
			for _, advance := range advances {
				clock.mu.Lock()
				clock.at = clock.at.Add(advance)
				clock.mu.Unlock()
				journalBefore := ownerStartupJournalBytes(t, statePath)
				d, api, server = startContextRefusalDaemon(t, args, getenv, clock)
				for _, index := range []int{1, 2} {
					if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
						t.Fatalf("restart supervisor %d: %v", index, err)
					}
				}
				if !reflect.DeepEqual(journalBefore, ownerStartupJournalBytes(t, statePath)) {
					t.Fatal("restart appended to a settled run")
				}
				after, err := api.GetRun(context.Background(), scope)
				if err != nil || after.HeadIdentity() != receipt.HeadIdentity() || after.Status() != receipt.Status() {
					t.Fatalf("restart changed the run: %v", err)
				}
				reopened, err := api.GetDiagnosticSet(context.Background(), scope)
				if err != nil || reopened.Identity() != final.Identity() {
					t.Fatalf("restart changed the result: %v", err)
				}
				if calls, _, _, _ := fake.generation.snapshot(); calls != generationCalls {
					t.Fatalf("restart redispatched generation: %d", calls)
				}
				if calls, _, _, _ := fake.verification.snapshot(); calls != verificationCalls {
					t.Fatalf("restart redispatched verification: %d", calls)
				}
				server.Close()
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// Past retention the journal and audit still have to prove the settled tail:
// an extra audit event on a rejected generation, or a scope marker on a
// completed run, keeps startup refused without an append.
func TestDaemonLocalModelWorkersSettledRunsAfterRetentionRefusals(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"rejection-extra-audit", "completed-marker"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			if mode == "rejection-extra-audit" {
				fake.generation.generationOutcome = "malformed"
			}
			args = append(args, "--local-model-workers")
			clock := &daemonFakeHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
			statePath := daemonTestFlagValue(t, args, "--state-dir")
			d, api, server := startContextRefusalDaemon(t, args, getenv, clock)
			scope := runLocalFullReviewOnSupervisors(t, d, api, "run-"+mode, repository, base, head, policy, inventory, clock.Now())
			if receipt, err := api.GetRun(context.Background(), scope); err != nil || receipt.Status() == controlplane.ReviewRunActive {
				t.Fatalf("run not settled: %v", err)
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			clock.mu.Lock()
			clock.at = clock.at.Add(25 * time.Hour)
			clock.mu.Unlock()
			switch mode {
			case "rejection-extra-audit":
				ledger, err := audit.NewFileLedger(filepath.Join(statePath, "audit"))
				if err != nil {
					t.Fatal(err)
				}
				last, _, err := ledger.Head(context.Background(), scope)
				if err != nil {
					t.Fatal(err)
				}
				event, err := audit.NewEvent(scope, last.Sequence()+1, last.Identity(), audit.EventRouteAttemptClaimed, strings.Repeat("a", 64), nil, clock.Now())
				if err != nil {
					t.Fatal(err)
				}
				if err := ledger.Append(context.Background(), last.Identity(), event); err != nil {
					t.Fatal(err)
				}
				if err := ledger.Close(); err != nil {
					t.Fatal(err)
				}
			case "completed-marker":
				if err := os.WriteFile(filepath.Join(statePath, scope.Identity()+".scope-intent.json"), []byte("unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			journalBefore := ownerStartupJournalBytes(t, statePath)
			restarted, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, daemonDependencies{clock: clock, generationSanitizer: daemonTestGenerationSanitizer(), verificationSanitizer: daemonTestVerificationSanitizer()})
			if err == nil {
				restarted.Close()
				t.Fatal("unproven settled tail admitted after retention")
			}
			if !reflect.DeepEqual(journalBefore, ownerStartupJournalBytes(t, statePath)) {
				t.Fatal("refusal changed the journal")
			}
		})
	}
}

// A run that ended before its final result was recorded, and is first
// projected after retention lapses, must not stop the supervisor: it gets the
// result its journal proves, marked evidence-expired, never a completed pass.
func TestDaemonLocalModelWorkersProjectAfterRetentionKeepsServing(t *testing.T) {
	args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
	args = append(args, "--local-model-workers")
	clock := &daemonFakeHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
	statePath := daemonTestFlagValue(t, args, "--state-dir")
	d, api, server := startContextRefusalDaemon(t, args, getenv, clock)
	scope := runLocalFullReviewOnSupervisors(t, d, api, "run-projected-late", repository, base, head, policy, inventory, clock.Now())
	receipt, err := api.GetRun(context.Background(), scope)
	if err != nil || receipt.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("fixture run status=%v err=%v", receipt.Status(), err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash between finalization and projection.
	entries, err := os.ReadDir(filepath.Join(statePath, "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".diagnostic-set.json") {
			if err := os.Remove(filepath.Join(statePath, "diagnostics", entry.Name())); err != nil {
				t.Fatal(err)
			}
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("removed %d final results", removed)
	}
	clock.mu.Lock()
	clock.at = clock.at.Add(25 * time.Hour)
	clock.mu.Unlock()
	d, api, _ = startContextRefusalDaemon(t, args, getenv, clock)
	for _, index := range []int{1, 2} {
		if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(context.Background()); err != nil {
			t.Fatalf("supervisor %d stopped projecting expired evidence: %v", index, err)
		}
	}
	final, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil || final.Outcome() != diagnostics.FinalOutcomeInconclusive || !final.EvidenceExpired() || final.VerifiedSetIdentity() != "" || final.AnalysisResultIdentity() != "" {
		t.Fatalf("late result outcome=%s expired=%v err=%v", final.Outcome(), final.EvidenceExpired(), err)
	}
	later := runLocalFullReviewOnSupervisors(t, d, api, "run-after-late-projection", repository, base, head, policy, inventory, clock.Now())
	if result, err := api.GetDiagnosticSet(context.Background(), later); err != nil || result.Outcome() != diagnostics.FinalOutcomeCompleted || result.EvidenceExpired() {
		t.Fatalf("later run result=%s err=%v", result.Outcome(), err)
	}
	if calls, _, _, _ := fake.generation.snapshot(); calls != 2 {
		t.Fatalf("generation calls=%d", calls)
	}
}
