//go:build unix

package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

// A verification request the provider rate-limited and the handler retried on
// the same route stops with its final attempt in flight: the daemon's state is
// copied while the provider holds that request, as a crash would leave it. On
// restart after the lease expires the run fails as inconclusive without
// another request, and the daemon then boots cleanly while its artifacts are
// retained and after retention lapses, without appending to the journal or
// the audit.
func TestDaemonLocalModelWorkersVerificationLeaseExpiryRestarts(t *testing.T) {
	t.Parallel()
	for _, rateLimits := range []int{0, 2} {
		t.Run(fmt.Sprintf("rate-limits-%d", rateLimits), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			args, getenv, fake, repository, base, head, policy, inventory := localModelWorkerFixture(t)
			args = append(args, "--local-model-workers")
			statePath := daemonTestFlagValue(t, args, "--state-dir")
			crashed := filepath.Join(t.TempDir(), "state")
			var snapshot struct {
				sync.Mutex
				taken bool
				err   error
			}
			fake.verification.rateLimits = rateLimits
			fake.verification.onDispatch = func(call int) {
				if call != rateLimits+1 {
					return
				}
				snapshot.Lock()
				defer snapshot.Unlock()
				snapshot.taken, snapshot.err = true, copyDaemonState(statePath, crashed)
			}
			clock := &daemonBudgetedHandlerClock{at: time.Now().UTC().Truncate(time.Millisecond)}
			d, api, server := startContextRefusalDaemon(t, args, getenv, clock)
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", fmt.Sprintf("run-verification-expiry-%d", rateLimits))
			if err != nil {
				t.Fatal(err)
			}
			intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.SubmitLocalFullReview(ctx, intent); err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{1, 2, 1} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(ctx); err != nil {
					t.Fatalf("supervisor %d: %v", index, err)
				}
			}
			snapshot.Lock()
			taken, copyErr := snapshot.taken, snapshot.err
			snapshot.Unlock()
			if !taken || copyErr != nil {
				t.Fatalf("no state copied at the final verification request: taken=%t err=%v", taken, copyErr)
			}
			generationCalls, _, _, _ := fake.generation.snapshot()
			verificationCalls, _, _, _ := fake.verification.snapshot()
			if generationCalls != 1 || verificationCalls != rateLimits+1 {
				t.Fatalf("calls generation=%d verification=%d", generationCalls, verificationCalls)
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			if err := restoreDaemonState(crashed, statePath); err != nil {
				t.Fatal(err)
			}
			auditPath := filepath.Join(statePath, "audit", scope.Identity()+".audit.jsonl")
			assertVerificationExpiryAudit(t, auditPath, rateLimits)

			// The lease the copied journal holds expires; the restarted
			// daemon fails the run without dispatching again.
			d, api, server = startContextRefusalDaemon(t, args, getenv, clock)
			events, err := d.journal.Read(ctx, scope, 1, 100)
			if err != nil {
				t.Fatal(err)
			}
			var leaseExpires time.Time
			for _, event := range events {
				if event.TaskKey() == "verification" && event.Kind() == controlplane.RunEventTaskLeased {
					leaseExpires = event.LeaseExpiresAt()
				}
				if event.TaskKey() == "verification" && event.Kind() == controlplane.RunEventTaskSucceeded {
					t.Fatal("verification success survived the crash copy")
				}
			}
			if leaseExpires.IsZero() {
				t.Fatal("verification lease absent from the crash copy")
			}
			clock.mu.Lock()
			clock.at = leaseExpires.Add(5 * time.Second)
			clock.mu.Unlock()
			for _, index := range []int{1, 2, 1} {
				if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(ctx); err != nil {
					t.Fatalf("expiry supervisor %d: %v", index, err)
				}
			}
			receipt, err := api.GetRun(ctx, scope)
			if err != nil || receipt.Status() != controlplane.ReviewRunFailed {
				t.Fatalf("run not failed after the lease expired: %v", err)
			}
			if task, _ := receipt.Task("verification"); task.Status() != controlplane.TaskRuntimeFailed || task.Failure() != controlplane.RunFailureResourceLimit {
				t.Fatalf("verification after expiry: %s %s", task.Status(), task.Failure())
			}
			final, err := api.GetDiagnosticSet(ctx, scope)
			if err != nil || final.Outcome() != diagnostics.FinalOutcomeInconclusive {
				t.Fatalf("final result after expiry: %v", err)
			}
			assertVerificationExpiryAudit(t, auditPath, rateLimits)
			// The packet the restarts below are proved against is still retained.
			facts, err := d.journal.(*controlplane.FileRunJournal).InspectHistoricalContextPackets(ctx)
			if err != nil || len(facts) != 1 {
				t.Fatalf("historical facts: %v", err)
			}
			expires := time.UnixMilli(facts[0].PreparedEvent().PacketDescriptor().ExpiresAtMilliseconds)
			if !clock.Now().Add(time.Minute).Before(expires) {
				t.Fatalf("packet expires %s after the lease; the retained restart needs a minute", expires.Sub(clock.Now()))
			}
			server.Close()
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			auditBefore, err := os.ReadFile(auditPath)
			if err != nil {
				t.Fatal(err)
			}

			// While the artifacts are retained startup proves the tail from
			// their bytes; after retention lapses, from the journal and audit.
			for _, advance := range []time.Duration{time.Minute, 25 * time.Hour} {
				clock.mu.Lock()
				clock.at = clock.at.Add(advance)
				clock.mu.Unlock()
				journalBefore := ownerStartupJournalBytes(t, statePath)
				t.Logf("restarting %s later", advance)
				d, api, server = startContextRefusalDaemon(t, args, getenv, clock)
				for _, index := range []int{1, 2} {
					if _, err := d.supervisors[index].(*worker.RepositorySupervisor).RunOnce(ctx); err != nil {
						t.Fatalf("restart supervisor %d after %s: %v", index, advance, err)
					}
				}
				if !reflect.DeepEqual(journalBefore, ownerStartupJournalBytes(t, statePath)) {
					t.Fatalf("restart after %s appended to the failed run", advance)
				}
				if auditAfter, err := os.ReadFile(auditPath); err != nil || !bytes.Equal(auditBefore, auditAfter) {
					t.Fatalf("restart after %s changed the audit: %v", advance, err)
				}
				after, err := api.GetRun(ctx, scope)
				if err != nil || after.HeadIdentity() != receipt.HeadIdentity() || after.Status() != receipt.Status() {
					t.Fatalf("restart after %s changed the run: %v", advance, err)
				}
				reopened, err := api.GetDiagnosticSet(ctx, scope)
				if err != nil || reopened.Identity() != final.Identity() {
					t.Fatalf("restart after %s changed the result: %v", advance, err)
				}
				if calls, _, _, _ := fake.generation.snapshot(); calls != generationCalls {
					t.Fatalf("restart after %s redispatched generation: %d", advance, calls)
				}
				if calls, _, _, _ := fake.verification.snapshot(); calls != verificationCalls {
					t.Fatalf("restart after %s redispatched verification: %d", advance, calls)
				}
				server.Close()
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// assertVerificationExpiryAudit requires the generation request's selection
// and settled attempt, then the verification selection, rateLimits refused and
// settled attempts, and the final claim the crash left in flight.
func assertVerificationExpiryAudit(t *testing.T, path string, rateLimits int) {
	t.Helper()
	want := []audit.EventKind{audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled, audit.EventRouteSelected}
	for range rateLimits {
		want = append(want, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled)
	}
	want = append(want, audit.EventRouteAttemptClaimed)
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(encoded), []byte("\n"))
	if len(lines) != len(want) {
		t.Fatalf("audit events=%d, want %d", len(lines), len(want))
	}
	for i, line := range lines {
		event, err := audit.ParseEvent(line)
		if err != nil || event.Kind() != want[i] {
			t.Fatalf("audit event %d: %v, want %s", i, err, want[i])
		}
	}
}

// restoreDaemonState puts a stopped daemon's state back as copyDaemonState
// took it. The owner record binds the state directories' identities, so it
// keeps every directory and rewrites each file in place, and removes the
// files and directories the copy does not have.
func restoreDaemonState(snapshot, live string) error {
	var extra []string
	err := filepath.WalkDir(live, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(live, path)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(filepath.Join(snapshot, relative)); os.IsNotExist(err) {
			extra = append(extra, path)
			if entry.IsDir() {
				return filepath.SkipDir
			}
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, path := range extra {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return copyDaemonState(snapshot, live)
}

// copyDaemonState copies a stopped or quiescent daemon state directory with
// its modes, as the files stood at one instant. Existing files are rewritten
// in place.
func copyDaemonState(source, target string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case entry.IsDir():
			if err := os.MkdirAll(destination, 0700); err != nil {
				return err
			}
			return os.Chmod(destination, info.Mode().Perm())
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.WriteFile(destination, data, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(destination, info.Mode().Perm())
		default:
			return fmt.Errorf("unexpected state entry %s (%s)", relative, info.Mode().Type())
		}
	})
}
