//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

type packagedVerifierBarrier struct {
	server  *httptest.Server
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newPackagedVerifierBarrier(t *testing.T, endpoint *daemonFakeModelEndpoint) *packagedVerifierBarrier {
	t.Helper()
	barrier := &packagedVerifierBarrier{entered: make(chan struct{}, 1), release: make(chan struct{})}
	barrier.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := httptest.NewRecorder()
		endpoint.serve(t, response, r)
		if barrier.armed.CompareAndSwap(true, false) {
			barrier.entered <- struct{}{}
			select {
			case <-barrier.release:
			case <-r.Context().Done():
				return
			}
		}
		for key, values := range response.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	}))
	t.Cleanup(func() { close(barrier.release); barrier.server.Close() })
	return barrier
}

type packagedModelWorkerRun struct {
	api                      *client.Client
	model                    *daemonFakeModelFixture
	barrier                  *packagedVerifierBarrier
	scope                    audit.ReviewScope
	cli, daemon              string
	cliArgs, daemonArgs, env []string
	process                  *exec.Cmd
	logFile                  *os.File
	log                      func() string
	state                    string
	recoveryArgs             []string
	candidateBarrierPath     string
}

func testPackagedModelWorkerLifecycle(t *testing.T, run packagedModelWorkerRun) {
	t.Helper()
	ctx := context.Background()
	command := func(args []string) []byte {
		t.Helper()
		cmd := exec.Command(run.cli, args...)
		cmd.Env = run.env
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("packaged CLI: %v %s daemon=%s", err, output, run.log())
		}
		return bytes.TrimSpace(output)
	}
	submit := func(args []string, scope audit.ReviewScope) controlplane.ReviewRunReceipt {
		t.Helper()
		receipt, err := controlplane.ParseReviewRunReceipt(command(args))
		if err != nil || receipt.Scope().Identity() != scope.Identity() {
			t.Fatalf("packaged admission scope: %v", err)
		}
		return receipt
	}
	awaitSet := func(scope audit.ReviewScope, timeout time.Duration) diagnostics.Set {
		t.Helper()
		deadline := time.NewTimer(timeout)
		defer deadline.Stop()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			set, err := run.api.GetDiagnosticSet(ctx, scope)
			if err == nil {
				return set
			}
			select {
			case <-deadline.C:
				receipt, receiptErr := run.api.GetRun(ctx, scope)
				t.Fatalf("terminal diagnostics unavailable scope=%s: %v receipt=%+v receipt_error=%v daemon=%s", scope.ReviewRunID(), err, receipt, receiptErr, run.log())
			case <-ticker.C:
			}
		}
	}
	assertCalls := func(generation, verification int) {
		t.Helper()
		for _, item := range []struct {
			endpoint *daemonFakeModelEndpoint
			count    int
		}{{run.model.generation, generation}, {run.model.verification, verification}} {
			calls, _, captures, failures := item.endpoint.snapshot()
			if calls != item.count || len(captures) != calls || len(failures) != 0 {
				t.Fatalf("%s calls=%d captures=%d failures=%v", item.endpoint.name, calls, len(captures), failures)
			}
		}
	}
	admitted := submit(run.cliArgs, run.scope)
	t.Log("await initial completed review")
	final := awaitSet(run.scope, 30*time.Second)
	if final.SchemaVersion() != 7 || final.Outcome() != diagnostics.FinalOutcomeCompleted || final.VerifiedSetIdentity() == "" || final.VerifiedCount() != 1 || len(final.Findings()) != 1 || len(final.DeterministicChecks()) != 1 || len(final.DeterministicObservations()) != 1 || final.SnapshotIdentity() == "" || final.ReviewSnapshotIdentity() == "" || final.SnapshotIdentity() == final.ReviewSnapshotIdentity() {
		t.Fatalf("invalid completed V7 outcome=%s verified=%d findings=%d observations=%d", final.Outcome(), final.VerifiedCount(), len(final.Findings()), len(final.DeterministicObservations()))
	}
	assertCalls(1, 1)
	packagedAssertRouteAudit(t, run.state, run.scope, 2)
	if replay := submit(run.cliArgs, run.scope); replay.PlanIdentity() != admitted.PlanIdentity() {
		t.Fatal("replay changed plan")
	}
	packagedAssertResultParity(t, command, run.cliArgs, run.scope, final)
	packagedAssertProgressParity(t, command, run.cliArgs, run.scope, run.api, &final)
	packagedAssertEmbeddedAssets(t, run.cliArgs)

	interrupted, err := audit.NewReviewScope(run.scope.TenantID(), run.scope.RepositoryID(), "run-packaged-interrupted")
	if err != nil {
		t.Fatal(err)
	}
	interruptedArgs := append([]string(nil), run.cliArgs...)
	for i := range interruptedArgs {
		if interruptedArgs[i] == "--run" {
			interruptedArgs[i+1] = interrupted.ReviewRunID()
		}
	}
	run.barrier.armed.Store(true)
	interruptedAdmission := submit(interruptedArgs, interrupted)
	select {
	case <-run.barrier.entered:
	case <-time.After(30 * time.Second):
		t.Fatalf("owned verifier barrier not reached: %s", run.log())
	}
	receipt, err := run.api.GetRun(ctx, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := receipt.Task("candidates")
	verification, _ := receipt.Task("verification")
	if candidate.Status() != controlplane.TaskRuntimeSucceeded || candidate.OutputIdentity() == "" || verification.Status() != controlplane.TaskRuntimeLeased {
		t.Fatalf("barrier candidate=%s verifier=%s", candidate.Status(), verification.Status())
	}
	activeProgress := packagedAssertProgressParity(t, command, interruptedArgs, interrupted, run.api, nil)
	if activeProgress.Progress.Verification.State != "not_run" || activeProgress.Progress.Verification.Verified != nil || activeProgress.Progress.Verification.Candidates != nil {
		t.Fatalf("unsettled verifier exposed counts: %+v", activeProgress.Progress.Verification)
	}
	if _, err := run.api.GetDiagnosticSet(ctx, interrupted); err == nil {
		t.Fatal("active run published provisional diagnostics")
	}
	candidateID := candidate.OutputIdentity()
	candidateBytes := packagedReadArtifact(t, run.state, interrupted, candidateID)
	assertCalls(2, 2)
	// The verifier request is already claimed. This kills an owned process, not a
	// storage failure or a crash at the candidate Put instruction boundary.
	if err := run.process.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := run.process.Wait(); err == nil {
		t.Fatal("interrupted daemon exited successfully")
	}
	// The observation is independent of startup: a match cannot authorize restart.
	offline := func(action string, extra ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.Command(run.daemon, append(append([]string{action}, run.recoveryArgs...), extra...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
		return cmd.CombinedOutput()
	}
	point, err := offline("recovery-point")
	if err != nil {
		t.Fatalf("stopped comparison record: %s %v", point, err)
	}
	pointPath := filepath.Join(t.TempDir(), "recovery-point.json")
	if err := os.WriteFile(pointPath, point, 0o600); err != nil {
		t.Fatal(err)
	}
	matched, err := offline("verify-restore", "--record", pointPath)
	if err != nil || string(matched) != "{\"status\":\"matched_pending\",\"restart_authorized\":false}\n" {
		t.Fatalf("pending comparison: %s %v", matched, err)
	}
	ownerPath := filepath.Join(run.state, ".local-source-owner.json")
	ownerBytes, err := os.ReadFile(ownerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownerPath, []byte("corrupt owner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := offline("verify-restore", "--record", pointPath); err == nil {
		t.Fatalf("corrupt owner accepted: %s", output)
	}
	if err := os.WriteFile(ownerPath, ownerBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := offline("verify-restore", "--record", pointPath); err != nil {
		t.Fatalf("restored owner bytes: %s %v", output, err)
	}
	journalBytes, err := os.ReadFile(filepath.Join(run.state, interrupted.Identity()+".run.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var expires time.Time
	for _, line := range bytes.Split(bytes.TrimSpace(journalBytes), []byte("\n")) {
		event, err := controlplane.ParseRunEvent(line)
		if err != nil {
			t.Fatal(err)
		}
		if event.TaskKey() == "verification" && (event.Kind() == controlplane.RunEventTaskLeased || event.Kind() == controlplane.RunEventTaskLeaseRenewed) {
			expires = event.LeaseExpiresAt()
		}
	}
	if expires.IsZero() || time.Until(expires) > 2*time.Minute {
		t.Fatalf("unexpected verifier lease expiry %s", expires)
	}
	restarted := exec.Command(run.daemon, run.daemonArgs...)
	restarted.Env = run.env
	restarted.Stdout, restarted.Stderr = run.logFile, run.logFile
	if err := restarted.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if restarted.ProcessState == nil {
			restarted.Process.Kill()
			restarted.Wait()
		}
	})
	packagedAwaitReady(t, run.cliArgs, run.log)
	if replay := submit(interruptedArgs, interrupted); replay.PlanIdentity() != interruptedAdmission.PlanIdentity() {
		t.Fatal("restart replay changed plan")
	}
	t.Log("await interrupted review after restart")
	uncertain := awaitSet(interrupted, time.Until(expires)+20*time.Second)
	if uncertain.SchemaVersion() != 7 || uncertain.Outcome() != diagnostics.FinalOutcomeInconclusive || uncertain.VerifiedSetIdentity() != "" || len(uncertain.Findings()) != 0 || uncertain.AnalysisResultIdentity() == "" {
		t.Fatalf("uncertain verification promoted outcome=%s verified=%s", uncertain.Outcome(), uncertain.VerifiedSetIdentity())
	}
	receipt, err = run.api.GetRun(ctx, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ = receipt.Task("candidates")
	verification, _ = receipt.Task("verification")
	if candidate.Status() != controlplane.TaskRuntimeSucceeded || candidate.OutputIdentity() != candidateID || verification.Status() != controlplane.TaskRuntimeFailed || verification.Failure() != controlplane.RunFailureResourceLimit {
		t.Fatalf("restart candidate=%s verifier=%s failure=%s", candidate.Status(), verification.Status(), verification.Failure())
	}
	if !bytes.Equal(candidateBytes, packagedReadArtifact(t, run.state, interrupted, candidateID)) {
		t.Fatal("candidate bytes changed after restart")
	}
	interruptedTerminalJournal, err := os.ReadFile(filepath.Join(run.state, interrupted.Identity()+".run.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	interruptedAuditPath := filepath.Join(run.state, "audit", interrupted.Identity()+".audit.jsonl")
	interruptedTerminalAudit, err := os.ReadFile(interruptedAuditPath)
	if err != nil {
		t.Fatal(err)
	}
	packagedAssertResultParity(t, command, interruptedArgs, interrupted, uncertain)
	interruptedProgress := packagedAssertProgressParity(t, command, interruptedArgs, interrupted, run.api, &uncertain)
	cleanAgain, err := run.api.GetDiagnosticSet(ctx, run.scope)
	if err != nil || cleanAgain.Identity() != final.Identity() {
		t.Fatalf("completed diagnostic changed after restart: %v", err)
	}
	packagedAssertResultParity(t, command, run.cliArgs, run.scope, cleanAgain)
	completedProgress := packagedAssertProgressParity(t, command, run.cliArgs, run.scope, run.api, &cleanAgain)
	assertCalls(2, 2)
	packagedAssertRouteAudit(t, run.state, run.scope, 2)
	packagedAssertRouteAudit(t, run.state, interrupted, 1)
	later, err := audit.NewReviewScope(run.scope.TenantID(), run.scope.RepositoryID(), "run-packaged-later")
	if err != nil {
		t.Fatal(err)
	}
	laterArgs := append([]string(nil), run.cliArgs...)
	for i := range laterArgs {
		if laterArgs[i] == "--run" {
			laterArgs[i+1] = later.ReviewRunID()
		}
	}
	laterAdmission := submit(laterArgs, later)
	t.Log("await unrelated later review")
	laterSet := awaitSet(later, 30*time.Second)
	if laterSet.Outcome() != diagnostics.FinalOutcomeCompleted || laterSet.VerifiedCount() != 1 {
		t.Fatalf("unrelated later review failed: %s", laterSet.Outcome())
	}
	packagedAssertResultParity(t, command, laterArgs, later, laterSet)
	laterProgress := packagedAssertProgressParity(t, command, laterArgs, later, run.api, &laterSet)
	assertCalls(3, 3)
	if err := restarted.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Wait(); err != nil {
		t.Fatalf("graceful packaged stop: %v daemon=%s", err, run.log())
	}
	second := exec.Command(run.daemon, run.daemonArgs...)
	second.Env = run.env
	second.Stdout, second.Stderr = run.logFile, run.logFile
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if second.ProcessState == nil {
			second.Process.Kill()
			second.Wait()
		}
	})
	packagedAwaitReady(t, run.cliArgs, run.log)
	for _, item := range []struct {
		args      []string
		scope     audit.ReviewScope
		admission controlplane.ReviewRunReceipt
		set       diagnostics.Set
		progress  client.RunProgress
	}{
		{run.cliArgs, run.scope, admitted, final, completedProgress}, {interruptedArgs, interrupted, interruptedAdmission, uncertain, interruptedProgress}, {laterArgs, later, laterAdmission, laterSet, laterProgress},
	} {
		if replay := submit(item.args, item.scope); replay.PlanIdentity() != item.admission.PlanIdentity() {
			t.Fatal("second restart replay changed plan")
		}
		current, err := run.api.GetDiagnosticSet(ctx, item.scope)
		if err != nil || current.Identity() != item.set.Identity() {
			t.Fatalf("second restart diagnostics changed: %v", err)
		}
		packagedAssertResultParity(t, command, item.args, item.scope, current)
		progress := packagedAssertProgressParity(t, command, item.args, item.scope, run.api, &current)
		if progress.Run.Identity() != item.progress.Run.Identity() || !reflect.DeepEqual(progress.Progress, item.progress.Progress) {
			t.Fatal("second restart changed terminal progress")
		}
	}
	if !bytes.Equal(candidateBytes, packagedReadArtifact(t, run.state, interrupted, candidateID)) {
		t.Fatal("second restart changed candidate bytes")
	}
	currentReceipt, err := run.api.GetRun(ctx, interrupted)
	if err != nil {
		t.Fatal(err)
	}
	candidateAfter, _ := currentReceipt.Task("candidates")
	verificationAfter, _ := currentReceipt.Task("verification")
	if candidateAfter.OutputIdentity() != candidateID || candidateAfter.Status() != controlplane.TaskRuntimeSucceeded || verificationAfter.Status() != controlplane.TaskRuntimeFailed || verificationAfter.OutputIdentity() != "" || verificationAfter.Failure() != controlplane.RunFailureResourceLimit {
		t.Fatal("second restart changed terminal task result")
	}
	currentJournal, err := os.ReadFile(filepath.Join(run.state, interrupted.Identity()+".run.jsonl"))
	if err != nil || !bytes.Equal(currentJournal, interruptedTerminalJournal) {
		t.Fatalf("second restart changed terminal journal: %v", err)
	}
	currentAudit, err := os.ReadFile(interruptedAuditPath)
	if err != nil || !bytes.Equal(currentAudit, interruptedTerminalAudit) {
		t.Fatalf("second restart changed terminal verifier audit: %v", err)
	}
	packagedAssertRouteAudit(t, run.state, interrupted, 1)
	assertCalls(3, 3)
	if err := second.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := second.Wait(); err != nil {
		t.Fatalf("second graceful stop: %v daemon=%s", err, run.log())
	}
	t.Log("verifier second restart exact audit and terminal progress retained; begin candidate interruption")
	if run.candidateBarrierPath != "" {
		blocked := exec.Command(run.daemon, run.daemonArgs...)
		blocked.Env = run.env
		blocked.Stdout, blocked.Stderr = run.logFile, run.logFile
		if err := blocked.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if blocked.ProcessState == nil {
				blocked.Process.Kill()
				blocked.Wait()
			}
		})
		packagedAwaitReady(t, run.cliArgs, run.log)
		putScope, err := audit.NewReviewScope(run.scope.TenantID(), run.scope.RepositoryID(), "run-packaged-put-interrupted")
		if err != nil {
			t.Fatal(err)
		}
		putArgs := append([]string(nil), run.cliArgs...)
		for i := range putArgs {
			if putArgs[i] == "--run" {
				putArgs[i+1] = putScope.ReviewRunID()
			}
		}
		submit(putArgs, putScope)
		deadline := time.NewTimer(30 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		var persisted []byte
	waiting:
		for {
			persisted, err = os.ReadFile(run.candidateBarrierPath)
			if err == nil {
				break waiting
			}
			select {
			case <-deadline.C:
				t.Fatalf("candidate persistence barrier missing: %s", run.log())
			case <-tick.C:
			}
		}
		candidateBeforeKill := packagedReadArtifact(t, run.state, putScope, string(persisted))

		journalPath := filepath.Join(run.state, putScope.Identity()+".run.jsonl")
		journalAtBarrier, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		leased := false
		for _, line := range bytes.Split(bytes.TrimSpace(journalAtBarrier), []byte("\n")) {
			event, err := controlplane.ParseRunEvent(line)
			if err != nil {
				t.Fatal(err)
			}
			if event.TaskKey() == "candidates" {
				if event.Kind() == controlplane.RunEventTaskLeased {
					leased = true
				}
				if event.Kind() == controlplane.RunEventTaskSucceeded || event.Kind() == controlplane.RunEventTaskFailed {
					t.Fatal("candidate fixture missed unsettled persistence boundary")
				}
			}
		}
		if !leased {
			t.Fatal("candidate persistence has no journal lease")
		}

		if err := blocked.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if err := blocked.Wait(); err == nil {
			t.Fatal("candidate interruption unexpectedly clean")
		}
		// Persisted bytes alone do not authorize task success or another dispatch.

		resumed := exec.Command(run.daemon, run.daemonArgs...)
		resumed.Env = run.env
		resumed.Stdout, resumed.Stderr = run.logFile, run.logFile
		if err := resumed.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if resumed.ProcessState == nil {
				resumed.Process.Kill()
				resumed.Wait()
			}
		})
		packagedAwaitReady(t, run.cliArgs, run.log)
		retained := awaitSet(putScope, time.Minute)
		if retained.Outcome() != diagnostics.FinalOutcomeInconclusive || retained.VerifiedSetIdentity() != "" || len(retained.Findings()) != 0 {
			t.Fatal("unsettled candidate was promoted")
		}
		expiredReceipt, err := run.api.GetRun(ctx, putScope)
		if err != nil {
			t.Fatal(err)
		}
		expiredCandidate, _ := expiredReceipt.Task("candidates")
		unrunVerifier, _ := expiredReceipt.Task("verification")
		if expiredCandidate.Status() != controlplane.TaskRuntimeFailed || expiredCandidate.Failure() != controlplane.RunFailureResourceLimit || expiredCandidate.Attempts() != 1 || expiredCandidate.OutputIdentity() != "" || unrunVerifier.Attempts() != 0 || unrunVerifier.OutputIdentity() != "" {
			t.Fatal("unsettled candidate retried or gained output authority")
		}
		packagedAssertResultParity(t, command, putArgs, putScope, retained)
		retainedProgress := packagedAssertProgressParity(t, command, putArgs, putScope, run.api, &retained)
		if err := resumed.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := resumed.Wait(); err != nil {
			t.Fatalf("persist-interrupted first graceful stop: %v daemon=%s", err, run.log())
		}

		terminalJournal, err := os.ReadFile(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		auditPath := filepath.Join(run.state, "audit", putScope.Identity()+".audit.jsonl")
		terminalAudit, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("candidate first restart inconclusive; begin second restart")
		candidateSecond := exec.Command(run.daemon, run.daemonArgs...)
		candidateSecond.Env = run.env
		candidateSecond.Stdout, candidateSecond.Stderr = run.logFile, run.logFile
		if err := candidateSecond.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if candidateSecond.ProcessState == nil {
				candidateSecond.Process.Kill()
				candidateSecond.Wait()
			}
		})
		packagedAwaitReady(t, run.cliArgs, run.log)
		if replay := submit(putArgs, putScope); replay.PlanIdentity() != expiredReceipt.PlanIdentity() {
			t.Fatal("persist-interrupted replay changed plan")
		}
		currentSet, err := run.api.GetDiagnosticSet(ctx, putScope)
		if err != nil || currentSet.Identity() != retained.Identity() {
			t.Fatalf("persist-interrupted second restart changed diagnostics: %v", err)
		}
		currentReceipt, err := run.api.GetRun(ctx, putScope)
		if err != nil || currentReceipt.Identity() != expiredReceipt.Identity() {
			t.Fatalf("persist-interrupted second restart changed receipt: %v", err)
		}
		for path, expected := range map[string][]byte{journalPath: terminalJournal, auditPath: terminalAudit} {
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(current, expected) {
				t.Fatalf("persist-interrupted second restart changed %s: %v", filepath.Base(path), err)
			}
		}
		packagedAssertResultParity(t, command, putArgs, putScope, currentSet)
		currentProgress := packagedAssertProgressParity(t, command, putArgs, putScope, run.api, &currentSet)
		if currentProgress.Run.Identity() != retainedProgress.Run.Identity() || !reflect.DeepEqual(currentProgress.Progress, retainedProgress.Progress) {
			t.Fatal("persist-interrupted second restart changed terminal progress")
		}
		if err := candidateSecond.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		if err := candidateSecond.Wait(); err != nil {
			t.Fatalf("persist-interrupted second graceful stop: %v daemon=%s", err, run.log())
		}
		if !bytes.Equal(candidateBeforeKill, packagedReadArtifact(t, run.state, putScope, string(persisted))) {
			t.Fatal("restart changed persisted candidate bytes")
		}
		assertCalls(4, 3)
		t.Log("exact candidate Put interruption retained; one expired attempt, no verifier dispatch or unverified promotion")
	}
	t.Logf("packaged model workers: completed=%s interrupted=%s candidate=%s verifier_already_claimed=true terminal_restart_dedupe=true physical_crash_acceptance=false", final.Identity(), uncertain.Identity(), candidateID)
}

func packagedAssertProgressParity(t *testing.T, command func([]string) []byte, args []string, scope audit.ReviewScope, api *client.Client, final *diagnostics.Set) client.RunProgress {
	t.Helper()
	progress, err := api.GetRunProgress(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	statusArgs := []string{"runs", "status", "--server", packagedServer(args), "--tenant", scope.TenantID(), "--repository", scope.RepositoryID(), "--run", scope.ReviewRunID(), "--format", "progress"}
	var cli struct {
		Run      json.RawMessage         `json:"run"`
		Progress client.ProgressCoverage `json:"progress"`
	}
	if err := json.Unmarshal(command(statusArgs), &cli); err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.ParseReviewRunReceipt(cli.Run)
	if err != nil || receipt.Identity() != progress.Run.Identity() || !reflect.DeepEqual(cli.Progress, progress.Progress) {
		t.Fatalf("packaged progress differs from bound API receipt: %v", err)
	}
	coverage := progress.Progress
	if coverage.Change.State != "available" || coverage.Deterministic.State != "available" || coverage.Context.State != "available" || coverage.Context.ArtifactIdentity == "" {
		t.Fatalf("packaged progress lost source accounting: %+v", coverage)
	}
	contextTask, found := progress.Run.Task("context")
	if !found || contextTask.OutputIdentity() == coverage.Context.ArtifactIdentity {
		t.Fatal("context packet identity confused with authorized task input")
	}
	if coverage.Context.Analyzed == nil || coverage.Context.Selected == nil || coverage.Context.Omitted == nil || *coverage.Context.Analyzed != *coverage.Context.Selected+*coverage.Context.Omitted || *coverage.Context.Selected == 0 {
		t.Fatal("packaged progress lost context source coverage")
	}
	if final != nil {
		if final.VerifiedSetIdentity() != "" && (coverage.Context.Analyzed == nil || coverage.Context.Selected == nil || coverage.Context.Omitted == nil || *coverage.Context.Analyzed != int(final.SourceAnalyzedCount()) || *coverage.Context.Selected != int(final.SourceSelectedCount()) || *coverage.Context.Omitted != int(final.SourceOmittedCount())) {
			t.Fatalf("packaged progress differs from final source accounting scope=%s progress=%+v final analyzed=%d selected=%d omitted=%d", scope.ReviewRunID(), coverage.Context, final.SourceAnalyzedCount(), final.SourceSelectedCount(), final.SourceOmittedCount())
		}
		if final.VerifiedSetIdentity() != "" && (coverage.Verification.State != "available" || coverage.Verification.Candidates == nil || coverage.Verification.Verified == nil || coverage.Verification.Rejected == nil || coverage.Verification.Inconclusive == nil || *coverage.Verification.Candidates != int(final.CandidateCount()) || *coverage.Verification.Verified != int(final.VerifiedCount()) || *coverage.Verification.Rejected != int(final.RejectedCount()) || *coverage.Verification.Inconclusive != int(final.InconclusiveCount())) {
			t.Fatal("packaged progress differs from final verification accounting")
		}
		if final.VerifiedSetIdentity() == "" && (coverage.Verification.State == "available" || coverage.Verification.Candidates != nil || coverage.Verification.Verified != nil || coverage.Verification.Rejected != nil || coverage.Verification.Inconclusive != nil) {
			t.Fatal("packaged progress invented unavailable verification counts")
		}
	}
	return progress
}

func packagedReadArtifact(t *testing.T, state string, scope audit.ReviewScope, identity string) []byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(state, "artifacts", "*.artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		value, err := artifact.Parse(body)
		if err != nil {
			t.Fatal(err)
		}
		if value.Scope().Identity() == scope.Identity() && value.Identity() == identity {
			if value.Kind() != artifact.KindCandidateBatch {
				t.Fatalf("candidate output kind=%s", value.Kind())
			}
			return body
		}
	}
	t.Fatalf("missing persisted candidate %s", identity)
	return nil
}

func packagedServer(args []string) string {
	for i := range args {
		if args[i] == "--server" {
			return args[i+1]
		}
	}
	return ""
}

func packagedAwaitReady(t *testing.T, args []string, log func() string) {
	t.Helper()
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		response, err := (&http.Client{Timeout: 2 * time.Second}).Get(packagedServer(args) + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("restart not ready: %s", log())
		case <-ticker.C:
		}
	}
}

func packagedAssertEmbeddedAssets(t *testing.T, args []string) {
	t.Helper()
	get := func(path string) []byte {
		t.Helper()
		response, err := (&http.Client{Timeout: 2 * time.Second}).Get(packagedServer(args) + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("embedded %s status=%d err=%v", path, response.StatusCode, err)
		}
		return body
	}
	index := get("/console/")
	expected, err := os.ReadFile("../../web/dist/index.html")
	if err != nil || !bytes.Equal(index, expected) {
		t.Fatalf("embedded index differs: %v", err)
	}
	assets := regexp.MustCompile(`(?:src|href)="(/console/assets/[^" ]+\.(?:js|css))"`).FindAllSubmatch(index, -1)
	if len(assets) < 2 {
		t.Fatal("embedded console omitted JS/CSS assets")
	}
	for _, match := range assets {
		path := string(match[1])
		expected, err := os.ReadFile(filepath.Join("../../web/dist", strings.TrimPrefix(path, "/console/")))
		if err != nil || !bytes.Equal(get(path), expected) {
			t.Fatalf("embedded %s differs: %v", path, err)
		}
	}
}

func packagedAssertResultParity(t *testing.T, command func([]string) []byte, args []string, scope audit.ReviewScope, set diagnostics.Set) {
	t.Helper()
	statusArgs := []string{"runs", "status", "--server", packagedServer(args), "--tenant", scope.TenantID(), "--repository", scope.RepositoryID(), "--run", scope.ReviewRunID()}
	encoded, err := diagnostics.EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	if set.VerifiedSetIdentity() == "" {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &envelope); err != nil {
			t.Fatal(err)
		}
		if _, exists := envelope["verified"]; exists || set.VerificationContextIdentity() != "" || set.ReviewSnapshotIdentity() != "" {
			t.Fatal("incomplete final record invented verification lineage")
		}
	}
	if !bytes.Equal(command(append(statusArgs, "--format", "json")), encoded) {
		t.Fatal("packaged CLI JSON differs from canonical API set")
	}
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Properties map[string]any `json:"properties"`
			Results    []struct {
				Rule         string            `json:"ruleId"`
				Fingerprints map[string]string `json:"fingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(command(append(statusArgs, "--format", "sarif")), &sarif); err != nil || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
		t.Fatalf("invalid packaged SARIF: %v", err)
	}
	run := sarif.Runs[0]
	if run.Properties["trestleDiagnosticSetId"] != set.Identity() || run.Properties["trestleFinalOutcome"] != string(set.Outcome()) || run.Properties["trestleSourceSnapshotId"] != set.SnapshotIdentity() || run.Properties["trestleAnalysisResultId"] != set.AnalysisResultIdentity() || len(run.Results) != len(set.Findings())+len(set.DeterministicObservations()) {
		t.Fatal("packaged SARIF lineage/count parity failed")
	}
	observations := map[string]bool{}
	findings := map[string]bool{}
	for _, result := range run.Results {
		if id := result.Fingerprints["openTrestleObservationId/v1"]; id != "" {
			observations[id] = true
		}
		if id := result.Fingerprints["openTrestleVerifiedFindingId/v1"]; id != "" {
			findings[id] = true
		}
	}
	for _, observation := range set.DeterministicObservations() {
		if !observations[observation.Identity()] {
			t.Fatal("SARIF lost observation identity")
		}
	}
	for _, finding := range set.Findings() {
		if !findings[finding.Identity()] {
			t.Fatal("SARIF lost verified finding identity")
		}
	}
	if set.VerifiedSetIdentity() != "" {
		if run.Properties["trestleVerifiedSetId"] != set.VerifiedSetIdentity() || run.Properties["trestleReviewSnapshotId"] != set.ReviewSnapshotIdentity() {
			t.Fatal("SARIF lost verification lineage")
		}
	} else if _, present := run.Properties["trestleVerifiedSetId"]; present {
		t.Fatal("SARIF invented verification")
	}
}

type packagedStaging struct {
	root, scannerFlags, releaseSHA256, helperSHA256 string
}

func readPackagedStaging() (packagedStaging, error) {
	selected, ok := os.LookupEnv("OPEN_TRESTLE_PACKAGED_STAGING")
	if !ok {
		selected = "../../.container"
	}
	if selected == "" {
		return packagedStaging{}, fmt.Errorf("empty packaged staging selection")
	}
	absolute, err := filepath.Abs(selected)
	if err != nil {
		return packagedStaging{}, err
	}
	root, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return packagedStaging{}, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return packagedStaging{}, err
	}
	if !info.IsDir() {
		return packagedStaging{}, fmt.Errorf("packaged staging is not a directory: %s", root)
	}
	encoded, err := os.ReadFile(filepath.Join(root, "release/secret-scanner-release.json"))
	if err != nil {
		return packagedStaging{}, err
	}
	var manifest struct {
		SchemaVersion int    `json:"schema_version"`
		Scanner       string `json:"scanner"`
		Helper        struct {
			SHA256 string `json:"sha256"`
		} `json:"helper"`
		RootClient struct {
			Helper string `json:"helper_sha256"`
		} `json:"root_client"`
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		return packagedStaging{}, err
	}
	if manifest.SchemaVersion != 1 || manifest.Scanner != "betterleaks" || len(manifest.Helper.SHA256) != 64 || manifest.Helper.SHA256 != manifest.RootClient.Helper {
		return packagedStaging{}, fmt.Errorf("invalid staged scanner release manifest: %s", root)
	}
	body, err := os.ReadFile(filepath.Join(root, "libexec/open-trestle/open-trestle-scan-helper"))
	if err != nil {
		return packagedStaging{}, err
	}
	if digest := sha256.Sum256(body); hex.EncodeToString(digest[:]) != manifest.Helper.SHA256 {
		return packagedStaging{}, fmt.Errorf("staged open-trestle-scan-helper differs from release digest: %s", root)
	}
	releaseDigest := sha256.Sum256(encoded)
	return packagedStaging{
		root:          root,
		scannerFlags:  "-s -w -buildid= -X github.com/georgejieh/open-trestle/internal/secretscan.expectedHelperSHA256=" + manifest.Helper.SHA256,
		releaseSHA256: hex.EncodeToString(releaseDigest[:]),
		helperSHA256:  manifest.Helper.SHA256,
	}, nil
}

func copyPackagedFile(t *testing.T, source, target string, mode os.FileMode) {
	t.Helper()
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, body, mode); err != nil {
		t.Fatal(err)
	}
}

func (staging packagedStaging) copyRuntimeMembers(t *testing.T, destination string) {
	t.Helper()
	for _, name := range []string{"LICENSE", "NOTICE", "ca-certificates.crt", "release/secret-scanner-release.json", "release/secret-scanner.spdx.json", "release/vulnerability-scan.json", "libexec/open-trestle/open-trestle-scan-helper"} {
		mode := os.FileMode(0444)
		if strings.HasPrefix(name, "libexec/") {
			mode = 0555
		}
		copyPackagedFile(t, filepath.Join(staging.root, name), filepath.Join(destination, name), mode)
	}
	if err := filepath.WalkDir(filepath.Join(staging.root, "licenses"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("nonregular license: %s", path)
		}
		relative, err := filepath.Rel(staging.root, path)
		if err != nil {
			return err
		}
		copyPackagedFile(t, path, filepath.Join(destination, relative), 0444)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func packagedAssertRouteAudit(t *testing.T, state string, scope audit.ReviewScope, completed int) {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(state, "audit", scope.Identity()+".audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	counts := map[audit.EventKind]int{}
	previous := ""
	for index, line := range bytes.Split(bytes.TrimSpace(encoded), []byte("\n")) {
		event, err := audit.ParseEvent(line)
		if err != nil || event.Scope().Identity() != scope.Identity() || event.Sequence() != uint64(index+1) || event.PreviousIdentity() != previous {
			t.Fatalf("route audit chain index=%d: %v", index, err)
		}
		previous = event.Identity()
		counts[event.Kind()]++
	}
	if counts[audit.EventRouteAttemptClaimed] != 2 || counts[audit.EventRouteDispatchCompleted] != completed || counts[audit.EventPublicationClaimed] != 0 || counts[audit.EventPublicationCompleted] != 0 {
		t.Fatalf("unexpected route/publication audit counts=%v", counts)
	}
}
