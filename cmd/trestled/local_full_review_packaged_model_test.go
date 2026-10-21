//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func newPackagedVerifierBarrier(t *testing.T, endpoint *daemonBudgetedModelEndpoint) *packagedVerifierBarrier {
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
	model                    *daemonBudgetedModelFixture
	barrier                  *packagedVerifierBarrier
	scope                    audit.ReviewScope
	cli, daemon              string
	cliArgs, daemonArgs, env []string
	process                  *exec.Cmd
	logFile                  *os.File
	log                      func() string
	state                    string
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
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			set, err := run.api.GetDiagnosticSet(ctx, scope)
			if err == nil {
				return set
			}
			select {
			case <-deadline.C:
				t.Fatalf("terminal diagnostics unavailable: %v daemon=%s", err, run.log())
			case <-ticker.C:
			}
		}
	}
	assertCalls := func(generation, verification int) {
		t.Helper()
		for _, item := range []struct {
			endpoint *daemonBudgetedModelEndpoint
			count    int
		}{{run.model.generation, generation}, {run.model.verification, verification}} {
			calls, _, captures, failures := item.endpoint.snapshot()
			if calls != item.count || len(captures) != calls || len(failures) != 0 {
				t.Fatalf("%s calls=%d captures=%d failures=%v", item.endpoint.name, calls, len(captures), failures)
			}
		}
	}
	admitted := submit(run.cliArgs, run.scope)
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
	packagedAssertResultParity(t, command, interruptedArgs, interrupted, uncertain)
	packagedAssertProgressParity(t, command, interruptedArgs, interrupted, run.api, &uncertain)
	cleanAgain, err := run.api.GetDiagnosticSet(ctx, run.scope)
	if err != nil || cleanAgain.Identity() != final.Identity() {
		t.Fatalf("completed diagnostic changed after restart: %v", err)
	}
	packagedAssertResultParity(t, command, run.cliArgs, run.scope, cleanAgain)
	packagedAssertProgressParity(t, command, run.cliArgs, run.scope, run.api, &cleanAgain)
	assertCalls(2, 2)
	packagedAssertRouteAudit(t, run.state, run.scope, 2)
	packagedAssertRouteAudit(t, run.state, interrupted, 1)
	t.Logf("packaged model workers: completed=%s interrupted=%s candidate=%s verifier_already_claimed=true generation_calls=2 verification_calls=2 physical_crash_acceptance=false", final.Identity(), uncertain.Identity(), candidateID)
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
	if final != nil {
		if coverage.Context.Analyzed == nil || coverage.Context.Selected == nil || coverage.Context.Omitted == nil || *coverage.Context.Analyzed != int(final.SourceAnalyzedCount()) || *coverage.Context.Selected != int(final.SourceSelectedCount()) || *coverage.Context.Omitted != int(final.SourceOmittedCount()) {
			t.Fatal("packaged progress differs from final source accounting")
		}
		if final.VerifiedSetIdentity() != "" && (coverage.Verification.State != "available" || coverage.Verification.Candidates == nil || coverage.Verification.Verified == nil || coverage.Verification.Rejected == nil || coverage.Verification.Inconclusive == nil || *coverage.Verification.Candidates != int(final.CandidateCount()) || *coverage.Verification.Verified != int(final.VerifiedCount()) || *coverage.Verification.Rejected != int(final.RejectedCount()) || *coverage.Verification.Inconclusive != int(final.InconclusiveCount())) {
			t.Fatal("packaged progress differs from final verification accounting")
		}
		if final.VerifiedSetIdentity() == "" && (coverage.Verification.Verified != nil || coverage.Verification.Rejected != nil || coverage.Verification.Inconclusive != nil) {
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

func packagedScannerBuildFlags(t *testing.T) string {
	t.Helper()
	encoded, err := os.ReadFile("../../.container/release/secret-scanner-release.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		RootClient struct {
			Launcher string `json:"launcher_sha256"`
			Worker   string `json:"worker_sha256"`
		} `json:"root_client"`
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, digest string }{{"open-trestle-secret-scanner", manifest.RootClient.Launcher}, {"open-trestle-secret-scanner-worker", manifest.RootClient.Worker}} {
		body, err := os.ReadFile(filepath.Join("../../.container/libexec/open-trestle", item.name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(body)
		if len(item.digest) != 64 || hex.EncodeToString(digest[:]) != item.digest {
			t.Fatalf("staged %s differs from release digest", item.name)
		}
	}
	return "-s -w -buildid= -X github.com/georgejieh/open-trestle/internal/secretscan.expectedSecretScannerLauncherSHA256=" + manifest.RootClient.Launcher + " -X github.com/georgejieh/open-trestle/internal/secretscan.expectedSecretScannerWorkerSHA256=" + manifest.RootClient.Worker
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
