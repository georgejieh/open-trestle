package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/worker"
)

func TestLocalFinalProjectorRefusesActiveAndNonFullPlans(t *testing.T) {
	artifacts, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	destination := diagnostics.NewMemoryStore()
	projector, err := NewLocalFinalDiagnosticProjector(artifacts, destination, digestForTest())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-projector")
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, digestForTest(), digestForTest(), nil, 1, 0, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, digestForTest(), digestForTest(), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	state, err := coordinator.Open(context.Background(), plan, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(context.Background(), state); !errors.Is(err, ErrInvalidLocalFinalDiagnosticProjection) {
		t.Fatalf("active state: %v", err)
	}
	state, err = coordinator.CancelRun(context.Background(), plan, time.Now().UTC().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(context.Background(), state); err != nil {
		t.Fatalf("non-full plan must be ignored: %v", err)
	}
	if _, err := destination.GetDiagnosticSet(context.Background(), scope); !errors.Is(err, diagnostics.ErrSetNotFound) {
		t.Fatalf("unexpected projection: %v", err)
	}
}

func digestForTest() string {
	return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func finalProjectorPlan(t *testing.T, scope audit.ReviewScope, analysisHandler string) controlplane.ReviewRunPlan {
	t.Helper()
	definitions := []struct {
		key      string
		kind     controlplane.TaskKind
		deps     []string
		required bool
	}{
		{"source-base", controlplane.TaskAcquireSource, nil, true},
		{"source-head", controlplane.TaskAcquireSource, nil, true},
		{"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}, true},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}, true},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}, true},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}, true},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}, true},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}, true},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"verification"}, true},
	}
	tasks := make([]controlplane.TaskDefinition, 0, len(definitions))
	for _, item := range definitions {
		handler := digestForTest()
		if item.key == "analysis" {
			handler = analysisHandler
		}
		task, err := controlplane.NewTaskDefinition(item.key, item.kind, digestForTest(), handler, item.deps, 1, 0, 30000, item.required)
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, digestForTest(), digestForTest(), controlplane.ReviewRunLocal, tasks)
	if err != nil {
		t.Fatal(err)
	}
	if !isLocalFullReviewPlan(plan) {
		t.Fatal("invalid full plan fixture")
	}
	return plan
}

func TestLocalFinalProjectorCanceledWithoutSourceAndIdempotent(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-final-canceled")
	plan := finalProjectorPlan(t, scope, digestForTest())
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	at := time.Now().UTC()
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	terminal, err := coordinator.CancelRun(ctx, plan, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	destination := diagnostics.NewMemoryStore()
	projector, _ := NewLocalFinalDiagnosticProjector(artifacts, destination, digestForTest())
	for range 2 {
		if err := projector.Project(ctx, terminal); err != nil {
			t.Fatal(err)
		}
	}
	result, err := destination.GetDiagnosticSet(ctx, scope)
	if err != nil || result.SchemaVersion() != 7 || result.Outcome() != diagnostics.FinalOutcomeCanceled || result.SnapshotIdentity() != "" || result.HeadRevision() != "" {
		t.Fatalf("canceled result=%s err=%v", result.Outcome(), err)
	}
}

func TestLocalFinalProjectorFailedVerificationWithoutV5IsInconclusive(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-final-no-verifier")
	plan := finalProjectorPlan(t, scope, digestForTest())
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	at := time.Now().UTC()
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification"} {
		at = at.Add(time.Second)
		if _, err := coordinator.Advance(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
		task, _ := plan.Task(key)
		lease, claimed, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "fixture", at)
		if err != nil || !claimed {
			t.Fatalf("claim %s: %v", key, err)
		}
		var completion controlplane.TaskCompletion
		if key == "verification" {
			completion, err = controlplane.NewTaskFailure(controlplane.RunFailureTransient)
		} else {
			completion, err = controlplane.NewTaskSuccess(digestForTest())
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatalf("complete %s: %v", key, err)
		}
	}
	finalizer, _ := controlplane.NewRunFinalizer(journal)
	terminal, _, err := finalizer.ReconcileRun(ctx, scope, at.Add(time.Second))
	if err != nil || terminal.Status() != controlplane.ReviewRunFailed {
		t.Fatalf("terminal=%s err=%v", terminal.Status(), err)
	}
	// The task success IDs are placeholders here, so the real artifact builder
	// must reject them. The integration regression uses physical artifacts below.
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	destination := diagnostics.NewMemoryStore()
	projector, _ := NewLocalFinalDiagnosticProjector(artifacts, destination, digestForTest())
	if err := projector.Project(ctx, terminal); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("unverified IDs accepted: %v", err)
	}
	if _, err := destination.GetDiagnosticSet(ctx, scope); !errors.Is(err, diagnostics.ErrSetNotFound) {
		t.Fatalf("invented V7: %v", err)
	}
}

func TestLocalFinalProjectorPreservesHistoricalFullRunDiagnostics(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-historical-v6")
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	oldHandler, err := analysishandler.NewHandlerWithDiagnostics(artifacts, diagnostics.NewMemoryStore(), finalProjectorClock{})
	if err != nil {
		t.Fatal(err)
	}
	newHandler, err := analysishandler.NewHandler(artifacts, finalProjectorClock{})
	if err != nil {
		t.Fatal(err)
	}
	plan := finalProjectorPlan(t, scope, oldHandler.HandlerIdentity())
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	at := time.Now().UTC()
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	terminal, err := coordinator.CancelRun(ctx, plan, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	destination := diagnostics.NewMemoryStore()
	projector, err := NewLocalFinalDiagnosticProjector(artifacts, destination, newHandler.HandlerIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(ctx, terminal); err != nil {
		t.Fatalf("historical run refused: %v", err)
	}
	if _, err := destination.GetDiagnosticSet(ctx, scope); !errors.Is(err, diagnostics.ErrSetNotFound) {
		t.Fatalf("historical run modified diagnostics: %v", err)
	}
}

type finalProjectorClock struct{}

func (finalProjectorClock) Now() time.Time { return time.Now().UTC() }

func TestLocalFinalProjectorVerifierUnavailableProjectsInconclusiveWithoutV5(t *testing.T) {
	args, getenv, repository, base, head, policy, inventory := localFullDaemonFixture(t)
	deps := daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: testsupport.NewCleanGenerationSanitizer(), verificationSanitizer: reviewcore.NewFixedVerificationRequestSanitizer(nil)}
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-final-verifier-unavailable")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	supervisor, ok := d.supervisors[1].(*worker.RepositorySupervisor)
	if !ok {
		t.Fatalf("unexpected premodel supervisor: %T", d.supervisors[1])
	}
	if _, err := supervisor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	plan, found, err := d.journal.LoadPlan(context.Background(), scope)
	if err != nil || !found {
		t.Fatalf("load plan: found=%t err=%v", found, err)
	}
	coordinator, _ := controlplane.NewCoordinator(d.journal)
	_, state, err := coordinator.Resume(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if runtime, _ := state.Task("analysis"); runtime.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatalf("analysis=%s", runtime.Status())
	}
	// Simulate a transient local verifier outage with no provider calls. Source,
	// change, analysis, and context artifacts came from the real daemon path.
	for _, key := range []string{"candidates", "verification"} {
		task, _ := plan.Task(key)
		now := time.Now().UTC()
		if _, err := coordinator.Advance(context.Background(), plan, now); err != nil {
			t.Fatal(err)
		}
		lease, claimed, err := coordinator.ClaimTask(context.Background(), plan, key, task.HandlerIdentity(), "fixture", now)
		if err != nil || !claimed {
			t.Fatalf("claim %s: %v", key, err)
		}
		var completion controlplane.TaskCompletion
		if key == "candidates" {
			completion, err = controlplane.NewTaskSuccess(digestForTest())
		} else {
			completion, err = controlplane.NewTaskFailure(controlplane.RunFailureTransient)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, now.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	finalizer, _ := controlplane.NewRunFinalizer(d.journal)
	terminal, _, err := finalizer.ReconcileRun(context.Background(), scope, time.Now().UTC())
	if err != nil || terminal.Status() != controlplane.ReviewRunFailed {
		t.Fatalf("terminal=%s err=%v", terminal.Status(), err)
	}
	analysisTask, _ := plan.Task("analysis")
	projector, err := NewLocalFinalDiagnosticProjector(d.artifactStore, d.diagnosticStore, analysisTask.HandlerIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := projector.Project(context.Background(), terminal); err != nil {
			t.Fatal(err)
		}
	}
	result, err := d.diagnosticStore.GetDiagnosticSet(context.Background(), scope)
	if err != nil || result.SchemaVersion() != 7 || result.Outcome() != diagnostics.FinalOutcomeInconclusive || result.AnalysisResultIdentity() == "" || result.VerifiedSetIdentity() != "" || result.SnapshotIdentity() == "" || result.HeadRevision() == "" {
		t.Fatalf("inconclusive result=%s schema=%d analysis=%q verified=%q err=%v", result.Outcome(), result.SchemaVersion(), result.AnalysisResultIdentity(), result.VerifiedSetIdentity(), err)
	}
}

// Artifact access is counted independently of the diagnostic store read path.
type finalCountingArtifacts struct {
	artifact.Store
	gets int
}

func (s *finalCountingArtifacts) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	s.gets++
	return s.Store.Get(ctx, scope, identity, at)
}

func TestLocalFinalProjectorReplayDoesNotReloadArtifacts(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-final-replay")
	plan := finalProjectorPlan(t, scope, digestForTest())
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	at := time.Now().UTC()
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	terminal, err := coordinator.CancelRun(ctx, plan, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	counted := &finalCountingArtifacts{Store: store}
	destination := diagnostics.NewMemoryStore()
	projector, err := NewLocalFinalDiagnosticProjector(counted, destination, digestForTest())
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	before := counted.gets
	if err := projector.Project(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	if counted.gets != before {
		t.Fatalf("replay reopened artifacts: before=%d after=%d", before, counted.gets)
	}
	existing, err := destination.GetDiagnosticSet(ctx, scope)
	if err != nil || existing.Outcome() != diagnostics.FinalOutcomeCanceled {
		t.Fatalf("replay changed outcome: %v", err)
	}
}

func TestLocalFinalProjectorNewPlanRejectsExistingLegacySet(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-final-legacy-conflict")
	plan := finalProjectorPlan(t, scope, digestForTest())
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	at := time.Now().UTC()
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	terminal, err := coordinator.CancelRun(ctx, plan, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	destination := diagnostics.NewMemoryStore()
	legacy, err := diagnostics.NewSet(scope, digestForTest(), "0123456789012345678901234567890123456789", digestForTest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := destination.PutDiagnosticSet(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	projector, _ := NewLocalFinalDiagnosticProjector(store, destination, digestForTest())
	if err := projector.Project(ctx, terminal); !errors.Is(err, diagnostics.ErrSetConflict) {
		t.Fatalf("legacy record on new plan: %v", err)
	}
	stored, err := destination.GetDiagnosticSet(ctx, scope)
	if err != nil || stored.Identity() != legacy.Identity() {
		t.Fatalf("legacy record overwritten: %v", err)
	}
}

func TestLocalFinalProjectorValidContextAbstention(t *testing.T) {
	args, getenv, repository, base, _, policy, inventory := localFullDaemonFixture(t)
	objects := daemonTestFlagValue(t, args, "--local-git-objects-root")
	head := abstentionHeadRevision(t, objects, "package-lock.json", []byte("{\"lockfileVersion\": \"unsupported-marker\"}\n"))
	deps := daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: testsupport.NewCleanGenerationSanitizer(), verificationSanitizer: reviewcore.NewFixedVerificationRequestSanitizer(nil)}
	d, err := buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server := httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-final-abstention")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(context.Background(), intent); err != nil {
		t.Fatal(err)
	}
	supervisor, ok := d.supervisors[1].(*worker.RepositorySupervisor)
	if !ok {
		t.Fatalf("unexpected supervisor: %T", d.supervisors[1])
	}
	if _, err := supervisor.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(d.journal)
	plan, state, err := coordinator.Resume(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status() == controlplane.ReviewRunActive {
		finalizer, _ := controlplane.NewRunFinalizer(d.journal)
		state, _, err = finalizer.ReconcileRun(context.Background(), scope, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
	}
	if state.Status() != controlplane.ReviewRunFailed {
		t.Fatalf("terminal=%s", state.Status())
	}
	analysisTask, _ := plan.Task("analysis")
	projector, err := NewLocalFinalDiagnosticProjector(d.artifactStore, d.diagnosticStore, analysisTask.HandlerIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := projector.Project(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	result, err := d.diagnosticStore.GetDiagnosticSet(context.Background(), scope)
	if err != nil || result.Outcome() != diagnostics.FinalOutcomeAbstained || result.AnalysisResultIdentity() == "" || result.VerifiedSetIdentity() != "" {
		t.Fatalf("abstention=%s analysis=%q verified=%q err=%v", result.Outcome(), result.AnalysisResultIdentity(), result.VerifiedSetIdentity(), err)
	}

	packagedAssertCoverageAbstention(t, daemonTestFlagValue(t, args, "--state-dir"), scope, plan.Identity(), result)
	canonical, err := diagnostics.EncodeSet(result)
	if err != nil {
		t.Fatal(err)
	}
	progress, err := api.GetRunProgress(context.Background(), scope)
	if err != nil || progress.Progress.Change.State != "available" || progress.Progress.Deterministic.State != "available" || progress.Progress.Context.State != "unavailable" || progress.Progress.Context.ArtifactIdentity != "" || progress.Progress.Context.Analyzed != nil || progress.Progress.Context.Selected != nil || progress.Progress.Context.Omitted != nil || progress.Progress.Verification.State != "unavailable" || progress.Progress.Verification.Candidates != nil || progress.Progress.Verification.Verified != nil || progress.Progress.Verification.Rejected != nil || progress.Progress.Verification.Inconclusive != nil {
		t.Fatalf("abstention progress invented coverage or verification: %+v %v", progress.Progress, err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	d, err = buildDaemonWithDependencies(context.Background(), args, getenv, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	server = httptest.NewServer(d.server.Handler)
	defer server.Close()
	api, err = client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	replay, err := api.SubmitLocalFullReview(context.Background(), intent)
	if err != nil || replay.PlanIdentity() != plan.Identity() {
		t.Fatalf("abstention replay: %v", err)
	}
	reopened, err := api.GetDiagnosticSet(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	packagedAssertCoverageAbstention(t, daemonTestFlagValue(t, args, "--state-dir"), scope, plan.Identity(), reopened)
	reencoded, err := diagnostics.EncodeSet(reopened)
	if err != nil || !bytes.Equal(canonical, reencoded) {
		t.Fatalf("abstention changed after restart: %v", err)
	}
	reopenedProgress, err := api.GetRunProgress(context.Background(), scope)
	if err != nil || reopenedProgress.Run.Identity() != progress.Run.Identity() || !reflect.DeepEqual(reopenedProgress.Progress, progress.Progress) {
		t.Fatalf("abstention progress changed after restart: %v", err)
	}
}

func packagedAssertCoverageAbstention(t *testing.T, state string, scope audit.ReviewScope, plan string, set diagnostics.Set) {
	t.Helper()
	if set.SchemaVersion() != 7 || set.Outcome() != diagnostics.FinalOutcomeAbstained || set.AnalysisResultIdentity() == "" || set.VerifiedSetIdentity() != "" || len(set.Findings()) != 0 {
		t.Fatal("coverage refusal was not a content-linked abstention")
	}
	encoded, err := os.ReadFile(filepath.Join(state, scope.Identity()+".run.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	previous, output := "", ""
	preparedAt, failedAt, terminalAt, failed, terminal := -1, -1, -1, 0, 0
	for index, line := range bytes.Split(bytes.TrimSpace(encoded), []byte("\n")) {
		event, err := controlplane.ParseRunEvent(line)
		if err != nil || event.Scope().Identity() != scope.Identity() || event.PlanIdentity() != plan || event.Sequence() != uint64(index+1) || event.PreviousIdentity() != previous {
			t.Fatalf("abstention journal chain: %v", err)
		}
		previous = event.Identity()
		if event.Kind() == controlplane.RunEventFailed {
			terminal++
			terminalAt = index
		}
		if event.TaskKey() != "context" {
			continue
		}
		if event.Kind() == controlplane.RunEventContextAbstentionPrepared {
			if preparedAt >= 0 {
				t.Fatal("duplicate abstention prepare")
			}
			preparedAt = index
			output = event.OutputIdentity()
			encodedPrepare, err := controlplane.EncodeRunEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			var prepare struct {
				Artifact []byte `json:"prepared_artifact"`
			}
			if err := json.Unmarshal(encodedPrepare, &prepare); err != nil {
				t.Fatal(err)
			}
			physical, err := os.ReadFile(filepath.Join(state, "artifacts", scope.Identity()+"-"+output+".artifact.json"))
			if err != nil || !bytes.Equal(physical, prepare.Artifact) {
				t.Fatalf("abstention physical readback: %v", err)
			}
			value, err := artifact.Parse(physical)
			if err != nil || value.Scope().Identity() != scope.Identity() || value.Identity() != output || value.Kind() != artifact.KindDeterministicEvidence {
				t.Fatalf("abstention physical binding: %v", err)
			}
			var payload struct {
				Contract  string `json:"contract"`
				Scope     string `json:"review_scope_identity"`
				Plan      string `json:"plan_identity"`
				Task      string `json:"task_identity"`
				Omissions []struct {
					Path   string `json:"path"`
					Reason string `json:"reason"`
					Count  int    `json:"count"`
				} `json:"source_omissions"`
			}
			if err := json.Unmarshal(value.Payload(), &payload); err != nil || payload.Contract != "open-trestle/context-abstention" || payload.Scope != scope.Identity() || payload.Plan != plan || payload.Task != event.TaskIdentity() {
				t.Fatalf("abstention payload binding: %v", err)
			}
			found := false
			for _, omission := range payload.Omissions {
				if omission.Path == "package-lock.json" && omission.Reason == "excluded_path" && omission.Count > 0 {
					found = true
				}
			}
			if !found || bytes.Contains(value.Payload(), []byte("unsupported-marker")) {
				t.Fatal("coverage omission missing or source leaked")
			}
		}
		if event.Kind() == controlplane.RunEventTaskFailed {
			if output == "" || event.OutputIdentity() != output {
				t.Fatal("context failure lost abstention identity")
			}
			failed++
			failedAt = index
		}
	}
	if preparedAt < 0 || failedAt <= preparedAt || failed != 1 || terminal != 1 || terminalAt <= failedAt {
		t.Fatal("abstention did not settle exactly once after prepare")
	}
	auditBytes, err := os.ReadFile(filepath.Join(state, "audit", scope.Identity()+".audit.jsonl"))
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	previous = ""
	for index, line := range bytes.Split(bytes.TrimSpace(auditBytes), []byte("\n")) {
		event, err := audit.ParseEvent(line)
		if err != nil || event.Scope().Identity() != scope.Identity() || event.Sequence() != uint64(index+1) || event.PreviousIdentity() != previous {
			t.Fatalf("abstention audit chain: %v", err)
		}
		previous = event.Identity()
		if event.Kind() == audit.EventRouteAttemptClaimed || event.Kind() == audit.EventRouteDispatchCompleted || event.Kind() == audit.EventPublicationClaimed || event.Kind() == audit.EventPublicationCompleted {
			t.Fatal("coverage abstention dispatched a route or publication")
		}
	}
}
