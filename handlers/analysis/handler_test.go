package analysis

import (
	"context"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"strings"
	"testing"
	"time"
)

type testClock struct{ at time.Time }

func (c testClock) Now() time.Time { return c.at }

type testSource struct {
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
}

func (a *testSource) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a *testSource) Acquire(_ context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	return a.results[r.Revision().Identity()]
}
func makeSourceResult(t *testing.T, contents map[string][]byte) scm.SourceAdapterResult {
	t.Helper()
	files := make([]evidence.RepositoryFile, 0, len(contents))
	for path, content := range contents {
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
}
func TestHandlerBindsExactChangedSourceSlices(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &testSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{
		baseRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.txt": []byte("same\nold\n")}),
		headRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.txt": []byte("same\nnew\n"), "gate.go": []byte("package gate\nimport \"fmt\"\nfunc run() { fmt.Println(\"debug\") }\n")}),
	}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceTaskHandler, _ := sourcehandler.NewHandler(store, adapter, testClock{time.UnixMilli(200)})
	changeTaskHandler, _ := changehandler.NewHandler(store, testClock{time.UnixMilli(210)})
	diagnosticStore := diagnostics.NewMemoryStore()
	analysisTaskHandler, _ := NewHandlerWithDiagnostics(store, diagnosticStore, testClock{time.UnixMilli(220)})
	if analysisTaskHandler.HandlerIdentity() == "" {
		t.Fatal("projecting analysis handler has no identity")
	}
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeTaskHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	analysisTask, _ := controlplane.NewTaskDefinition("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("d", 64), analysisTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), strings.Repeat("f", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, analysisTask})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	execute := func(task controlplane.TaskDefinition, handler controlplane.TaskHandler, at time.Time) {
		state, err := coordinator.Advance(context.Background(), plan, at)
		if err != nil {
			t.Fatal(err)
		}
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		if err != nil {
			t.Fatal(err)
		}
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("%s completion status=%s failure=%s, want succeeded", task.Key(), completion.Status(), completion.Failure())
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	execute(baseTask, sourceTaskHandler, time.UnixMilli(101))
	execute(headTask, sourceTaskHandler, time.UnixMilli(103))
	execute(changeTask, changeTaskHandler, time.UnixMilli(105))
	execute(analysisTask, analysisTaskHandler, time.UnixMilli(107))
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(109))
	if err != nil {
		t.Fatal(err)
	}
	analysisState, _ := state.Task("analysis")
	output, err := store.Get(context.Background(), scope, analysisState.OutputIdentity(), time.UnixMilli(221))
	if err != nil {
		t.Fatal(err)
	}
	changeState, _ := state.Task("change")
	changeOutput, _ := store.Get(context.Background(), scope, changeState.OutputIdentity(), time.UnixMilli(221))
	baseState, _ := state.Task("source-base")
	headState, _ := state.Task("source-head")
	baseOutput, _ := store.Get(context.Background(), scope, baseState.OutputIdentity(), time.UnixMilli(221))
	headOutput, _ := store.Get(context.Background(), scope, headState.OutputIdentity(), time.UnixMilli(221))
	result, err := ParseResultArtifact(output, changeOutput, baseOutput, headOutput)
	if err != nil || len(result.Items()) < 2 || len(result.Gaps()) != 0 {
		t.Fatalf("result=(%#v,%v)", result, err)
	}
	if result.SchemaVersion() != 4 || result.Identity() == "" {
		t.Fatalf("result schema=%d identity=%s", result.SchemaVersion(), result.Identity())
	}
	checks := result.Checks()
	observations := result.Observations()
	if len(checks) != 1 || checks[0].State() != CheckFailed || checks[0].MatchCount() != 1 || checks[0].ApplicableFiles() != 1 || checks[0].CheckedFiles() != 1 || !checks[0].Complete() {
		t.Fatalf("checks=%#v", checks)
	}
	if len(observations) != 1 || observations[0].Path() != "gate.go" || observations[0].StartLine() != 3 || observations[0].EndLine() != 3 || observations[0].CheckIdentity() != checks[0].Identity() || observations[0].EvidenceID() == "" {
		t.Fatalf("observations=%#v", observations)
	}
	projected, err := diagnosticStore.GetDiagnosticSet(context.Background(), scope)
	if err != nil || projected.SchemaVersion() != 6 || projected.AnalysisResultIdentity() != result.Identity() || len(projected.Findings()) != 0 || len(projected.DeterministicObservations()) != 1 || projected.DeterministicObservations()[0].SourceIdentity() != observations[0].Identity() {
		t.Fatalf("projected diagnostics=%#v err=%v", projected, err)
	}
	assertOldCodeAnalysisGoldens(t, baseOutput, headOutput, changeOutput, output, result)
	semantic := result.SemanticImpact()
	if semantic.Identity() == "" || len(semantic.Gaps()) != 1 || semantic.Gaps()[0].Reason() != "unsupported_language" {
		t.Fatalf("semantic=%#v", semantic)
	}
	var item Item
	for _, candidate := range result.Items() {
		if candidate.Path() == "a.txt" {
			item = candidate
		}
	}
	if item.Path() != "a.txt" || item.StartLine() != 2 || item.EndLine() != 2 || item.SliceBytes() != 4 {
		t.Fatalf("item=%#v", item)
	}
}

func TestHandlerBindsMultilineDebugObservationToChangedLiteral(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &testSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{
		baseRevision.Identity(): makeSourceResult(t, map[string][]byte{"gate.go": []byte("package gate\nimport \"fmt\"\nfunc run() {\n\tfmt.Println(\n\t\t\"trace\",\n\t)\n}\n")}),
		headRevision.Identity(): makeSourceResult(t, map[string][]byte{"gate.go": []byte("package gate\nimport \"fmt\"\nfunc run() {\n\tfmt.Println(\n\t\t\"debug\",\n\t)\n}\n")}),
	}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "multiline")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceTaskHandler, _ := sourcehandler.NewHandler(store, adapter, testClock{time.UnixMilli(200)})
	changeTaskHandler, _ := changehandler.NewHandler(store, testClock{time.UnixMilli(210)})
	analysisTaskHandler, _ := NewHandlerWithDiagnostics(store, diagnostics.NewMemoryStore(), testClock{time.UnixMilli(220)})
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeTaskHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	analysisTask, _ := controlplane.NewTaskDefinition("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("d", 64), analysisTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), strings.Repeat("f", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, analysisTask})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	execute := func(task controlplane.TaskDefinition, handler controlplane.TaskHandler, at time.Time) string {
		state, err := coordinator.Advance(context.Background(), plan, at)
		if err != nil {
			t.Fatal(err)
		}
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		if err != nil {
			t.Fatal(err)
		}
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("%s completion status=%s failure=%s, want succeeded", task.Key(), completion.Status(), completion.Failure())
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		return completion.OutputIdentity()
	}
	baseOutputID := execute(baseTask, sourceTaskHandler, time.UnixMilli(101))
	headOutputID := execute(headTask, sourceTaskHandler, time.UnixMilli(103))
	changeOutputID := execute(changeTask, changeTaskHandler, time.UnixMilli(105))
	analysisOutputID := execute(analysisTask, analysisTaskHandler, time.UnixMilli(107))
	analysisOutput, _ := store.Get(context.Background(), scope, analysisOutputID, time.UnixMilli(221))
	changeOutput, _ := store.Get(context.Background(), scope, changeOutputID, time.UnixMilli(221))
	baseOutput, _ := store.Get(context.Background(), scope, baseOutputID, time.UnixMilli(221))
	headOutput, _ := store.Get(context.Background(), scope, headOutputID, time.UnixMilli(221))
	result, err := ParseResultArtifact(analysisOutput, changeOutput, baseOutput, headOutput)
	if err != nil {
		t.Fatal(err)
	}
	observations := result.Observations()
	if len(observations) != 1 || observations[0].Path() != "gate.go" || observations[0].StartLine() != 5 || observations[0].EndLine() != 5 || observations[0].EvidenceID() == "" {
		t.Fatalf("observations=%#v, want exact changed literal line gate.go:5-5", observations)
	}
}

func TestDiagnosticWriteFailureClassifiesDiagnosticStoreCapacity(t *testing.T) {
	if got := diagnosticWriteFailure(context.Background(), diagnostics.ErrStoreCapacity); got != controlplane.RunFailureResourceLimit {
		t.Fatalf("diagnostic store capacity mapped to %s", got)
	}
}

// An emptied head file leaves no head line to anchor a deletion, so the entry
// keeps the version 5 whole-entry gap.
func TestHandlerKeepsNoChangedHeadLinesGap(t *testing.T) {
	for _, after := range []string{""} {
		t.Run(after, func(t *testing.T) {
			output, change, base, head := deletionAnalysisFixture(t, map[string][]byte{"a.txt": []byte("guard\nkeep\n")}, map[string][]byte{"a.txt": []byte(after)})
			result, err := ParseResultArtifact(output, change, base, head)
			if err != nil {
				t.Fatal(err)
			}
			if result.SchemaVersion() != 5 || len(result.Items()) != 0 || len(result.Observations()) != 0 || len(result.Gaps()) != 1 {
				t.Fatalf("invalid deletion analysis: %#v", result)
			}
			gap := result.Gaps()[0]
			if gap.Path() != "a.txt" || gap.Reason() != "no_changed_head_lines" || gap.StartLine() != 0 || gap.EndLine() != 0 {
				t.Fatalf("gap=%#v", gap)
			}
			check := result.Checks()[0]
			if check.State() != CheckNotApplicable || check.ApplicableFiles() != 0 || check.ApplicableRanges() != 0 || check.CheckedRanges() != 0 {
				t.Fatalf("deletion was counted as checked: %#v", check)
			}
			if result.SemanticImpact().Identity() == "" || len(result.SemanticImpact().Gaps()) != 1 || result.SemanticImpact().Gaps()[0].Path() != "a.txt" {
				t.Fatal("deletion path was lost from semantic profiling")
			}
		})
	}
}

func TestHandlerKeepsV5MixedObservations(t *testing.T) {
	output, change, base, head := deletionAnalysisFixture(t,
		map[string][]byte{"a.txt": []byte("guard\nkeep\n")},
		map[string][]byte{"a.txt": []byte(""), "gate.go": []byte("package gate\nimport \"fmt\"\nfunc run() { fmt.Println(\"debug\") }\n")})
	result, err := ParseResultArtifact(output, change, base, head)
	if err != nil || result.SchemaVersion() != 5 || len(result.Gaps()) != 1 || len(result.Observations()) != 1 || result.Observations()[0].Path() != "gate.go" || len(result.Items()) != 1 {
		t.Fatalf("mixed v5 result=%#v err=%v", result, err)
	}
}

func deletionAnalysisFixture(t *testing.T, baseFiles, headFiles map[string][]byte) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &testSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{
		baseRevision.Identity(): makeSourceResult(t, baseFiles),
		headRevision.Identity(): makeSourceResult(t, headFiles),
	}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "multiline")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceTaskHandler, _ := sourcehandler.NewHandler(store, adapter, testClock{time.UnixMilli(200)})
	changeTaskHandler, _ := changehandler.NewHandler(store, testClock{time.UnixMilli(210)})
	analysisTaskHandler, _ := NewHandlerWithDiagnostics(store, diagnostics.NewMemoryStore(), testClock{time.UnixMilli(220)})
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeTaskHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	analysisTask, _ := controlplane.NewTaskDefinition("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("d", 64), analysisTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), strings.Repeat("f", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, analysisTask})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	execute := func(task controlplane.TaskDefinition, handler controlplane.TaskHandler, at time.Time) string {
		state, err := coordinator.Advance(context.Background(), plan, at)
		if err != nil {
			t.Fatal(err)
		}
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		if err != nil {
			t.Fatal(err)
		}
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		if err != nil {
			t.Fatal(err)
		}
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("%s completion status=%s failure=%s, want succeeded", task.Key(), completion.Status(), completion.Failure())
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		return completion.OutputIdentity()
	}
	baseOutputID := execute(baseTask, sourceTaskHandler, time.UnixMilli(101))
	headOutputID := execute(headTask, sourceTaskHandler, time.UnixMilli(103))
	changeOutputID := execute(changeTask, changeTaskHandler, time.UnixMilli(105))
	analysisOutputID := execute(analysisTask, analysisTaskHandler, time.UnixMilli(107))
	analysisOutput, _ := store.Get(context.Background(), scope, analysisOutputID, time.UnixMilli(221))
	changeOutput, _ := store.Get(context.Background(), scope, changeOutputID, time.UnixMilli(221))
	baseOutput, _ := store.Get(context.Background(), scope, baseOutputID, time.UnixMilli(221))
	headOutput, _ := store.Get(context.Background(), scope, headOutputID, time.UnixMilli(221))
	return analysisOutput, changeOutput, baseOutput, headOutput
}

func TestNoChangedHeadLinesGapSurvivesEvidenceLimit(t *testing.T) {
	_, change, base, head := deletionAnalysisFixture(t, map[string][]byte{"a.txt": []byte("guard\nkeep\n")}, map[string][]byte{"a.txt": []byte("keep\n")})
	result, err := changehandler.ParseResultArtifact(change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	gap, ok := wholeEntryGap(result.Entries()[0], true)
	if !ok || gap.Reason() != "no_changed_head_lines" || gap.StartLine() != 0 || gap.EndLine() != 0 {
		t.Fatalf("mandatory deletion gap replaced at evidence limit: %#v, %v", gap, ok)
	}
}
