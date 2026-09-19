package change

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type pairSourceAdapter struct {
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
}

func (a *pairSourceAdapter) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a *pairSourceAdapter) Acquire(_ context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	return a.results[request.Revision().Identity()]
}
func sourceResult(t *testing.T, contents map[string][]byte) scm.SourceAdapterResult {
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
func TestHandlerBuildsBoundedChangeModelFromExactSourceDependencies(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &pairSourceAdapter{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{baseRevision.Identity(): sourceResult(t, map[string][]byte{"a.txt": []byte("old\n"), "removed.txt": []byte("gone\n")}), headRevision.Identity(): sourceResult(t, map[string][]byte{"a.txt": []byte("new\n"), "added.txt": []byte("hello\n")})}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceHandler, _ := sourcehandler.NewHandler(store, adapter, fixedClock{time.UnixMilli(200)})
	changeHandler, _ := NewHandler(store, fixedClock{time.UnixMilli(210)})
	if changeHandler.HandlerIdentity() != "1a574001085da1114defaf7d093fb91bb05abd684e40d3fc05cd2c20fdd0482d" {
		t.Fatalf("handler identity=%s", changeHandler.HandlerIdentity())
	}
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("d", 64), strings.Repeat("e", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	executeSource := func(task controlplane.TaskDefinition, at time.Time) {
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", task.Key(), acquired, err)
		}
		request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
		if err != nil {
			t.Fatal(err)
		}
		completion := sourceHandler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("source %s=%#v", task.Key(), completion)
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	executeSource(baseTask, time.UnixMilli(101))
	executeSource(headTask, time.UnixMilli(103))
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(105))
	if err != nil {
		t.Fatal(err)
	}
	lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "change", changeHandler.HandlerIdentity(), "worker", time.UnixMilli(106))
	if err != nil || !acquired {
		t.Fatalf("change claim=(%v,%v)", acquired, err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, changeTask)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, changeTask, lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := artifact.NewValidatedTaskHandler(changeHandler, store, fixedClock{time.UnixMilli(211)}, []artifact.Kind{artifact.KindSourceSnapshot}, []artifact.Kind{artifact.KindChangeModel})
	if err != nil {
		t.Fatal(err)
	}
	completion := validated.Execute(context.Background(), request)
	if completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("completion=%#v", completion)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(212))
	if err != nil {
		t.Fatal(err)
	}
	baseOutput, _ := store.Get(context.Background(), scope, dependencies[0].OutputIdentity(), time.UnixMilli(212))
	headOutput, _ := store.Get(context.Background(), scope, dependencies[1].OutputIdentity(), time.UnixMilli(212))
	if dependencies[0].TaskKey() == "source-head" {
		baseOutput, headOutput = headOutput, baseOutput
	}
	result, err := ParseResultArtifact(output, baseOutput, headOutput)
	if err != nil || len(result.Entries()) != 3 || result.HeadRevision().Identity() != headRevision.Identity() {
		t.Fatalf("result=(%#v,%v)", result, err)
	}
	entries := result.Entries()
	if entries[0].Path() != "a.txt" || entries[0].Status() != "supported" || len(entries[0].Ranges()) == 0 || entries[1].Path() != "added.txt" || entries[1].Status() != "supported" || entries[1].Reason() != "none" || len(entries[1].Ranges()) != 1 || entries[2].Path() != "removed.txt" || entries[2].Status() != "unsupported" || len(entries[2].Ranges()) != 0 {
		t.Fatalf("entries=%#v", entries)
	}
}
