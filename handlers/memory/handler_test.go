package memory

import (
	"context"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/scm"
	"strings"
	"testing"
	"time"
)

type memoryTestClock struct{ at time.Time }

func (c memoryTestClock) Now() time.Time { return c.at }

type memoryTestSource struct {
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
}

func (a *memoryTestSource) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a *memoryTestSource) Acquire(_ context.Context, r evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
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
func TestHandlerRetrievesFreshScopedMemoryForChangedPath(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &memoryTestSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{baseRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.txt": []byte("same\nold\n")}), headRevision.Identity(): makeSourceResult(t, map[string][]byte{"a.txt": []byte("same\nnew\n")})}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", "run")
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, adapterIdentity)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, adapterIdentity)
	baseArtifact, _ := sourcehandler.NewInputArtifact(scope, baseInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	headArtifact, _ := sourcehandler.NewInputArtifact(scope, headInput, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, time.UnixMilli(50), time.UnixMilli(10000))
	_, _ = store.Put(context.Background(), baseArtifact, time.UnixMilli(50))
	_, _ = store.Put(context.Background(), headArtifact, time.UnixMilli(50))
	sourceTaskHandler, _ := sourcehandler.NewHandler(store, adapter, memoryTestClock{time.UnixMilli(200)})
	changeTaskHandler, _ := changehandler.NewHandler(store, memoryTestClock{time.UnixMilli(210)})
	index := memorycore.NewLexicalIndex()
	memoryScope, scopeErr := memorycore.NewScope("tenant", "repository", "reviewer", memorycore.RefVisibilityExact, headRevision.Identity(), []string{"."})
	if scopeErr != nil {
		t.Fatal(scopeErr)
	}
	record, recordErr := memorycore.NewRecord(memoryScope, memorycore.RecordInput{Kind: memorycore.RecordCanonicalFact, Taint: memorycore.TaintTrusted, Path: "a.txt", Text: "this path has a parser invariant", EvidenceIDs: []string{strings.Repeat("9", 64)}, ProducerIdentity: strings.Repeat("7", 64), ObservedAt: time.UnixMilli(10), ValidFrom: time.UnixMilli(10)})
	if recordErr != nil {
		t.Fatal(recordErr)
	}
	if _, _, err := index.Add(context.Background(), memoryScope, record); err != nil {
		t.Fatal(err)
	}
	policyIdentity := strings.Repeat("f", 64)
	memoryTaskHandler, _ := NewHandler(store, memoryTestClock{time.UnixMilli(220)}, index, strings.Repeat("6", 64), policyIdentity, "reviewer", []string{"."}, 10, 20)
	baseTask, _ := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, baseArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	headTask, _ := controlplane.NewTaskDefinition("source-head", controlplane.TaskAcquireSource, headArtifact.Identity(), sourceTaskHandler.HandlerIdentity(), nil, 1, 1000, 30000, true)
	changeTask, _ := controlplane.NewTaskDefinition("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), changeTaskHandler.HandlerIdentity(), []string{"source-base", "source-head"}, 1, 1000, 30000, true)
	memoryTask, _ := controlplane.NewTaskDefinition("memory", controlplane.TaskRetrieveContext, strings.Repeat("d", 64), memoryTaskHandler.HandlerIdentity(), []string{"change"}, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), policyIdentity, controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask, memoryTask})
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
			t.Fatalf("%s completion=%#v", task.Key(), completion)
		}
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	execute(baseTask, sourceTaskHandler, time.UnixMilli(101))
	execute(headTask, sourceTaskHandler, time.UnixMilli(103))
	execute(changeTask, changeTaskHandler, time.UnixMilli(105))
	execute(memoryTask, memoryTaskHandler, time.UnixMilli(107))
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(109))
	if err != nil {
		t.Fatal(err)
	}
	memoryState, _ := state.Task("memory")
	output, err := store.Get(context.Background(), scope, memoryState.OutputIdentity(), time.UnixMilli(221))
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
	if err != nil || len(result.Queries()) != 1 || len(result.Omissions()) != 0 {
		t.Fatalf("result=(%#v,%v)", result, err)
	}
	if result.RetrieverIdentity() != strings.Repeat("6", 64) {
		t.Fatalf("retriever=%s", result.RetrieverIdentity())
	}
	provenance := make([]string, 0, len(output.Provenance()))
	for _, identity := range output.Provenance() {
		if identity != result.RetrieverIdentity() {
			provenance = append(provenance, identity)
		}
	}
	withoutRetriever, artifactErr := artifact.New(scope, output.Kind(), output.MediaType(), output.Classification(), output.Origin(), output.Protection(), provenance, output.Payload(), output.CreatedAt(), output.ExpiresAt())
	if artifactErr != nil {
		t.Fatal(artifactErr)
	}
	if parsed, parseErr := ParseResultArtifact(withoutRetriever, changeOutput, baseOutput, headOutput); parseErr == nil || parsed.Identity() != "" {
		t.Fatal("memory result without backend provenance accepted")
	}
	query := result.Queries()[0]
	if query.Path() != "a.txt" || len(query.Items()) != 1 {
		t.Fatalf("query=%#v", query)
	}
}
