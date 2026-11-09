package change

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type mergeBaseTrees struct {
	identity  evidence.SourceAdapterIdentity
	trees     map[string]map[string]string
	mergeBase evidence.RevisionIdentity
	acquired  []string
}

func (m *mergeBaseTrees) Identity() evidence.SourceAdapterIdentity { return m.identity }
func (m *mergeBaseTrees) Acquire(_ context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	m.acquired = append(m.acquired, request.Revision().Digest())
	tree := m.trees[request.Revision().Digest()]
	contents := map[string][]byte{}
	files := []evidence.RepositoryFile{}
	for path, content := range tree {
		contents[path] = []byte(content)
		file, _ := evidence.NewRepositoryFile(path, contents[path])
		files = append(files, file)
	}
	manifest, _ := evidence.NewRepositoryManifest(files)
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
}
func (m *mergeBaseTrees) ResolveMergeBase(context.Context, scm.MergeBaseRequest) scm.MergeBaseResult {
	return scm.MergeBaseResult{Outcome: scm.MergeBaseResolved, MergeBase: m.mergeBase, Reason: evidence.AcquisitionReasonNone}
}

type changeClock struct{ at time.Time }

func (c changeClock) Now() time.Time { return c.at }

func mergeBaseRevision(t *testing.T, digit string) evidence.RevisionIdentity {
	t.Helper()
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat(digit, 40))
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

// runMergeBaseChange acquires a merge-base base input and a head input, then
// builds the change. It returns the change completion and its output.
func runMergeBaseChange(t *testing.T, requested, head, headInputRevision evidence.RevisionIdentity) (controlplane.TaskCompletion, artifact.Artifact, artifact.Artifact, artifact.Artifact, *mergeBaseTrees) {
	t.Helper()
	ctx := context.Background()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	check(err)
	adapterIdentity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	check(err)
	merge := mergeBaseRevision(t, "3")
	trees := &mergeBaseTrees{identity: adapterIdentity, mergeBase: merge, trees: map[string]map[string]string{
		merge.Digest():     {"a.go": "package p\nfunc A() int { return 1 }\n"},
		requested.Digest(): {"a.go": "package p\nfunc A() int { return 1 }\n", "base_only.go": "package p\nfunc B() {}\n"},
		head.Digest():      {"a.go": "package p\nfunc A() int { return 2 }\n"},
	}}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	check(err)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-merge-base")
	check(err)
	sources, err := source.NewHandler(store, trees, changeClock{time.UnixMilli(200)})
	check(err)
	changes, err := NewHandler(store, changeClock{time.UnixMilli(210)})
	check(err)
	baseInput, err := source.NewMergeBaseInput(repository, requested, head, adapterIdentity)
	check(err)
	headInput, err := source.NewInput(repository, headInputRevision, adapterIdentity)
	check(err)
	put := func(input source.Input, provenance string) artifact.Artifact {
		value, err := source.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{provenance}, time.UnixMilli(50), time.UnixMilli(10000))
		check(err)
		_, err = store.Put(ctx, value, time.UnixMilli(50))
		check(err)
		return value
	}
	baseArtifact, headArtifact := put(baseInput, strings.Repeat("a", 64)), put(headInput, strings.Repeat("b", 64))
	define := func(key string, handler controlplane.TaskHandler, input string, dependencies []string) controlplane.TaskDefinition {
		task, err := controlplane.NewTaskDefinition(key, handler.Kind(), input, handler.HandlerIdentity(), dependencies, 1, 1000, 30000, true)
		check(err)
		return task
	}
	baseTask := define("source-base", sources, baseArtifact.Identity(), nil)
	headTask := define("source-head", sources, headArtifact.Identity(), nil)
	changeTask := define("change", changes, strings.Repeat("c", 64), []string{"source-base", "source-head"})
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("e", 64), strings.Repeat("f", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{baseTask, headTask, changeTask})
	check(err)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	check(err)
	_, err = coordinator.Open(ctx, plan, time.UnixMilli(100))
	check(err)
	outputs := map[string]artifact.Artifact{}
	var completion controlplane.TaskCompletion
	for index, task := range []controlplane.TaskDefinition{baseTask, headTask, changeTask} {
		at := time.UnixMilli(int64(101 + 2*index))
		state, err := coordinator.Advance(ctx, plan, at)
		check(err)
		lease, acquired, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
		check(err)
		if !acquired {
			t.Fatalf("%s not acquired", task.Key())
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		check(err)
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		check(err)
		handler := controlplane.TaskHandler(sources)
		if task.Key() == "change" {
			handler = changes
		}
		completion = handler.Execute(ctx, request)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			return completion, outputs["source-base"], outputs["source-head"], artifact.Artifact{}, trees
		}
		_, err = coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond))
		check(err)
		outputs[task.Key()], err = store.Get(ctx, scope, completion.OutputIdentity(), time.UnixMilli(240))
		check(err)
	}
	return completion, outputs["source-base"], outputs["source-head"], outputs["change"], trees
}

// The change of a merge-base input runs from the merge base, so commits the
// base branch gained after the branch point never appear as reverse changes.
func TestChangeRunsFromTheRecordedMergeBase(t *testing.T) {
	requested, head := mergeBaseRevision(t, "1"), mergeBaseRevision(t, "2")
	completion, baseArtifact, headArtifact, changeArtifact, trees := runMergeBaseChange(t, requested, head, head)
	if completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("change failed: %s", completion.Failure())
	}
	result, err := ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		t.Fatal(err)
	}
	var changed []string
	for _, entry := range result.Entries() {
		changed = append(changed, entry.Path()+":"+entry.Kind())
	}
	if result.BaseRevision() != trees.mergeBase || result.HeadRevision() != head || !slices.Equal(changed, []string{"a.go:modified"}) || !slices.Equal(trees.acquired, []string{trees.mergeBase.Digest(), head.Digest()}) {
		t.Fatalf("base=%s head=%s changed=%v acquired=%v", result.BaseRevision().Digest(), result.HeadRevision().Digest(), changed, trees.acquired)
	}
}

// The head task must acquire the head the merge base was resolved for.
func TestChangeRefusesAMergeBaseResolvedForAnotherHead(t *testing.T) {
	requested, head, other := mergeBaseRevision(t, "1"), mergeBaseRevision(t, "2"), mergeBaseRevision(t, "4")
	completion, _, _, _, _ := runMergeBaseChange(t, requested, head, other)
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureInvalidInput {
		t.Fatalf("change accepted a merge base for another head: status=%s failure=%s", completion.Status(), completion.Failure())
	}
}
