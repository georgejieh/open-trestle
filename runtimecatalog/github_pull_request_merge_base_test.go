package runtimecatalog_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/webhook"
)

// mergeBaseSource serves exact commit trees, records every acquired commit,
// and answers merge-base questions the way the forge compare read would.
type mergeBaseSource struct {
	t          *testing.T
	identity   evidence.SourceAdapterIdentity
	trees      map[string]map[string]string
	mergeBases map[string]string
	acquired   []string
}

func (s *mergeBaseSource) Identity() evidence.SourceAdapterIdentity { return s.identity }
func (s *mergeBaseSource) Acquire(_ context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	digest := request.Revision().Digest()
	s.acquired = append(s.acquired, digest)
	tree, ok := s.trees[digest]
	if !ok {
		return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonArtifactIncomplete}
	}
	contents := make(map[string][]byte, len(tree))
	files := make([]evidence.RepositoryFile, 0, len(tree))
	for path, content := range tree {
		contents[path] = []byte(content)
		file, err := evidence.NewRepositoryFile(path, contents[path])
		requiredCheck(s.t, err)
		files = append(files, file)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	requiredCheck(s.t, err)
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
}
func (s *mergeBaseSource) ResolveMergeBase(_ context.Context, request scm.MergeBaseRequest) scm.MergeBaseResult {
	merge, ok := s.mergeBases[request.Base().Digest()+"..."+request.Head().Digest()]
	if !ok {
		return scm.MergeBaseResult{Outcome: scm.MergeBaseNone, Reason: evidence.AcquisitionReasonNone}
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, merge)
	requiredCheck(s.t, err)
	return scm.MergeBaseResult{Outcome: scm.MergeBaseResolved, MergeBase: revision, Reason: evidence.AcquisitionReasonNone}
}

const (
	mergeBaseCommit = "3333333333333333333333333333333333333333"
	baseTipCommit   = "1111111111111111111111111111111111111111"
	headCommit      = "2222222222222222222222222222222222222222"
	rebasedCommit   = "4444444444444444444444444444444444444444"
	unrelatedCommit = "5555555555555555555555555555555555555555"
)

type mergeBaseRun struct {
	source  *mergeBaseSource
	outputs map[string]artifact.Artifact
	state   controlplane.ReviewRunState
	failed  controlplane.TaskCompletion
}

// runGitHubPullRequestSource plans one pull_request delivery with the daemon's
// prepared planner and runs its source and change tasks with the real handlers.
func runGitHubPullRequestSource(t *testing.T, base, head string) mergeBaseRun {
	t.Helper()
	ctx := context.Background()
	before := "package p\nfunc Changed(x int) int { return x }\n"
	after := "package p\nfunc Changed(x int) int { return x + 1 }\n"
	baseOnly := "package p\nfunc AddedOnBase() {}\n"
	adapterIdentity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	requiredCheck(t, err)
	source := &mergeBaseSource{t: t, identity: adapterIdentity, trees: map[string]map[string]string{
		mergeBaseCommit: {"a.go": before},
		baseTipCommit:   {"a.go": before, "base_only.go": baseOnly},
		headCommit:      {"a.go": after},
		rebasedCommit:   {"a.go": after, "base_only.go": baseOnly},
		unrelatedCommit: {"other.go": "package other\n"},
	}, mergeBases: map[string]string{
		baseTipCommit + "..." + headCommit:      mergeBaseCommit,
		baseTipCommit + "..." + rebasedCommit:   baseTipCommit,
		baseTipCommit + "..." + mergeBaseCommit: mergeBaseCommit,
	}}
	clock := &requiredClock{at: time.UnixMilli(1000)}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	requiredCheck(t, err)
	sources, err := sourcehandler.NewHandler(store, source, clock)
	requiredCheck(t, err)
	changes, err := changehandler.NewHandler(store, clock)
	requiredCheck(t, err)
	kinds := []controlplane.TaskKind{controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication}
	bindings := []githubwebhook.TaskHandlerBinding{{Kind: controlplane.TaskAcquireSource, HandlerIdentity: sources.HandlerIdentity()}, {Kind: controlplane.TaskBuildChange, HandlerIdentity: changes.HandlerIdentity()}}
	for index, kind := range kinds {
		bindings = append(bindings, githubwebhook.TaskHandlerBinding{Kind: kind, HandlerIdentity: fmt.Sprintf("%064x", index+1)})
	}
	planner, err := githubwebhook.NewPreparedPullRequestPlanner("github.com", "owner/repository", requiredDigest("policy"), "github-review", controlplane.ReviewRunAdvisory, bindings, adapterIdentity, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, time.Hour)
	requiredCheck(t, err)
	scope, err := webhook.NewRepositoryScope("tenant-a", "repo-a")
	requiredCheck(t, err)
	payload := []byte(`{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"` + base + `","repo":{"full_name":"owner/repository"}},"head":{"sha":"` + head + `","repo":{"full_name":"owner/repository"}}}}`)
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-merge-base", "pull_request", "synchronize", requiredDigest("approval"), payload, clock.Now())
	requiredCheck(t, err)
	stored, _, err := webhook.NewMemoryStore().Put(ctx, delivery, clock.Now())
	requiredCheck(t, err)
	plan, inputs, err := planner.Prepare(ctx, stored)
	requiredCheck(t, err)
	for _, input := range inputs {
		_, err := store.Put(ctx, input, clock.Now())
		requiredCheck(t, err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	requiredCheck(t, err)
	_, err = coordinator.Open(ctx, plan, clock.step())
	requiredCheck(t, err)
	run := mergeBaseRun{source: source, outputs: map[string]artifact.Artifact{}}
	for _, key := range []string{"source-base", "source-head", "change"} {
		task, _ := plan.Task(key)
		state, err := coordinator.Advance(ctx, plan, clock.step())
		requiredCheck(t, err)
		lease, acquired, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", clock.step())
		requiredCheck(t, err)
		if !acquired {
			t.Fatalf("%s lease not acquired", key)
		}
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		requiredCheck(t, err)
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
		requiredCheck(t, err)
		handler := controlplane.TaskHandler(sources)
		if key == "change" {
			handler = changes
		}
		completion := handler.Execute(ctx, request)
		run.state, err = coordinator.CompleteTask(ctx, plan, lease, completion, clock.step())
		requiredCheck(t, err)
		if completion.Status() != controlplane.TaskCompletionSucceeded {
			run.failed = completion
			return run
		}
		run.outputs[key], err = store.Get(ctx, plan.Scope(), completion.OutputIdentity(), clock.Now())
		requiredCheck(t, err)
	}
	return run
}

func (r mergeBaseRun) change(t *testing.T) (evidence.RevisionIdentity, []string) {
	t.Helper()
	if r.failed.Status() == controlplane.TaskCompletionFailed {
		t.Fatalf("run failed: %s %s", r.failed.Failure(), r.failed.FailureReason())
	}
	change, err := changehandler.ParseResultArtifact(r.outputs["change"], r.outputs["source-base"], r.outputs["source-head"])
	requiredCheck(t, err)
	var changed []string
	for _, entry := range change.Entries() {
		changed = append(changed, entry.Path()+":"+entry.Kind())
	}
	return change.BaseRevision(), changed
}

// GitHub presents a pull request as merge-base...head. When the base branch
// moved after the branch point, pull_request.base.sha is ahead of the merge
// base, and reviewing base.sha..head would report the base branch's newer
// commits as reverse changes the pull request never made.
func TestGitHubPullRequestReviewStartsAtTheMergeBase(t *testing.T) {
	run := runGitHubPullRequestSource(t, baseTipCommit, headCommit)
	base, changed := run.change(t)
	if base.Digest() != mergeBaseCommit || !slices.Equal(run.source.acquired, []string{mergeBaseCommit, headCommit}) || !slices.Equal(changed, []string{"a.go:modified"}) {
		t.Fatalf("review base=%s acquired=%v changed=%v; want base %s and only a.go modified", base.Digest()[:7], abbreviate(run.source.acquired), changed, mergeBaseCommit[:7])
	}
	snapshot, err := sourcehandler.ParseSnapshotArtifact(run.outputs["source-base"])
	requiredCheck(t, err)
	derivation, derived := snapshot.Derivation()
	requested, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, baseTipCommit)
	if !derived || derivation.RequestedBaseIdentity() != requested.Identity() || derivation.MergeBase() != base {
		t.Fatal("base snapshot did not record the requested base and derived merge base")
	}
}

// A force-pushed head rebased onto the current base tip has that tip as its
// merge base, so the review covers only the head's own change.
func TestGitHubPullRequestReviewOfARebasedHead(t *testing.T) {
	run := runGitHubPullRequestSource(t, baseTipCommit, rebasedCommit)
	base, changed := run.change(t)
	if base.Digest() != baseTipCommit || !slices.Equal(changed, []string{"a.go:modified"}) {
		t.Fatalf("rebased review base=%s changed=%v", base.Digest()[:7], changed)
	}
}

// Refusals are explicit failures with a recorded reason, never a silent
// fallback to reviewing pull_request.base.sha.
func TestGitHubPullRequestReviewRefusesWithoutAReviewableMergeBase(t *testing.T) {
	for _, c := range []struct {
		name, base, head string
		reason           controlplane.TaskFailureReason
	}{
		{"unrelated histories", baseTipCommit, unrelatedCommit, controlplane.TaskFailureReasonNoMergeBase},
		{"head already in base", baseTipCommit, mergeBaseCommit, controlplane.TaskFailureReasonNothingToReview},
		{"base equals head", headCommit, headCommit, controlplane.TaskFailureReasonNothingToReview},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := runGitHubPullRequestSource(t, c.base, c.head)
			task, _ := run.state.Task("source-base")
			if run.failed.FailureReason() != c.reason || task.Status() != controlplane.TaskRuntimeFailed || task.Failure() != controlplane.RunFailurePolicy || task.FailureReason() != c.reason || len(run.source.acquired) != 0 {
				t.Fatalf("status=%s failure=%s reason=%s acquired=%v", task.Status(), task.Failure(), task.FailureReason(), run.source.acquired)
			}
		})
	}
}

func abbreviate(values []string) []string {
	short := make([]string, len(values))
	for index, value := range values {
		short[index] = value[:7]
	}
	return short
}
