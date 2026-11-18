package analysis

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// executeOldCodeScenario uses the real source, change, and analysis handlers.
func executeOldCodeScenario(t *testing.T, scenario string, baseContents, headContents map[string][]byte) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	baseRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	headRevision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapterIdentity, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	adapter := &testSource{identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{
		baseRevision.Identity(): makeSourceResult(t, baseContents),
		headRevision.Identity(): makeSourceResult(t, headContents),
	}}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	scope, _ := audit.NewReviewScope("tenant", "repository", scenario)
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
	if err != nil {
		t.Fatal(err)
	}
	return baseOutput, headOutput, changeOutput, output
}

func TestOldCodeHandlerProducedBranchGoldens(t *testing.T) {
	scenarios := []struct {
		name       string
		base, head map[string][]byte
	}{
		{"produced-v4-go-modified-function", map[string][]byte{"lib/api.go": []byte("package lib\nfunc Exported() int { return 1 }\n"), "lib/api_test.go": []byte("package lib\nfunc TestExported(){ _ = Exported() }\n")}, map[string][]byte{"lib/api.go": []byte("package lib\nfunc Exported() int { return 2 }\n"), "lib/api_test.go": []byte("package lib\nfunc TestExported(){ _ = Exported() }\n")}},
	}
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			base, head, change, output := executeOldCodeScenario(t, s.name, s.base, s.head)
			changed, err := changehandler.ParseResultArtifact(change, base, head)
			if err != nil {
				t.Fatal(err)
			}
			result, err := ParseResultArtifact(output, change, base, head)
			if err != nil {
				t.Fatal(err)
			}
			entries, checks, profile := changed.Entries(), result.Checks(), result.SemanticImpact()
			if len(entries) != 1 || len(checks) != 1 || len(result.Observations()) != 0 || result.SchemaVersion() != 4 {
				t.Fatalf("entries=%d checks=%d observations=%d schema=%d", len(entries), len(checks), len(result.Observations()), result.SchemaVersion())
			}
			switch s.name {
			case "produced-v4-go-modified-function":
				ranges := entries[0].Ranges()
				if entries[0].Path() != "lib/api.go" || entries[0].Kind() != "modified" || len(ranges) != 1 || ranges[0].StartLine() != 2 || ranges[0].EndLine() != 2 || len(result.Items()) != 1 || result.Items()[0].Path() != "lib/api.go" || result.Items()[0].StartLine() != 2 || result.Items()[0].EndLine() != 2 || len(result.Gaps()) != 0 {
					t.Fatalf("go range/coverage mismatch: entry=%#v items=%#v gaps=%#v", entries[0], result.Items(), result.Gaps())
				}
				if checks[0].State() != CheckPassed || !checks[0].Complete() || checks[0].ApplicableFiles() != 1 || checks[0].ApplicableRanges() != 1 || checks[0].CheckedFiles() != 1 || checks[0].CheckedRanges() != 1 || checks[0].MatchCount() != 0 {
					t.Fatal("go check mismatch")
				}
				ds := profile.Declarations()
				if len(ds) != 1 || ds[0].Key() != "func:Exported" || ds[0].Path() != "lib/api.go" || ds[0].Change() != semanticimpact.ChangeModified || !ds[0].Exported() || ds[0].PublicAPIChange() || len(profile.PublicAPIChanges()) != 0 || len(profile.Gaps()) != 0 || profile.GraphSchema() != "open-trestle/semantic-impact/go-ast-graph/v2" {
					t.Fatalf("go semantic mismatch: declarations=%#v gaps=%#v", ds, profile.Gaps())
				}
			}
			frozen := readOldCodeGolden(t, s.name)
			for _, p := range []struct {
				actual   artifact.Artifact
				expected goldenArtifact
			}{{base, frozen.Base}, {head, frozen.Head}, {change, frozen.Change}, {output, frozen.Evidence}} {
				if !bytes.Equal(p.actual.Payload(), p.expected.Payload) || !reflect.DeepEqual(freezeArtifact(p.actual), p.expected) {
					t.Fatalf("%s live artifact mismatch", s.name)
				}
			}
			if result.Identity() != frozen.ResultIdentity || profile.Identity() != frozen.SemanticIdentity {
				t.Fatal("live result/semantic mismatch")
			}
			verifyOldCodeGolden(t, frozen)
		})
	}
}

// A removed file was once analysed as a lone removed_file gap (version 4).
// Those recorded bytes still read back; the live handler now also binds the
// removed base text beside the gap.
func TestOldCodeRemovedFileGapGoldenStillReadsBack(t *testing.T) {
	verifyOldCodeGolden(t, readOldCodeGolden(t, "produced-v4-removed-file-gap"))
	base, head, change, output := executeOldCodeScenario(t, "produced-v4-removed-file-gap", map[string][]byte{"removed.txt": []byte("gone\n")}, map[string][]byte{})
	result, err := ParseResultArtifact(output, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	gaps, removed := result.Gaps(), result.RemovedLines()
	if result.SchemaVersion() != 7 || len(result.Items()) != 0 || len(gaps) != 1 || gaps[0].Reason() != "removed_file" || gaps[0].StartLine() != 0 {
		t.Fatalf("removed file: version=%d gaps=%#v", result.SchemaVersion(), gaps)
	}
	if len(removed) != 1 || removed[0].Path() != "removed.txt" || removed[0].StartLine() != 1 || removed[0].EndLine() != 1 || removed[0].HeadLine() != 0 || removed[0].Digest() != sliceDigest("gone\n") {
		t.Fatalf("removed file text: %#v", removed)
	}
	if check := result.Checks()[0]; check.State() != CheckNotApplicable || check.CheckedRanges() != 0 || len(result.SemanticImpact().Gaps()) != 1 || result.SemanticImpact().Gaps()[0].Reason() != semanticimpact.GapUnsupportedLanguage {
		t.Fatal("removed check or semantic branch mismatch")
	}
}
