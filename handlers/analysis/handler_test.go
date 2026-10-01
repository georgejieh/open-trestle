package analysis

import (
	"bytes"
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
			t.Fatalf("%s completion=%#v", task.Key(), completion)
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
	zeroMatch := result
	zeroMatch.checks = []DeterministicCheck{mustDeterministicCheck(t, result.ChangeIdentity(), CheckPassed, 1, 1, 1, 1, 0)}
	zeroMatch.observations = nil
	zeroMatch.identity = deriveIdentity(zeroMatch)
	zeroPayload, zeroErr := encodeResult(zeroMatch)
	if zeroErr != nil || !bytes.Contains(zeroPayload, []byte(`"observations":[]`)) {
		t.Fatalf("zero-match v4 payload=%s err=%v", zeroPayload, zeroErr)
	}
	zeroArtifact, _ := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", output.Classification(), artifact.OriginDeterministicTool, output.Protection(), output.Provenance(), zeroPayload, output.CreatedAt(), output.ExpiresAt())
	if parsed, parseErr := ParseResultArtifact(zeroArtifact, changeOutput, baseOutput, headOutput); parseErr != nil || parsed.SchemaVersion() != 4 || len(parsed.Observations()) != 0 {
		t.Fatalf("zero-match v4=(%#v,%v)", parsed, parseErr)
	}
	nullPayload := bytes.Replace(zeroPayload, []byte(`"observations":[]`), []byte(`"observations":null`), 1)
	nullArtifact, _ := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", output.Classification(), artifact.OriginDeterministicTool, output.Protection(), output.Provenance(), nullPayload, output.CreatedAt(), output.ExpiresAt())
	if parsed, parseErr := ParseResultArtifact(nullArtifact, changeOutput, baseOutput, headOutput); parseErr == nil || parsed.Identity() != "" {
		t.Fatalf("schema-invalid null observations accepted: %#v", parsed)
	}
	projected, err := diagnosticStore.GetDiagnosticSet(context.Background(), scope)
	if err != nil || projected.SchemaVersion() != 6 || projected.AnalysisResultIdentity() != result.Identity() || len(projected.Findings()) != 0 || len(projected.DeterministicObservations()) != 1 || projected.DeterministicObservations()[0].SourceIdentity() != observations[0].Identity() {
		t.Fatalf("projected diagnostics=%#v err=%v", projected, err)
	}
	legacyV3 := result
	legacyV3.schemaVersion = 3
	legacyV3.observations = nil
	legacyV3.identity = deriveIdentity(legacyV3)
	legacyV3Payload, err := encodeResult(legacyV3)
	if err != nil || bytes.Contains(legacyV3Payload, []byte(`"observations"`)) {
		t.Fatalf("legacy v3 identity=%s payload=%s err=%v", legacyV3.Identity(), legacyV3Payload, err)
	}
	legacyV3Artifact, _ := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", output.Classification(), artifact.OriginDeterministicTool, output.Protection(), output.Provenance(), legacyV3Payload, output.CreatedAt(), output.ExpiresAt())
	legacyV3Parsed, err := ParseResultArtifact(legacyV3Artifact, changeOutput, baseOutput, headOutput)
	if err != nil || legacyV3Parsed.SchemaVersion() != 3 || len(legacyV3Parsed.Observations()) != 0 || legacyV3Parsed.Identity() != legacyV3.Identity() {
		t.Fatalf("legacy v3=(%#v,%v)", legacyV3Parsed, err)
	}
	legacy := result
	legacy.schemaVersion = 2
	legacy.checks = nil
	legacy.observations = nil
	legacy.identity = deriveIdentity(legacy)
	legacyPayload, err := encodeResult(legacy)
	if legacy.Identity() != "9b51d2bfc59feabac5deb4f8b49f40ae89a7cc6b969fe07542b4a8a6b19b88a1" || bytes.Contains(legacyPayload, []byte(`"checks"`)) {
		t.Fatalf("legacy identity=%s payload=%s", legacy.Identity(), legacyPayload)
	}
	if err != nil {
		t.Fatal(err)
	}
	legacyArtifact, err := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", output.Classification(), artifact.OriginDeterministicTool, output.Protection(), output.Provenance(), legacyPayload, output.CreatedAt(), output.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	legacyParsed, err := ParseResultArtifact(legacyArtifact, changeOutput, baseOutput, headOutput)
	if err != nil || legacyParsed.SchemaVersion() != 2 || len(legacyParsed.Checks()) != 0 || legacyParsed.Identity() != legacy.Identity() {
		t.Fatalf("legacy=(%#v,%v)", legacyParsed, err)
	}
	forged := result
	forged.checks = append([]DeterministicCheck(nil), result.checks...)
	forged.checks[0].matches++
	forged.identity = deriveIdentity(forged)
	forgedPayload, err := encodeResult(forged)
	if err != nil {
		t.Fatal(err)
	}
	forgedArtifact, err := artifact.New(scope, artifact.KindDeterministicEvidence, "application/json", output.Classification(), artifact.OriginDeterministicTool, output.Protection(), output.Provenance(), forgedPayload, output.CreatedAt(), output.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseResultArtifact(forgedArtifact, changeOutput, baseOutput, headOutput); err == nil || parsed.Identity() != "" {
		t.Fatalf("forged=(%#v,%v)", parsed, err)
	}
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

func mustDeterministicCheck(t *testing.T, change string, state DeterministicCheckState, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32) DeterministicCheck {
	t.Helper()
	check, err := NewDeterministicCheck(change, state, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches)
	if err != nil {
		t.Fatal(err)
	}
	return check
}

func TestDiagnosticWriteFailureClassifiesDiagnosticStoreCapacity(t *testing.T) {
	if got := diagnosticWriteFailure(context.Background(), diagnostics.ErrStoreCapacity); got != controlplane.RunFailureResourceLimit {
		t.Fatalf("diagnostic store capacity mapped to %s", got)
	}
}
