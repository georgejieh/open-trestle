package source

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type sourceAdapter struct {
	identity evidence.SourceAdapterIdentity
	result   scm.SourceAdapterResult
	calls    int
}

func (a *sourceAdapter) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a *sourceAdapter) Acquire(context.Context, evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	a.calls++
	return a.result
}

func sourceFixture(t *testing.T) (evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.SourceAdapterIdentity, scm.SourceAdapterResult) {
	t.Helper()
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	revision, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	adapter, _ := evidence.NewSourceAdapterIdentity(
		evidence.SourceAdapterKindGit, "test-source", "1.0.0",
		[]evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent},
	)
	contents := map[string][]byte{"empty.txt": {}, "src/main.go": []byte("package main\n")}
	files := make([]evidence.RepositoryFile, 0, len(contents))
	for path, content := range contents {
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	manifest, _ := evidence.NewRepositoryManifest(files)
	return repository, revision, adapter, scm.SourceAdapterResult{
		Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone,
		Manifest: manifest, Contents: contents,
	}
}

func taskExecutionRequest(t *testing.T, scope audit.ReviewScope, inputIdentity, handlerIdentity string) controlplane.TaskExecutionRequest {
	t.Helper()
	task, err := controlplane.NewTaskDefinition(
		"source", controlplane.TaskAcquireSource, inputIdentity, handlerIdentity,
		nil, 2, 1000, 30000, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(
		scope, strings.Repeat("b", 64), strings.Repeat("c", 64),
		controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task},
	)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(101))
	lease, _, err := coordinator.ClaimTask(
		context.Background(), plan, task.Key(), handlerIdentity, "worker-a", time.UnixMilli(102),
	)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequest(plan, task, lease)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestHandlerAcquiresAndPersistsExactSourceArtifacts(t *testing.T) {
	repository, revision, adapterIdentity, result := sourceFixture(t)
	inner := &sourceAdapter{identity: adapterIdentity, result: result}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	handler, err := NewHandler(store, inner, fixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	input, err := NewInput(repository, revision, adapterIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(input) != "source acquisition input" || fmt.Sprintf("%#v", input) != "source.Input{<redacted>}" {
		t.Fatalf("input formatting leaked: %v / %#v", input, input)
	}
	inputArtifact, err := NewInputArtifact(
		scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate,
		[]string{strings.Repeat("d", 64)}, time.UnixMilli(100), time.UnixMilli(10000),
	)
	if err != nil {
		t.Fatal(err)
	}
	if created, err := store.Put(context.Background(), inputArtifact, time.UnixMilli(100)); err != nil || !created {
		t.Fatalf("store input = (%v, %v)", created, err)
	}
	request := taskExecutionRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity())
	validated, err := artifact.NewValidatedTaskHandler(
		handler, store, fixedClock{at: time.UnixMilli(201)},
		[]artifact.Kind{artifact.KindTaskInput}, []artifact.Kind{artifact.KindSourceSnapshot},
	)
	if err != nil {
		t.Fatal(err)
	}
	completion := validated.Execute(context.Background(), request)
	if completion.Status() != controlplane.TaskCompletionSucceeded || completion.Validate() != nil || inner.calls != 1 {
		t.Fatalf("completion = %#v, calls = %d", completion, inner.calls)
	}
	output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParseSnapshotArtifact(output)
	if err != nil || snapshot.ManifestIdentity() != result.Manifest.Identity() || snapshot.FileCount() != 2 || snapshot.AcquisitionExecutionIdentity() == "" {
		t.Fatalf("snapshot = (%#v, %v)", snapshot, err)
	}
	if fmt.Sprint(snapshot) != "source snapshot" || fmt.Sprintf("%#v", snapshot) != "source.Snapshot{<redacted>}" {
		t.Fatalf("snapshot formatting leaked: %v / %#v", snapshot, snapshot)
	}
	for _, reference := range snapshot.Files() {
		fileArtifact, err := store.Get(context.Background(), scope, reference.ArtifactIdentity(), time.UnixMilli(201))
		if err != nil {
			t.Fatal(err)
		}
		file, err := ParseFileArtifact(fileArtifact, snapshot, reference)
		if err != nil || file.Path() != reference.Path() || file.Digest() != reference.Digest() || file.SizeBytes() != reference.SizeBytes() {
			t.Fatalf("file = (%#v, %v), reference = %#v", file, err, reference)
		}
		if !bytes.Equal(file.Content(), result.Contents[file.Path()]) {
			t.Fatalf("content mismatch for %s", file.Path())
		}
		copy := file.Content()
		if len(copy) != 0 {
			copy[0] ^= 0xff
			if bytes.Equal(copy, file.Content()) {
				t.Fatal("file content was mutable")
			}
		}
		if fmt.Sprint(file) != "source file" || fmt.Sprintf("%#v", file) != "source.File{<redacted>}" {
			t.Fatalf("file formatting leaked: %v / %#v", file, file)
		}
	}
	if handler.Validate() != nil || fmt.Sprint(handler) != "source acquisition task handler" || fmt.Sprintf("%#v", handler) != "source.Handler{<redacted>}" {
		t.Fatalf("handler validation or formatting failed: %v / %#v", handler, handler)
	}
}

func TestInputAndOutputContractsRejectNoncanonicalOrCrossWiredData(t *testing.T) {
	repository, revision, adapterIdentity, result := sourceFixture(t)
	input, _ := NewInput(repository, revision, adapterIdentity)
	encoded, err := EncodeInput(input)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInput(encoded)
	if err != nil || parsed.Identity() != input.Identity() || !bytes.Equal(encoded, mustEncodeInput(t, parsed)) {
		t.Fatalf("parsed input = (%#v, %v)", parsed, err)
	}
	if _, err := ParseInput(append(encoded, '\n')); err == nil {
		t.Fatal("noncanonical input accepted")
	}

	inner := &sourceAdapter{identity: adapterIdentity, result: result}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	handler, _ := NewHandler(store, inner, fixedClock{at: time.UnixMilli(200)})
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	otherAdapter, _ := evidence.NewSourceAdapterIdentity(
		evidence.SourceAdapterKindGit, "other-source", "1.0.0",
		[]evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent},
	)
	crossWired, _ := NewInput(repository, revision, otherAdapter)
	inputArtifact, _ := NewInputArtifact(
		scope, crossWired, artifact.ClassificationInternal, artifact.ProtectionProcessPrivate,
		[]string{strings.Repeat("d", 64)}, time.UnixMilli(100), time.UnixMilli(10000),
	)
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(100))
	completion := handler.Execute(context.Background(), taskExecutionRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity()))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailurePolicy || inner.calls != 0 {
		t.Fatalf("completion = %#v, calls = %d", completion, inner.calls)
	}
}

func mustEncodeInput(t *testing.T, input Input) []byte {
	t.Helper()
	encoded, err := EncodeInput(input)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestHandlerMapsClosedAcquisitionOutcomes(t *testing.T) {
	repository, revision, adapterIdentity, _ := sourceFixture(t)
	tests := []struct {
		name    string
		outcome evidence.RepositoryAcquisitionOutcome
		reason  evidence.RepositoryAcquisitionReason
		failure controlplane.RunFailure
	}{
		{"authorization", evidence.AcquisitionOutcomeBlocked, evidence.AcquisitionReasonAuthorizationRequired, controlplane.RunFailurePolicy},
		{"policy", evidence.AcquisitionOutcomeBlocked, evidence.AcquisitionReasonPolicyBlocked, controlplane.RunFailurePolicy},
		{"unavailable", evidence.AcquisitionOutcomeBlocked, evidence.AcquisitionReasonAdapterUnavailable, controlplane.RunFailureTransient},
		{"resource", evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonResourceLimit, controlplane.RunFailureResourceLimit},
		{"incomplete", evidence.AcquisitionOutcomeFailed, evidence.AcquisitionReasonArtifactIncomplete, controlplane.RunFailureInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inner := &sourceAdapter{identity: adapterIdentity, result: scm.SourceAdapterResult{Outcome: test.outcome, Reason: test.reason}}
			store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
			handler, _ := NewHandler(store, inner, fixedClock{at: time.UnixMilli(200)})
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
			input, _ := NewInput(repository, revision, adapterIdentity)
			inputArtifact, _ := NewInputArtifact(
				scope, input, artifact.ClassificationInternal, artifact.ProtectionProcessPrivate,
				[]string{strings.Repeat("d", 64)}, time.UnixMilli(100), time.UnixMilli(10000),
			)
			_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(100))
			completion := handler.Execute(context.Background(), taskExecutionRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity()))
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != test.failure || completion.Validate() != nil {
				t.Fatalf("completion = %#v, failure=%s", completion, completion.Failure())
			}
		})
	}
}

func TestHandlerRejectsMissingOrExpiredInputBeforeAdapter(t *testing.T) {
	_, _, adapterIdentity, result := sourceFixture(t)
	inner := &sourceAdapter{identity: adapterIdentity, result: result}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	handler, _ := NewHandler(store, inner, fixedClock{at: time.UnixMilli(200)})
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	completion := handler.Execute(context.Background(), taskExecutionRequest(t, scope, strings.Repeat("e", 64), handler.HandlerIdentity()))
	if completion.Status() != controlplane.TaskCompletionFailed || completion.Failure() != controlplane.RunFailureInvalidInput || inner.calls != 0 {
		t.Fatalf("completion = %#v, calls = %d", completion, inner.calls)
	}
}

var _ controlplane.TaskHandler = (*Handler)(nil)
