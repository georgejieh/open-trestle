package worker

import (
	"context"
	"os"
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

type cancelingSourceAdapter struct {
	identity evidence.SourceAdapterIdentity
	root     *os.Root
	entered  chan struct{}
	drained  chan bool
}

func (a *cancelingSourceAdapter) Identity() evidence.SourceAdapterIdentity { return a.identity }
func (a *cancelingSourceAdapter) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	close(a.entered)
	<-ctx.Done()
	_, err := a.root.Stat(".")
	a.drained <- err == nil && request.SourceAdapterIdentity() == a.identity.Identity()
	return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonAdapterFailure}
}

func TestForegroundRunnerPropagatesCallerCancellationThroughSourceHandler(t *testing.T) {
	objects, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	identity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "canceling-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &cancelingSourceAdapter{identity: identity, root: objects, entered: make(chan struct{}), drained: make(chan bool, 1)}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 8)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "source-cancel")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"team"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	if err != nil {
		t.Fatal(err)
	}
	input, err := sourcehandler.NewInput(repository, revision, identity)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	inputArtifact, err := sourcehandler.NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), inputArtifact, at); err != nil {
		t.Fatal(err)
	}
	handler, err := sourcehandler.NewHandler(store, adapter, workerSystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputArtifact.Identity(), handler.HandlerIdentity(), nil, 3, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, at); err != nil {
		t.Fatal(err)
	}
	control, err := NewLocalControl(journal, workerSystemClock{}, "source-worker")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: time.Second, ExecutionTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	select {
	case <-adapter.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("real source handler did not call adapter")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("source cancellation did not return")
	}
	wait, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := runner.Wait(wait); err != nil {
		t.Fatal(err)
	}
	select {
	case owned := <-adapter.drained:
		if !owned {
			t.Fatal("source root or adapter authority was lost during cancellation")
		}
	default:
		t.Fatal("source adapter did not drain")
	}
	state, err := coordinator.CancelRun(wait, plan, time.Now().UTC())
	if err != nil || state.Status() != controlplane.ReviewRunCanceled {
		t.Fatal("source cancellation did not finalize local state")
	}
}
