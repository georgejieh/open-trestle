package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestForegroundRunnerLocalControlRenewsAndFinalizes(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-foreground-renewal")
	if err != nil {
		t.Fatal(err)
	}
	handler := delayedHandler{identity: strings.Repeat("d", 64), delay: 250 * time.Millisecond}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.HandlerIdentity(), nil, 3, 1000, 30000, true)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := coordinator.Open(ctx, plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	control, err := NewLocalControl(journal, workerSystemClock{}, "foreground-worker")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	renewals := 0
	for _, event := range events {
		if err := event.Validate(); err != nil {
			t.Fatal(err)
		}
		if event.Kind() == controlplane.RunEventTaskLeaseRenewed {
			renewals++
		}
	}
	if renewals == 0 {
		t.Fatal("real foreground LocalControl path did not renew the pending handler lease")
	}
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil || state.Status() != controlplane.ReviewRunActive {
		t.Fatal("worker settlement was confused with journal finalization")
	}
	finalizer, err := controlplane.NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	state, changed, err := finalizer.ReconcileRun(ctx, scope, time.Now().UTC())
	if err != nil || !changed || state.Status() != controlplane.ReviewRunSucceeded || state.OutputIdentity() != strings.Repeat("e", 64) {
		t.Fatal("actual finalizer did not produce the settled task result")
	}
	runtime, ok := state.Task("source")
	if !ok || runtime.Attempts() != 1 || runtime.Status() != controlplane.TaskRuntimeSucceeded {
		t.Fatal("renewal changed task attempt identity")
	}
}
