package tui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// A refused source acquisition shows its recorded reason beside the run
// disposition, so an operator can tell no-merge-base from a transport failure.
func TestRunShowsSourceFailureReason(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-reason")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 1, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(1000)); err != nil {
		t.Fatal(err)
	}
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "source-base", task.HandlerIdentity(), "worker", time.UnixMilli(1001))
	if err != nil || !ok {
		t.Fatalf("claim: %v", err)
	}
	completion, err := controlplane.NewSourceTaskFailureWithReason(controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNoMergeBase, plan, task)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(1002)); err != nil {
		t.Fatal(err)
	}
	finalizer, err := controlplane.NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	state, terminal, err := finalizer.ReconcileRun(ctx, scope, time.UnixMilli(1003))
	if err != nil || !terminal {
		t.Fatalf("finalize terminal=%t: %v", terminal, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view, err := New(&fakeService{receipt: receipt, diagnosticErr: errors.New("no diagnostics")}, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Run(ctx); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, want := range []string{"Disposition policy", "Reason      source-base: no_merge_base (the requested base and the head share no history)"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q in:\n%s", want, rendered)
		}
	}
}
