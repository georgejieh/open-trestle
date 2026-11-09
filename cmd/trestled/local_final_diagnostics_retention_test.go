package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

// expiredArtifacts reports every artifact as past its retention.
type expiredArtifacts struct{ artifact.Store }

func (expiredArtifacts) Get(context.Context, audit.ReviewScope, string, time.Time) (artifact.Artifact, error) {
	return artifact.Artifact{}, artifact.ErrArtifactExpired
}

// finalProjectorRefusedRun records a full run whose context task was refused
// for reason, then finalizes it.
func finalProjectorRefusedRun(t *testing.T, run string, reason controlplane.TaskFailureReason, shortfall controlplane.TaskFailureContextShortfall) controlplane.ReviewRunState {
	t.Helper()
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", run)
	plan := finalProjectorPlan(t, scope, digestForTest())
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	at := time.Now().UTC()
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context"} {
		at = at.Add(time.Second)
		if _, err := coordinator.Advance(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
		task, _ := plan.Task(key)
		lease, claimed, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "fixture", at)
		if err != nil || !claimed {
			t.Fatalf("claim %s: %v", key, err)
		}
		var completion controlplane.TaskCompletion
		if key == "context" && reason != 0 {
			completion, err = controlplane.NewContextTaskRefusal(reason, shortfall, plan, task)
		} else if key == "context" {
			completion, err = controlplane.NewTaskFailure(controlplane.RunFailurePolicy)
		} else {
			completion, err = controlplane.NewTaskSuccess(digestForTest())
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatalf("complete %s: %v", key, err)
		}
	}
	finalizer, _ := controlplane.NewRunFinalizer(journal)
	terminal, _, err := finalizer.ReconcileRun(ctx, scope, at.Add(time.Second))
	if err != nil || terminal.Status() != controlplane.ReviewRunFailed {
		t.Fatalf("terminal=%s err=%v", terminal.Status(), err)
	}
	return terminal
}

// A refused run finalized after its evidence retention lapsed still gets its
// failed result with the recorded refusal; the expired deterministic evidence
// is reported unavailable instead of stopping the supervisor.
func TestLocalFinalProjectorRefusedRunAfterRetention(t *testing.T) {
	ctx := context.Background()
	shortfall := controlplane.TaskFailureContextShortfall{RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097}
	terminal := finalProjectorRefusedRun(t, "run-refused-expired", controlplane.TaskFailureReasonRouteContextInsufficient, shortfall)
	destination := diagnostics.NewMemoryStore()
	projector, _ := NewLocalFinalDiagnosticProjector(expiredArtifacts{}, destination, digestForTest())
	for range 2 {
		if err := projector.Project(ctx, terminal); err != nil {
			t.Fatal(err)
		}
	}
	set, err := destination.GetDiagnosticSet(ctx, terminal.Plan().Scope())
	refusal, refused := set.ContextRefusal()
	if err != nil || set.Outcome() != diagnostics.FinalOutcomeFailed || set.AnalysisResultIdentity() != "" || set.VerifiedSetIdentity() != "" || set.SnapshotIdentity() != "" || !refused || refusal.Reason != diagnostics.ContextRefusalRouteContextInsufficient || refusal.DeclaredContextTokens != 4097 {
		t.Fatalf("set outcome=%s refusal=%+v err=%v", set.Outcome(), refusal, err)
	}
	// Other failed runs keep refusing to invent a result from expired evidence.
	unreasoned := finalProjectorRefusedRun(t, "run-failed-expired", 0, controlplane.TaskFailureContextShortfall{})
	if err := projector.Project(ctx, unreasoned); !errors.Is(err, artifact.ErrArtifactExpired) {
		t.Fatalf("unrefused failed run with expired evidence: %v", err)
	}
}
