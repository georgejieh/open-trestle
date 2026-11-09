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
	if err != nil || set.Outcome() != diagnostics.FinalOutcomeFailed || set.AnalysisResultIdentity() != "" || set.VerifiedSetIdentity() != "" || set.SnapshotIdentity() != "" || !refused || refusal.Reason != diagnostics.ContextRefusalRouteContextInsufficient || refusal.DeclaredContextTokens != 4097 || !set.EvidenceExpired() {
		t.Fatalf("set outcome=%s refusal=%+v expired=%v err=%v", set.Outcome(), refusal, set.EvidenceExpired(), err)
	}
}

// finalProjectorScriptedRun runs keys in plan order, failing a key with its
// listed failure, optionally cancels, then finalizes the run.
func finalProjectorScriptedRun(t *testing.T, run string, keys []string, fail map[string]controlplane.RunFailure, cancel bool) controlplane.ReviewRunState {
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
	for _, key := range keys {
		at = at.Add(time.Second)
		if _, err := coordinator.Advance(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
		task, _ := plan.Task(key)
		lease, claimed, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "fixture", at)
		if err != nil || !claimed {
			t.Fatalf("claim %s: %v", key, err)
		}
		completion, err := controlplane.NewTaskSuccess(digestForTest())
		if failure, failed := fail[key]; failed {
			completion, err = controlplane.NewTaskFailure(failure)
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatalf("complete %s: %v", key, err)
		}
	}
	if cancel {
		if _, err := coordinator.CancelRun(ctx, plan, at.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	finalizer, _ := controlplane.NewRunFinalizer(journal)
	terminal, _, err := finalizer.ReconcileRun(ctx, scope, at.Add(2*time.Second))
	if err != nil || terminal.Status() == controlplane.ReviewRunActive {
		t.Fatalf("terminal=%s err=%v", terminal.Status(), err)
	}
	return terminal
}

// A run first projected after its evidence retention lapsed gets the result
// its journal proves, marked evidence-expired and without any evidence part.
// A succeeded run is never projected as completed without its verified
// evidence; it is inconclusive. The expired artifacts are not read.
func TestLocalFinalProjectorEveryOutcomeAfterRetention(t *testing.T) {
	ctx := context.Background()
	all := []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"}
	upTo := func(key string) []string {
		for i, k := range all {
			if k == key {
				return all[:i+1]
			}
		}
		t.Fatalf("unknown key %s", key)
		return nil
	}
	for _, tc := range []struct {
		name    string
		keys    []string
		fail    map[string]controlplane.RunFailure
		cancel  bool
		outcome diagnostics.FinalOutcome
	}{
		{"completed", all, nil, false, diagnostics.FinalOutcomeInconclusive},
		{"generation-rejected", upTo("candidates"), map[string]controlplane.RunFailure{"candidates": controlplane.RunFailureInternal}, false, diagnostics.FinalOutcomeInconclusive},
		{"generation-lease-exhausted", upTo("candidates"), map[string]controlplane.RunFailure{"candidates": controlplane.RunFailureResourceLimit}, false, diagnostics.FinalOutcomeInconclusive},
		{"verification-lease-exhausted", upTo("verification"), map[string]controlplane.RunFailure{"verification": controlplane.RunFailureResourceLimit}, false, diagnostics.FinalOutcomeInconclusive},
		{"input-terminated", upTo("context"), map[string]controlplane.RunFailure{"context": controlplane.RunFailurePolicy}, false, diagnostics.FinalOutcomeFailed},
		{"canceled-after-context", upTo("context"), nil, true, diagnostics.FinalOutcomeCanceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			terminal := finalProjectorScriptedRun(t, "run-expired-"+tc.name, tc.keys, tc.fail, tc.cancel)
			destination := diagnostics.NewMemoryStore()
			artifacts := &finalCountingArtifacts{Store: expiredArtifacts{}}
			projector, _ := NewLocalFinalDiagnosticProjector(artifacts, destination, digestForTest())
			for range 2 {
				if err := projector.Project(ctx, terminal); err != nil {
					t.Fatal(err)
				}
			}
			set, err := destination.GetDiagnosticSet(ctx, terminal.Plan().Scope())
			if err != nil || set.SchemaVersion() != 7 || set.Outcome() != tc.outcome || !set.EvidenceExpired() || set.AnalysisResultIdentity() != "" || set.VerifiedSetIdentity() != "" || set.SnapshotIdentity() != "" || len(set.Findings()) != 0 {
				t.Fatalf("outcome=%s expired=%v err=%v", set.Outcome(), set.EvidenceExpired(), err)
			}
			if set.Validate() != nil {
				t.Fatal("expired-evidence result does not validate")
			}
		})
	}
	// Any other evidence fault still stops the projection.
	terminal := finalProjectorScriptedRun(t, "run-missing-evidence", all, nil, false)
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	projector, _ := NewLocalFinalDiagnosticProjector(artifacts, diagnostics.NewMemoryStore(), digestForTest())
	if err := projector.Project(ctx, terminal); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("missing evidence: %v", err)
	}
}
