package worker

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// A local run control schedules a rate-limited retry at the provider's
// Retry-After, never past the run deadline, on the clock it was given.
func TestLocalRunControlBoundsARateLimitedRetryByTheRunDeadline(t *testing.T) {
	ctx := context.Background()
	start := time.UnixMilli(1_000_000)
	for _, test := range []struct {
		name     string
		deadline time.Time
		want     time.Duration
	}{
		{"before the deadline", start.Add(time.Minute), 7 * time.Second},
		{"past the deadline", start.Add(3 * time.Second), 3 * time.Second},
		{"no deadline", time.Time{}, 7 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "worker-run-deadline")
			if err != nil {
				t.Fatal(err)
			}
			chain := []controlplane.TaskDefinition{}
			for index, step := range []struct {
				key  string
				kind controlplane.TaskKind
			}{{"source", controlplane.TaskAcquireSource}, {"change", controlplane.TaskBuildChange}, {"context", controlplane.TaskAssembleContext}, {"candidates", controlplane.TaskGenerateCandidates}} {
				var dependencies []string
				if index > 0 {
					dependencies = []string{chain[index-1].Key()}
				}
				definition, err := controlplane.NewTaskDefinition(step.key, step.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), dependencies, 3, 1_000, 30_000, true)
				if err != nil {
					t.Fatal(err)
				}
				chain = append(chain, definition)
			}
			task := chain[3]
			plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, chain)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { journal.Close() })
			coordinator, err := controlplane.NewCoordinator(journal)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Open(ctx, plan, start.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			for index, before := range chain[:3] {
				at := start.Add(time.Duration(index-3) * 100 * time.Millisecond)
				lease, acquired, err := coordinator.ClaimTask(ctx, plan, before.Key(), before.HandlerIdentity(), "worker", at)
				if err != nil || !acquired {
					t.Fatalf("claim %s: %v", before.Key(), err)
				}
				success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
				if _, err := coordinator.CompleteTask(ctx, plan, lease, success, at.Add(time.Millisecond)); err != nil {
					t.Fatalf("complete %s: %v", before.Key(), err)
				}
			}
			control, err := NewLocalRunControl(journal, terminalReadClock{start}, "worker-deadline", test.deadline)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := control.ClaimTask(ctx, scope, task.Key(), task.HandlerIdentity())
			if err != nil {
				t.Fatal(err)
			}
			completion, err := controlplane.NewRateLimitedModelTaskFailure(7_000, plan, task)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := control.CompleteTask(ctx, scope, lease, completion)
			if err != nil {
				t.Fatal(err)
			}
			recorded, _ := receipt.Task("candidates")
			if got := recorded.RetryAt().Sub(start); recorded.FailureReason() != controlplane.TaskFailureReasonProviderRateLimited || got != test.want {
				t.Fatalf("retry in %v reason %s, want %v", got, recorded.FailureReason(), test.want)
			}
		})
	}
	if _, err := NewLocalRunControl(controlplane.NewMemoryRunJournal(), terminalReadClock{start}, "worker-deadline", time.UnixMilli(0)); err == nil {
		t.Fatal("a deadline before the run epoch was accepted")
	}
}
