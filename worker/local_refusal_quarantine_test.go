package worker

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

type steppedLocalClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *steppedLocalClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}
func (c *steppedLocalClock) set(at time.Time) {
	c.mu.Lock()
	c.at = at
	c.mu.Unlock()
}

func localRefusalFixture(t *testing.T, name string) (*controlplane.FileRunJournal, *LocalControl, *steppedLocalClock, audit.ReviewScope, controlplane.TaskDefinition) {
	t.Helper()
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", name)
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 2, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(10_000)); err != nil {
		t.Fatal(err)
	}
	clock := &steppedLocalClock{at: time.UnixMilli(10_001)}
	local, err := NewLocalControl(journal, clock, "worker-refusal")
	if err != nil {
		t.Fatal(err)
	}
	return journal, local, clock, scope, task
}

// A deterministic coordinator refusal appends nothing and must not leave the
// scope quarantined behind an unresolved intent marker.
func TestLocalControlStaleCompletionDoesNotQuarantineScope(t *testing.T) {
	_, local, clock, scope, task := localRefusalFixture(t, "stale-complete")
	lease, err := local.ClaimTask(context.Background(), scope, task.Key(), task.HandlerIdentity())
	if err != nil {
		t.Fatal(err)
	}
	clock.set(lease.ExpiresAt().Add(time.Second))
	completion, _ := controlplane.NewTaskSuccess(strings.Repeat("f", 64))
	if _, err := local.CompleteTask(context.Background(), scope, lease, completion); !errors.Is(err, controlplane.ErrRunTransitionLeaseMismatch) || errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("stale completion err=%v", err)
	}
	if _, err := local.GetRun(context.Background(), scope); err != nil {
		t.Fatalf("stale completion quarantined scope: %v", err)
	}
	if _, err := local.ClaimTask(context.Background(), scope, task.Key(), task.HandlerIdentity()); err != nil {
		t.Fatalf("reclaim after expiry: %v", err)
	}
}

func TestLocalControlClockRegressionDoesNotQuarantineScope(t *testing.T) {
	_, local, clock, scope, _ := localRefusalFixture(t, "clock-regression")
	clock.set(time.UnixMilli(9_000))
	if _, err := local.GetRun(context.Background(), scope); !errors.Is(err, controlplane.ErrRunTransitionSequenceMismatch) || errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("regressed read err=%v", err)
	}
	clock.set(time.UnixMilli(10_002))
	if _, err := local.GetRun(context.Background(), scope); err != nil {
		t.Fatalf("clock regression quarantined scope: %v", err)
	}
}
