package worker

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestLocalControlUnclaimedAdvanceRetainsIntentAcrossRestart(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "unclaimed-advance")
	first, err := controlplane.NewTaskDefinition("first", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 2, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	dependent, err := controlplane.NewTaskDefinition("dependent", controlplane.TaskBuildChange, strings.Repeat("e", 64), strings.Repeat("d", 64), []string{"first"}, 2, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{first, dependent})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coordinator.Open(ctx, plan, time.UnixMilli(10000)); err != nil {
		t.Fatal(err)
	}
	before, found, err := journal.Head(ctx, scope)
	if err != nil || !found {
		t.Fatalf("head found=%t err=%v", found, err)
	}
	local, err := NewLocalControl(journal, &steppedLocalClock{at: time.UnixMilli(10001)}, "worker-claim")
	if err != nil {
		t.Fatal(err)
	}
	_, err = local.ClaimTask(ctx, scope, dependent.Key(), dependent.HandlerIdentity())
	if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("unclaimed advance cleared unverified intent: err=%v", err)
	}
	// The availability append is real even though the requested task was not leased.
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil || state.HeadIdentity() == before.Identity() {
		t.Fatalf("availability append not observed: err=%v state=%s before=%s", err, state.HeadIdentity(), before.Identity())
	}
	if _, err = local.GetRun(ctx, scope); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("quarantine not retained: err=%v", err)
	}
	if err = journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
			t.Fatal(err)
		}
		return
	}
	defer reopened.Close()
	resumed, err := NewLocalControl(reopened, &steppedLocalClock{at: time.UnixMilli(10001)}, "worker-claim")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resumed.GetRun(ctx, scope); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("restart lost unresolved claim intent: err=%v", err)
	}
}
