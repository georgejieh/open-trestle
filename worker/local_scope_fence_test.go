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

func TestLocalControlFileJournalGetRunRefusesActiveScope(t *testing.T) {
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "scope-gate")
	if err != nil {
		t.Fatal(err)
	}
	handler := &transientOnceHandler{}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	plan := workerPlan(t, scope, catalog)
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalControl(journal, workerSystemClock{}, "worker-gated")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- journal.WithScopeGate(context.Background(), scope, func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	waiting, stop, err := journal.WatchEffectGateContention()
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer stop()
	workerDone := make(chan error, 1)
	go func() { _, err := local.GetRun(context.Background(), scope); workerDone <- err }()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("worker did not wait on gate")
	}
	select {
	case err := <-workerDone:
		close(release)
		t.Fatalf("worker completed inside section: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-workerDone; err != nil {
		t.Fatal(err)
	}
}

func TestLocalControlFileJournalClaimAndConflictPreserveScope(t *testing.T) {
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "scope-claim")
	if err != nil {
		t.Fatal(err)
	}
	handler := &transientOnceHandler{}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	plan := workerPlan(t, scope, catalog)
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalControl(journal, workerSystemClock{}, "worker-gated")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.GetRun(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	task := plan.Tasks()[0]
	lease, err := local.ClaimTask(context.Background(), scope, task.Key(), task.HandlerIdentity())
	if err != nil || lease.EventIdentity() == "" {
		t.Fatalf("claim=%v %v", lease, err)
	}
	head, found, err := journal.Head(context.Background(), scope)
	if err != nil || !found || head.Identity() != lease.EventIdentity() {
		t.Fatalf("claim event not persisted: found=%t err=%v", found, err)
	}
	if _, err := local.ClaimTask(context.Background(), scope, task.Key(), task.HandlerIdentity()); err == nil {
		t.Fatal("second claim acquired")
	}
	if _, err := local.GetRun(context.Background(), scope); err != nil {
		t.Fatalf("conflict quarantined scope=%v", err)
	}
}

func TestLocalControlFileJournalRenewCompleteReadback(t *testing.T) {
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "scope-complete")
	if err != nil {
		t.Fatal(err)
	}
	handler := &transientOnceHandler{}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	plan := workerPlan(t, scope, catalog)
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	local, err := NewLocalControl(journal, workerSystemClock{}, "worker-complete")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := local.GetRun(context.Background(), scope); err != nil {
		t.Fatal(err)
	}
	task := plan.Tasks()[0]
	lease, err := local.ClaimTask(context.Background(), scope, task.Key(), task.HandlerIdentity())
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := local.RenewTaskLease(context.Background(), scope, lease)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := controlplane.NewTaskSuccess(strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := local.CompleteTask(context.Background(), scope, renewed, completion)
	if err != nil {
		t.Fatal(err)
	}
	observed, found, err := journal.Head(context.Background(), scope)
	if err != nil || !found || observed.Identity() != receipt.HeadIdentity() {
		t.Fatalf("completion journal=%t %v", found, err)
	}
}
