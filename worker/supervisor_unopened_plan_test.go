package worker

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestRepositorySupervisorSkipsPlanSavedBeforeItsRunOpens(t *testing.T) {
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "saved-unopened")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{&transientOnceHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	plan := workerPlan(t, scope, catalog)
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	supervisor, err := NewRepositorySupervisor(journal, catalog, RepositorySupervisorOptions{TenantID: "tenant-a", RepositoryIDs: []string{"repo-a"}, WorkerIdentity: "unopened-worker", PollInterval: time.Second, RenewalInterval: 50 * time.Millisecond, ExecutionTimeout: time.Second, Clock: workerSystemClock{}, FinalizeSettled: true})
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := supervisor.RunOnce(context.Background()); err != nil || worked {
		t.Fatalf("RunOnce() on a saved but unopened plan=(%t,%v)", worked, err)
	}
	// The pass left no scope intent behind, so the run can still open.
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatalf("Open() after the pass=%v", err)
	}
	if _, err := supervisor.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce() after Open=%v", err)
	}
}
