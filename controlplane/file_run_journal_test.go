package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileRunJournalPersistsPrivateCanonicalStream(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	if err := journal.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	opened := runOpenedEventFixture(t, plan)
	if err := journal.Append(context.Background(), "", opened); err != nil {
		t.Fatal(err)
	}
	available := taskAvailableEventFixture(t, plan, "source", 2, opened.Identity())
	if err := journal.Append(context.Background(), opened.Identity(), available); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileRunJournal(root); !errors.Is(err, ErrRunJournalLocked) {
		t.Fatalf("second writer=%v", err)
	}
	information, _ := os.Stat(root)
	if information.Mode().Perm() != 0o700 {
		t.Fatalf("root mode=%o", information.Mode().Perm())
	}
	streamInformation, _ := os.Stat(journal.streamPath(plan.Scope()))
	if streamInformation.Mode().Perm() != 0o600 {
		t.Fatalf("stream mode=%o", streamInformation.Mode().Perm())
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loadedPlan, found, err := reopened.LoadPlan(context.Background(), plan.Scope())
	if err != nil || !found || loadedPlan.Identity() != plan.Identity() {
		t.Fatalf("loaded plan=(%#v,%t,%v)", loadedPlan, found, err)
	}
	plans, err := reopened.ListPlans(context.Background(), plan.Scope().TenantID(), plan.Scope().RepositoryID(), "", 10)
	if err != nil || len(plans) != 1 || plans[0].Identity() != plan.Identity() {
		t.Fatalf("listed plans=(%#v,%v)", plans, err)
	}
	planInformation, _ := os.Stat(reopened.planPath(plan.Scope()))
	if planInformation.Mode().Perm() != 0o600 {
		t.Fatalf("plan mode=%o", planInformation.Mode().Perm())
	}
	events, err := reopened.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 2 || events[1].Identity() != available.Identity() {
		t.Fatalf("events=(%#v,%v)", events, err)
	}
	if err := reopened.Append(context.Background(), opened.Identity(), available); err != nil {
		t.Fatalf("idempotent append=%v", err)
	}
}
func TestFileRunJournalRejectsConflictClosedAndCorruptStream(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, _ := NewFileRunJournal(root)
	plan := runPlanFixture(t)
	opened := runOpenedEventFixture(t, plan)
	_ = journal.Append(context.Background(), "", opened)
	available := taskAvailableEventFixture(t, plan, "source", 2, opened.Identity())
	if err := journal.Append(context.Background(), "", available); !errors.Is(err, ErrRunJournalHeadConflict) {
		t.Fatalf("head conflict=%v", err)
	}
	streamPath := journal.streamPath(plan.Scope())
	_ = journal.Close()
	if err := journal.Append(context.Background(), opened.Identity(), available); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("closed append=%v", err)
	}
	content, _ := os.ReadFile(streamPath)
	if err := os.WriteFile(streamPath, content[:len(content)-1], 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, _, err := reopened.Head(context.Background(), plan.Scope()); !errors.Is(err, ErrCorruptRunJournalStream) {
		t.Fatalf("corrupt head=%v", err)
	}
}
func TestFileRunJournalRejectsSymlinkRootAndStream(t *testing.T) {
	temporary := t.TempDir()
	target := filepath.Join(temporary, "target")
	_ = os.Mkdir(target, 0o700)
	link := filepath.Join(temporary, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if journal, err := NewFileRunJournal(link); !errors.Is(err, ErrInvalidRunJournalRoot) || journal != nil {
		t.Fatalf("symlink root=(%#v,%v)", journal, err)
	}
	root := filepath.Join(temporary, "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	stream := journal.streamPath(plan.Scope())
	if err := os.Symlink(filepath.Join(temporary, "missing"), stream); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Head(context.Background(), plan.Scope()); !errors.Is(err, ErrCorruptRunJournalStream) {
		t.Fatalf("symlink stream=%v", err)
	}
	_ = journal.Close()
}

func TestCoordinatorRecoversDurableRunAndExpiredLease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lost, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-1", time.UnixMilli(200))
	if err != nil || !acquired {
		t.Fatal("initial lease unavailable")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recoveredCoordinator, _ := NewCoordinator(reopened)
	if lease, acquired, err := recoveredCoordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-2", lost.ExpiresAt().Add(-time.Millisecond)); err != nil || acquired || lease.Identity() != "" {
		t.Fatalf("early recovery=(%#v,%t,%v)", lease, acquired, err)
	}
	recovered, acquired, err := recoveredCoordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-2", lost.ExpiresAt().Add(time.Millisecond))
	if err != nil || !acquired || recovered.Attempt() != 2 {
		t.Fatalf("recovery=(%#v,%t,%v)", recovered, acquired, err)
	}
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	state, err := recoveredCoordinator.CompleteTask(context.Background(), plan, recovered, completion, recovered.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	source, _ := state.Task("source")
	if source.Status() != TaskRuntimeSucceeded {
		t.Fatalf("source=%#v", source)
	}
}
