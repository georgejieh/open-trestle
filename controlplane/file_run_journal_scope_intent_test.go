package controlplane

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

func TestJournalScopeIntentUncertainReopenRefusesWithoutExactResolution(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	err = journal.WithScopeIntent(context.Background(), plan.Scope(), "admission-input", plan.Identity(), func(context.Context) error { return errors.New("Put after rename") }, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("expected uncertain effect")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.WithScopeIntent(context.Background(), plan.Scope(), "admission-input", plan.Identity(), func(context.Context) error { t.Fatal("retried without reconciliation"); return nil }, func(context.Context) error { return nil }); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("restarted intent=%v", err)
	}
	if _, err := reopened.InspectStartupInventory(context.Background()); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("inventory=%v", err)
	}
	if err := reopened.SavePlan(context.Background(), plan); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("save plan=%v", err)
	}
	if err := reopened.Append(context.Background(), "", runOpenedEventFixture(t, plan)); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("append=%v", err)
	}
}

func TestJournalScopeIntentCleanVerificationAndInventory(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := runPlanFixture(t)
	if err := journal.WithScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(ctx context.Context) error { return nil }, func(ctx context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := journal.WithScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(ctx context.Context) error { return nil }, func(ctx context.Context) error { return nil }); err != nil {
		t.Fatalf("second committed operation=%v", err)
	}
}

func TestJournalScopeIntentExactReconciliationAfterRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	if err := journal.WithScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(ctx context.Context) error { return errors.New("ambiguous") }, func(context.Context) error { return nil }); err == nil {
		t.Fatal("expected unresolved")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	called := false
	if err := reopened.ReconcileScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(context.Context) error { called = true; return errors.New("not exact") }); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("unverified cleanup=%v", err)
	}
	if !called {
		t.Fatal("verification not run")
	}
	if err := reopened.WithScopeGate(context.Background(), plan.Scope(), func(context.Context) error { t.Fatal("effect entered without exact reconciliation"); return nil }); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("blocked=%v", err)
	}
	if err := reopened.ReconcileScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("exact reconciliation=%v", err)
	}
	if err := reopened.WithScopeGate(context.Background(), plan.Scope(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("unblocked=%v", err)
	}
}

func TestJournalScopeIntentPlanRenameErrorRequiresReconciliation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := runPlanFixture(t)
	fault := errors.New("after plan rename")
	journal.afterPlanRename = func(audit.ReviewScope) error { return fault }
	err = journal.WithScopeIntent(context.Background(), plan.Scope(), "save-plan", plan.Identity(), func(ctx context.Context) error { return journal.SavePlan(ctx, plan) }, func(context.Context) error { return nil })
	if !errors.Is(err, fault) || !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("error=%v", err)
	}
	persisted, found, err := journal.LoadPlan(context.Background(), plan.Scope())
	if err != nil || !found || persisted.Identity() != plan.Identity() {
		t.Fatalf("physical plan=%t %v", found, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.SavePlan(context.Background(), plan); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("unguarded retry=%v", err)
	}
	if err := reopened.ReconcileScopeIntent(context.Background(), plan.Scope(), "save-plan", plan.Identity(), func(ctx context.Context) error {
		observed, found, err := reopened.LoadPlan(ctx, plan.Scope())
		if err != nil || !found || observed.Identity() != plan.Identity() {
			return ErrScopeIntentUnresolved
		}
		return nil
	}); err != nil {
		t.Fatalf("exact plan proof=%v", err)
	}
	if err := reopened.SavePlan(context.Background(), plan); err != nil {
		t.Fatalf("idempotent plan=%v", err)
	}
}

func TestJournalScopeIntentAppendRenameErrorRequiresReconciliation(t *testing.T) {
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
	fault := errors.New("after stream rename")
	journal.afterStreamRename = func(audit.ReviewScope) error { return fault }
	err = journal.WithScopeIntent(context.Background(), plan.Scope(), "append-open", opened.Identity(), func(ctx context.Context) error { return journal.Append(ctx, "", opened) }, func(context.Context) error { return nil })
	if !errors.Is(err, fault) || !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("error=%v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Append(context.Background(), "", opened); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("unguarded retry=%v", err)
	}
	if err := reopened.ReconcileScopeIntent(context.Background(), plan.Scope(), "append-open", opened.Identity(), func(ctx context.Context) error {
		head, found, err := reopened.Head(ctx, plan.Scope())
		if err != nil || !found || head.Identity() != opened.Identity() {
			return ErrScopeIntentUnresolved
		}
		return nil
	}); err != nil {
		t.Fatalf("exact event proof=%v", err)
	}
}
