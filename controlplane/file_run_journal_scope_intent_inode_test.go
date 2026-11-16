package controlplane

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"testing"
)

func TestScopeIntentReconciliationRejectsMarkerReplacement(t *testing.T) {
	for _, variant := range []string{"same-bytes-inode", "same-bytes-symlink"} {
		t.Run(variant, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			journal, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			defer journal.Close()
			plan := runPlanFixture(t)
			if err := journal.WithScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(context.Context) error { return errors.New("ambiguous") }, func(context.Context) error { return nil }); !errors.Is(err, ErrScopeIntentUnresolved) {
				t.Fatal(err)
			}
			path := journal.scopeIntentPath(plan.Scope())
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "same-content")
			if err := os.WriteFile(target, original, 0o600); err != nil {
				t.Fatal(err)
			}
			err = journal.ReconcileScopeIntent(context.Background(), plan.Scope(), "journal-only", plan.Identity(), func(context.Context) error {
				if err := os.Rename(path, path+".saved"); err != nil {
					return err
				}
				if variant == "same-bytes-symlink" {
					return os.Symlink(target, path)
				}
				return os.WriteFile(path, original, 0o600)
			})
			if !errors.Is(err, ErrScopeIntentUnresolved) {
				t.Fatalf("marker replacement cleared: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatalf("replacement missing: %v", err)
			}
			if err := journal.WithScopeGate(context.Background(), plan.Scope(), func(context.Context) error { t.Fatal("replaced marker unblocked scope"); return nil }); !errors.Is(err, ErrScopeIntentUnresolved) {
				t.Fatalf("scope unblocked: %v", err)
			}
		})
	}
}

func TestScopeGateFromOtherScopeCannotBypassUnresolvedIntent(t *testing.T) {
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	scopeB, err := audit.NewReviewScope("tenant", "repository", "run-b")
	if err != nil {
		t.Fatal(err)
	}
	planB, err := NewReviewRunPlan(scopeB, strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, runPlanTasks(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.SavePlan(context.Background(), planB); err != nil {
		t.Fatal(err)
	}
	if err := journal.WithScopeIntent(context.Background(), scopeB, "journal-only", planB.Identity(), func(context.Context) error { return errors.New("effect uncertain") }, func(context.Context) error { return nil }); !errors.Is(err, ErrScopeIntentUnresolved) {
		t.Fatalf("marker setup: %v", err)
	}
	opened := runOpenedEventFixture(t, planB)
	if err := journal.WithScopeGate(context.Background(), runScopeFixture(t), func(granted context.Context) error {
		return journal.Append(granted, "", opened)
	}); !errors.Is(err, ErrScopeGateBusy) {
		t.Fatalf("foreign scope grant bypassed marker: %v", err)
	}
	if head, present, err := journal.Head(context.Background(), scopeB); err != nil || present || head.Identity() != "" {
		t.Fatalf("marked scope advanced: present=%t err=%v", present, err)
	}
}
