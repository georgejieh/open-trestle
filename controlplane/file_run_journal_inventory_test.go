package controlplane

import (
	"context"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func inventoryPlan(t *testing.T, tenant, repo, run string) ReviewRunPlan {
	t.Helper()
	scope, err := audit.NewReviewScope(tenant, repo, run)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, runPlanTasks(t))
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func inventoryOpen(t *testing.T, journal *FileRunJournal, plan ReviewRunPlan) *Coordinator {
	t.Helper()
	c, err := NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	return c
}
func inventoryPreparedLease(t *testing.T, c *Coordinator, plan ReviewRunPlan) TaskLease {
	t.Helper()
	ctx := context.Background()
	at := int64(200)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err = c.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+1)); err != nil {
			t.Fatal(err)
		}
		at += 20
	}
	task, _ := plan.Task("context")
	lease, ok, err := c.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !ok {
		t.Fatalf("context claim: %v", err)
	}
	return lease
}
func TestStartupInventoryHistoricalCanceledPacket(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	old := inventoryPlan(t, "old-tenant", "old-repo", "run-2")
	var current ReviewRunPlan
	for i := 0; i < 10000; i++ {
		candidate := inventoryPlan(t, "current-tenant", "current-repo", fmt.Sprintf("run-%d", i))
		if candidate.Scope().Identity() > old.Scope().Identity() {
			current = candidate
			break
		}
	}
	if current.Scope().Identity() == "" {
		t.Fatal("no ordered current digest")
	}
	inventoryOpen(t, j, current)
	c := inventoryOpen(t, j, old)
	lease := inventoryPreparedLease(t, c, old)
	d := ContextPacketDescriptor{LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(), PayloadDigest: strings.Repeat("b", 64), Classification: "internal", Protection: "process_private", Provenance: []string{strings.Repeat("c", 64), strings.Repeat("e", 64)}, SourceRootIdentity: strings.Repeat("d", 64), SnapshotIdentity: strings.Repeat("e", 64), DependencyIdentities: []string{strings.Repeat("e", 64)}, CreatedAtMilliseconds: 300, ExpiresAtMilliseconds: 3600300}
	d.ArtifactIdentity = packetArtifactIdentity(old.Scope(), d)
	before := lease.ExpiresAt().Add(-2 * time.Millisecond)
	prepared, err := c.PrepareContextPacket(context.Background(), old, lease, d, before)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.TerminatePreparedContextPacket(context.Background(), old, prepared, lease.ExpiresAt().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err = c.CancelRun(context.Background(), old, lease.ExpiresAt().Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	restarted, _ := NewCoordinator(j)
	_, state, err := restarted.Resume(context.Background(), old.Scope())
	if err != nil || state.Status() != ReviewRunCanceled {
		t.Fatalf("replay: %v", err)
	}
	runtime, _ := state.Task("context")
	if _, ok := runtime.PreparedContextPacket(); ok {
		t.Fatal("fixture is still prepared")
	}
	got, err := j.InspectStartupInventory(context.Background())
	if !errors.Is(err, ErrPreparedContextPacketAtStartup) || got != (StartupInventory{}) {
		t.Fatalf("historical verdict: %+v %v", got, err)
	}
	if err := os.WriteFile(j.streamPath(current.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = j.InspectStartupInventory(context.Background())
	if !errors.Is(err, ErrCorruptRunJournalStream) || errors.Is(err, ErrPreparedContextPacketAtStartup) || got != (StartupInventory{}) {
		t.Fatalf("corrupt current after historical packet: %+v %v", got, err)
	}
}
func TestStartupInventoryValidAndRejectsIncomplete(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	assert := func(plans, streams, events int) {
		t.Helper()
		got, err := j.InspectStartupInventory(ctx)
		if err != nil || got != (StartupInventory{plans, streams, events}) {
			t.Fatalf("inventory %+v %v", got, err)
		}
	}
	assert(0, 0, 0)
	p := inventoryPlan(t, "tenant", "repo", "run")
	inventoryOpen(t, j, p)
	assert(1, 1, 1)
	for _, sibling := range []string{"artifacts", "audit", "diagnostics", "webhook-inbox", "setup"} {
		if err := os.Mkdir(filepath.Join(root, sibling), 0700); err != nil {
			t.Fatal(err)
		}
	}
	assert(1, 1, 1)
	if err := os.WriteFile(filepath.Join(root, "unrecognized"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrInvalidStartupInventoryEntry) || got != (StartupInventory{}) {
		t.Fatalf("unknown root: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "unrecognized")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "plan.json"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrInvalidStartupInventoryEntry) || got != (StartupInventory{}) {
		t.Fatalf("direct setup state: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "plan.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(j.streamPath(p.Scope())); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrIncompleteStartupInventoryPrefix) || got != (StartupInventory{}) {
		t.Fatalf("plan-only: %+v %v", got, err)
	}
	other := inventoryPlan(t, "another-tenant", "another-repo", "another-run")
	wire, err := EncodeReviewRunPlan(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(j.planPath(other.Scope()), wire, 0600); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, strings.Repeat("f", 64)+runJournalStreamSuffix)
	if err := os.WriteFile(orphan, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrInvalidStartupInventoryEntry) || errors.Is(err, ErrIncompleteStartupInventoryPrefix) || got != (StartupInventory{}) {
		t.Fatalf("orphan plus plan-only: %+v %v", got, err)
	}
	if err := os.Remove(orphan); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(j.planPath(other.Scope())); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(j.planPath(p.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrInvalidReviewRunPlanEncoding) || errors.Is(err, ErrIncompleteStartupInventoryPrefix) || got != (StartupInventory{}) {
		t.Fatalf("malformed plan-only: %+v %v", got, err)
	}
	if err := os.Remove(j.planPath(p.Scope())); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(j.streamPath(p.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrInvalidStartupInventoryEntry) || got != (StartupInventory{}) {
		t.Fatalf("orphan: %v", err)
	}
}
func TestStartupInventoryMalformedAndBound(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	p := inventoryPlan(t, "tenant", "repo", "run")
	inventoryOpen(t, j, p)
	if err := os.WriteFile(j.streamPath(p.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrCorruptRunJournalStream) || got != (StartupInventory{}) {
		t.Fatalf("malformed: %v", err)
	}
	if err := os.Remove(j.streamPath(p.Scope())); err != nil {
		t.Fatal(err)
	}
	// The root bound includes the lock and all sibling entries, not only journal files.
	for i := 0; i < maxStartupInventoryEntries; i++ {
		name := filepath.Join(root, "entry-"+strings.Repeat("0", 5)+"-"+string(rune(0x1000+i)))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := j.InspectStartupInventory(ctx); !errors.Is(err, ErrStartupInventoryLimit) || got != (StartupInventory{}) {
		t.Fatalf("entry bound: %v", err)
	}
}

func TestStartupInventoryPlanAndAggregateLimits(t *testing.T) {
	for _, kind := range []string{"plans", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			j, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			if kind == "plans" {
				plan := inventoryPlan(t, "tenant", "repo", "run")
				wire, err := EncodeReviewRunPlan(plan)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i <= maxStartupInventoryPlans; i++ {
					path := filepath.Join(root, fmt.Sprintf("%064x%s", i, runJournalPlanSuffix))
					if err := os.WriteFile(path, wire, 0600); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				for i := 0; i < 5; i++ {
					path := filepath.Join(root, fmt.Sprintf("%064x%s", i, runJournalStreamSuffix))
					f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
					if err != nil {
						t.Fatal(err)
					}
					if err = f.Truncate(maxRunJournalStreamBytes); err != nil {
						t.Fatal(err)
					}
					if err = f.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			got, err := j.InspectStartupInventory(context.Background())
			if !errors.Is(err, ErrStartupInventoryLimit) || got != (StartupInventory{}) {
				t.Fatalf("%s: %+v %v", kind, got, err)
			}
		})
	}
}
func TestStartupInventoryDirectRootModesAndNames(t *testing.T) {
	for _, variant := range []string{"symlink", "public-directory", "irregular-name", "public-lock", "wrong-plan-name", "wrong-plan-scope", "wrong-sibling-type", "public-plan", "public-root"} {
		t.Run(variant, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			j, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			plan := inventoryPlan(t, "tenant", "repo", "run")
			inventoryOpen(t, j, plan)
			switch variant {
			case "symlink":
				if err := os.Symlink("audit", filepath.Join(root, "setup")); err != nil {
					t.Fatal(err)
				}
			case "public-directory":
				if err := os.Mkdir(filepath.Join(root, "setup"), 0755); err != nil {
					t.Fatal(err)
				}
			case "irregular-name":
				if err := os.Mkdir(filepath.Join(root, "unowned"), 0700); err != nil {
					t.Fatal(err)
				}
			case "public-lock":
				if err := os.Chmod(filepath.Join(root, runJournalWriterLockName), 0644); err != nil {
					t.Fatal(err)
				}
			case "wrong-plan-name":
				if err := os.Rename(j.planPath(plan.Scope()), filepath.Join(root, strings.Repeat("A", 64)+runJournalPlanSuffix)); err != nil {
					t.Fatal(err)
				}
			case "wrong-plan-scope":
				base := strings.Repeat("a", 64)
				if base == plan.Scope().Identity() {
					base = strings.Repeat("f", 64)
				}
				for _, pair := range [][2]string{{j.planPath(plan.Scope()), base + runJournalPlanSuffix}, {j.streamPath(plan.Scope()), base + runJournalStreamSuffix}} {
					wire, err := os.ReadFile(pair[0])
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, pair[1]), wire, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-sibling-type":
				if err := os.WriteFile(filepath.Join(root, "setup"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-plan":
				if err := os.Chmod(j.planPath(plan.Scope()), 0644); err != nil {
					t.Fatal(err)
				}
			case "public-root":
				if err := os.Chmod(root, 0755); err != nil {
					t.Fatal(err)
				}
			}
			got, err := j.InspectStartupInventory(context.Background())
			if err == nil || got != (StartupInventory{}) {
				t.Fatalf("unsafe root accepted: %+v %v", got, err)
			}
			if variant == "wrong-plan-scope" && !errors.Is(err, ErrInvalidReviewRunPlanEncoding) {
				t.Fatalf("scope mismatch: %v", err)
			}
		})
	}
}
