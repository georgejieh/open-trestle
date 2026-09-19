package setup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStateFileInitializesReadsAndFencesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	if err = store.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	current, err := store.Current(context.Background())
	if err != nil || current.Identity() != plan.Identity() {
		t.Fatalf("current=%v", err)
	}
	key := pendingRequirement(t, plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	checker, _ := catalog.Resolve(key)
	receipt, _ := newCheckReceipt(plan, key, checker, CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	next, _ := applyCheckReceipt(plan, receipt, catalog)
	nextReceipt, _ := newCheckReceipt(next, key, checker, CheckPassed, setupDigest("later"), RecoveryNone, setupTime(2))
	if _, err = store.applyReceipt(context.Background(), nextReceipt, catalog); !errors.Is(err, ErrStaleCheckReceipt) {
		t.Fatalf("stale=%v", err)
	}
	persisted, err := store.applyReceipt(context.Background(), receipt, catalog)
	if err != nil || persisted.Identity() != next.Identity() {
		t.Fatalf("apply=%v", err)
	}
	current, err = store.Current(context.Background())
	if err != nil || current.Identity() != next.Identity() || len(current.Receipts()) != 1 {
		t.Fatalf("updated=%v", err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}
func TestStateFileUsesExclusiveWriterLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	first, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := OpenStateFile(path); !errors.Is(err, ErrStateLocked) || second != nil {
		t.Fatalf("second=%#v err=%v", second, err)
	}
}
func TestStateFileRejectsCorruptionAndUnsafePath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "plan.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".receipts", 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Current(context.Background()); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt=%v", err)
	}
	_ = store.Close()
	_ = os.Chmod(path, 0o644)
	if store, err = OpenStateFile(path); !errors.Is(err, ErrInvalidStatePath) || store != nil {
		t.Fatalf("broad=%#v %v", store, err)
	}
	_ = os.Remove(path)
	target := filepath.Join(root, "target.json")
	_ = os.WriteFile(target, []byte(`{}`), 0o600)
	_ = os.Symlink(target, path)
	if store, err = OpenStateFile(path); !errors.Is(err, ErrInvalidStatePath) || store != nil {
		t.Fatalf("symlink=%#v %v", store, err)
	}
}

func TestNilStateFileFailsClosed(t *testing.T) {
	var store *StateFile
	if err := store.Close(); !errors.Is(err, ErrInvalidStatePath) {
		t.Fatalf("close=%v", err)
	}
	if _, err := store.Current(context.Background()); !errors.Is(err, ErrInvalidStatePath) {
		t.Fatalf("current=%v", err)
	}
}

func TestStateFileHonorsCancellationBeforeDurableChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = store.Initialize(ctx, plan); !errors.Is(err, ErrStatePersistence) {
		t.Fatalf("initialize=%v", err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state created: %v", err)
	}
}

func TestStateFileReclaimsOneProtectedInterruptedReplacement(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "plan.json")
	if err := os.WriteFile(path+".next", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if _, err = os.Stat(path + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary=%v", err)
	}
	if err = os.Symlink(path, path+".next"); err != nil {
		t.Fatal(err)
	}
	if store, err = OpenStateFile(path); !errors.Is(err, ErrInvalidStatePath) || store != nil {
		t.Fatalf("unsafe temporary=%#v %v", store, err)
	}
}

func TestStateFileRejectsFabricatedReadyPlanWithoutReceiptHistory(t *testing.T) {
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	for i, r := range plan.requirements {
		if r.source != CheckDeterministic {
			r.state = CheckPassed
			r.checkerIdentity = setupDigest("checker-" + string(r.key))
			r.evidenceIdentity = setupDigest("evidence-" + string(r.key))
			r.receiptIdentity = setupDigest("receipt-" + string(r.key))
			r.checkedAt = setupTime(1)
			plan.requirements[i] = r
		}
	}
	plan.revision = 2
	plan.previousIdentity = setupDigest("previous")
	plan.updatedAt = setupTime(1)
	plan.status = StatusReady
	plan.ready = true
	plan.identity = planIdentity(plan)
	encoded, _ := json.Marshal(wirePlan(plan, true))
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectStateFile(context.Background(), path); err == nil {
		t.Fatal("fabricated plan accepted")
	}
}

func TestStateFileRequiresProtectedReceiptLedgerForClosedChecks(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "plan.json")
	store, _ := OpenStateFile(path)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = store.Initialize(context.Background(), plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	key := pendingRequirement(t, plan)
	checker, _ := catalog.Resolve(key)
	receipt, _ := newCheckReceipt(plan, key, checker, CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	next, err := store.applyReceipt(context.Background(), receipt, catalog)
	if err != nil {
		t.Fatal(err)
	}
	records, _ := os.ReadDir(path + ".receipts")
	if len(records) != 1 {
		t.Fatalf("records=%d", len(records))
	}
	if err = os.Remove(filepath.Join(path+".receipts", records[0].Name())); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Current(context.Background()); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("missing receipt=%v", err)
	}
	_ = store.Close()
	copyPath := filepath.Join(root, "copy.json")
	encoded, _ := EncodePlan(next)
	if err = os.WriteFile(copyPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = InspectStateFile(context.Background(), copyPath); err == nil {
		t.Fatal("plan-only copy accepted")
	}
}
func TestStateFileResumesOneDurableOrphanReceipt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	store, _ := OpenStateFile(path)
	defer store.Close()
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	_ = store.Initialize(context.Background(), plan)
	catalog, _ := BuiltInCheckerCatalog(plan.Profile())
	key := pendingRequirement(t, plan)
	checker, _ := catalog.Resolve(key)
	receipt, _ := newCheckReceipt(plan, key, checker, CheckPassed, setupDigest("evidence"), RecoveryNone, setupTime(1))
	if err := store.persistReceipt(2, receipt); err != nil {
		t.Fatal(err)
	}
	current, err := store.Current(context.Background())
	if err != nil || current.Identity() != plan.Identity() {
		t.Fatalf("orphan current=%v", err)
	}
	pending, found, err := store.PendingReceipt(context.Background())
	if err != nil || !found || pending.Identity() != receipt.Identity() {
		t.Fatalf("pending=%v found=%v err=%v", pending.Identity(), found, err)
	}
	next, err := store.applyReceipt(context.Background(), receipt, catalog)
	if err != nil || next.Revision() != 2 {
		t.Fatalf("resume=%v", err)
	}
}
