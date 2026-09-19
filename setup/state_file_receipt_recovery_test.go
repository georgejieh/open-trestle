package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func receiptRecoveryFixture(t *testing.T) (string, Plan, CheckReceipt, CheckerCatalog) {
	t.Helper()
	path, plan := initializedSetupState(t)
	catalog, err := BuiltInCheckerCatalog(plan.Profile())
	if err != nil {
		t.Fatal(err)
	}
	key := pendingRequirement(t, plan)
	checker, ok := catalog.Resolve(key)
	if !ok {
		t.Fatal("missing checker")
	}
	receipt, err := newCheckReceipt(plan, key, checker, CheckPassed, setupDigest("recovery-evidence"), RecoveryNone, setupTime(1))
	if err != nil {
		t.Fatal(err)
	}
	return path, plan, receipt, catalog
}

func TestStateFileRecoversInterruptedReceiptStaging(t *testing.T) {
	for _, phase := range []string{"created", "short-write", "synced", "installed"} {
		t.Run(phase, func(t *testing.T) {
			path, plan, receipt, catalog := receiptRecoveryFixture(t)
			encoded, err := EncodeCheckReceipt(receipt)
			if err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(path+".receipts", receiptRecordName(2, receipt.Identity()))
			staging := final + ".next"
			data := encoded
			if phase == "created" {
				data = nil
			} else if phase == "short-write" {
				data = encoded[:len(encoded)/2]
			}
			if err = os.WriteFile(staging, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var installed os.FileInfo
			if phase == "installed" {
				if err = os.Link(staging, final); err != nil {
					t.Fatal(err)
				}
				installed, err = os.Lstat(final)
				if err != nil {
					t.Fatal(err)
				}
			}
			inspected, err := InspectStateFile(context.Background(), path)
			if err != nil || inspected.Identity() != plan.Identity() || len(inspected.Receipts()) != 0 {
				t.Errorf("read-only inspection changed committed plan: %v", err)
			}
			if got, readErr := os.ReadFile(staging); readErr != nil || string(got) != string(data) {
				t.Fatal("inspection changed receipt staging")
			}
			store, err := OpenStateFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err = os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging not reclaimed: %v", err)
			}
			current, err := store.Current(context.Background())
			if err != nil || current.Identity() != plan.Identity() || len(current.Receipts()) != 0 {
				t.Fatalf("committed plan changed: %v", err)
			}
			pending, found, err := store.PendingReceipt(context.Background())
			if err != nil || found != (phase == "installed") {
				t.Fatalf("pending=%v err=%v", found, err)
			}
			if found && pending.Identity() != receipt.Identity() {
				t.Fatal("wrong orphan receipt")
			}
			next, err := store.applyReceipt(context.Background(), receipt, catalog)
			if err != nil || next.Revision() != 2 || len(next.Receipts()) != 1 {
				t.Fatalf("retry=%v", err)
			}
			if installed != nil {
				again, statErr := os.Lstat(final)
				if statErr != nil || !os.SameFile(installed, again) {
					t.Fatal("retry replaced installed immutable receipt")
				}
			}
			entries, err := os.ReadDir(path + ".receipts")
			if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(final) {
				t.Fatalf("unexpected ledger after retry: %v", err)
			}
			if err = store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenStateFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			current, err = reopened.Current(context.Background())
			if err != nil || current.Identity() != next.Identity() {
				t.Fatalf("second reopen=%v", err)
			}
		})
	}
}

func TestStateFileReceiptStagingRequiresWriterLock(t *testing.T) {
	path, _, receipt, _ := receiptRecoveryFixture(t)
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	staging := filepath.Join(path+".receipts", receiptRecordName(2, receipt.Identity())+".next")
	if err = os.WriteFile(staging, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := OpenStateFile(path)
	if second != nil {
		_ = second.Close()
		t.Fatal("second writer acquired lock")
	}
	if !errors.Is(err, ErrStateLocked) {
		t.Fatalf("second writer=%v", err)
	}
	if got, readErr := os.ReadFile(staging); readErr != nil || string(got) != "partial" {
		t.Fatal("locked opener changed staging")
	}
}

func TestStateFileRejectsUnsafeReceiptStagingWithoutRemoval(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "broad-mode"} {
		t.Run(kind, func(t *testing.T) {
			path, _, receipt, _ := receiptRecoveryFixture(t)
			staging := filepath.Join(path+".receipts", receiptRecordName(2, receipt.Identity())+".next")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(path, staging)
			case "directory":
				err = os.Mkdir(staging, 0o700)
			case "broad-mode":
				err = os.WriteFile(staging, []byte("partial"), 0o600)
				if err == nil {
					err = os.Chmod(staging, 0o644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(staging)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = InspectStateFile(context.Background(), path); err == nil {
				t.Error("inspection accepted unsafe staging")
			}
			store, err := OpenStateFile(path)
			if store != nil {
				_ = store.Close()
				t.Error("writer accepted unsafe staging")
			}
			if err == nil {
				t.Error("missing unsafe staging error")
			}
			after, statErr := os.Lstat(staging)
			if statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatal("unsafe staging removed or changed")
			}
		})
	}
}

func TestStateFileDoesNotReclaimMalformedCommittedReceipts(t *testing.T) {
	for _, suffix := range []string{"", ".unexpected", ".next.bak"} {
		t.Run("suffix="+suffix, func(t *testing.T) {
			path, _, receipt, _ := receiptRecoveryFixture(t)
			record := filepath.Join(path+".receipts", receiptRecordName(2, receipt.Identity())+suffix)
			if err := os.WriteFile(record, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := InspectStateFile(context.Background(), path); err == nil {
				t.Error("inspection accepted malformed evidence")
			}
			store, err := OpenStateFile(path)
			if err == nil {
				defer store.Close()
				if _, err = store.Current(context.Background()); err == nil {
					t.Error("writer accepted malformed evidence")
				}
			}
			if got, readErr := os.ReadFile(record); readErr != nil || string(got) != "partial" {
				t.Fatal("malformed evidence removed or changed")
			}
		})
	}
}

func TestRestoreBackupSnapshotRecoversInterruptedReceiptStaging(t *testing.T) {
	path, _, receipt, catalog := receiptRecoveryFixture(t)
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	plan, err := state.applyReceipt(context.Background(), receipt, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshotRoot := t.TempDir()
	if err := os.Chmod(snapshotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(snapshotRoot, "snapshot.json")
	if _, err = CreateBackupSnapshot(context.Background(), path, snapshot, plan.Identity()); err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCheckReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"created", "short-write", "synced", "installed", "committed-partial"} {
		t.Run(phase, func(t *testing.T) {
			destinationRoot := t.TempDir()
			if err := os.Chmod(destinationRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(destinationRoot, "restored.json")
			partial, err := OpenStateFile(destination)
			if err != nil {
				t.Fatal(err)
			}
			if err = partial.Close(); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(destination+".receipts", receiptRecordName(2, receipt.Identity()))
			staging := final + ".next"
			data := encoded
			if phase == "created" {
				data = nil
			} else if phase == "short-write" || phase == "committed-partial" {
				data = encoded[:len(encoded)/2]
			}
			if phase == "committed-partial" {
				staging = final
			}
			if err = os.WriteFile(staging, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var installed os.FileInfo
			if phase == "installed" {
				if err = os.Link(staging, final); err != nil {
					t.Fatal(err)
				}
				installed, err = os.Lstat(final)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = RestoreBackupSnapshot(context.Background(), snapshot, destination, setupDigest("wrong-root"), plan.Identity()); !errors.Is(err, ErrStateConflict) {
				t.Fatalf("scope fence=%v", err)
			}
			if got, readErr := os.ReadFile(staging); readErr != nil || string(got) != string(data) {
				t.Fatal("wrong-scope restore changed staging")
			}
			restored, err := RestoreBackupSnapshot(context.Background(), snapshot, destination, plan.RootIdentity(), plan.Identity())
			if phase == "committed-partial" {
				if err == nil {
					t.Fatal("restore accepted malformed committed receipt")
				}
				if got, readErr := os.ReadFile(final); readErr != nil || string(got) != string(data) {
					t.Fatal("restore replaced malformed committed receipt")
				}
				if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
					t.Fatal("restore installed plan over corrupt ledger")
				}
				return
			}
			if err != nil || restored.Identity() != plan.Identity() {
				t.Fatalf("restore retry=%v", err)
			}
			if _, err = os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("restore staging not reclaimed: %v", err)
			}
			if installed != nil {
				again, statErr := os.Lstat(final)
				if statErr != nil || !os.SameFile(installed, again) {
					t.Fatal("restore replaced installed immutable receipt")
				}
			}
			inspected, err := InspectStateFile(context.Background(), destination)
			if err != nil || inspected.Identity() != plan.Identity() || len(inspected.Receipts()) != 1 {
				t.Fatalf("restored inspection=%v", err)
			}
			if _, err = RestoreBackupSnapshot(context.Background(), snapshot, destination, plan.RootIdentity(), plan.Identity()); !errors.Is(err, ErrStateConflict) {
				t.Fatalf("completed restore overwrite=%v", err)
			}
		})
	}
}

func TestStateFileReceiptStagingRejectsUnrecognizedScope(t *testing.T) {
	for _, kind := range []string{"distant", "missing-plan-distant", "old-uninstalled", "noncanonical", "zero-identity", "multiple"} {
		t.Run(kind, func(t *testing.T) {
			path, _, receipt, _ := receiptRecoveryFixture(t)
			name := receiptRecordName(2, receipt.Identity()) + ".next"
			switch kind {
			case "distant", "missing-plan-distant":
				name = receiptRecordName(9, receipt.Identity()) + ".next"
			case "old-uninstalled":
				name = receiptRecordName(1, receipt.Identity()) + ".next"
			case "noncanonical":
				name = "2-" + receipt.Identity() + ".receipt.json.next"
			case "zero-identity":
				name = receiptRecordName(2, "0000000000000000000000000000000000000000000000000000000000000000") + ".next"
			}
			staging := filepath.Join(path+".receipts", name)
			if err := os.WriteFile(staging, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
			if kind == "multiple" {
				other := filepath.Join(path+".receipts", receiptRecordName(2, setupDigest("other-stage"))+".next")
				if err := os.WriteFile(other, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "missing-plan-distant" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else if _, err := InspectStateFile(context.Background(), path); err == nil {
				t.Error("inspection accepted unrecognized staging scope")
			}
			store, err := OpenStateFile(path)
			if store != nil {
				_ = store.Close()
				t.Error("writer accepted unrecognized staging scope")
			}
			if err == nil {
				t.Error("missing staging scope error")
			}
			if got, readErr := os.ReadFile(staging); readErr != nil || string(got) != "partial" {
				t.Fatal("unrecognized staging removed")
			}
		})
	}
}

func TestStateFileReclaimsStagingOfVerifiedCommittedReceipt(t *testing.T) {
	path, _, receipt, catalog := receiptRecoveryFixture(t)
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	next, err := store.applyReceipt(context.Background(), receipt, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(path+".receipts", receiptRecordName(2, receipt.Identity()))
	if err = os.Link(final, final+".next"); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(final)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, err := reopened.Current(context.Background())
	if err != nil || current.Identity() != next.Identity() {
		t.Fatalf("current=%v", err)
	}
	after, err := os.Lstat(final)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatal("committed receipt changed")
	}
	if _, err = os.Lstat(final + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging remains: %v", err)
	}
}

func TestStateFilePersistReceiptNeverOverwritesCorruptFinal(t *testing.T) {
	path, _, receipt, _ := receiptRecoveryFixture(t)
	store, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	final := filepath.Join(path+".receipts", receiptRecordName(2, receipt.Identity()))
	if err = os.WriteFile(final, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = store.persistReceipt(2, receipt); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("persist=%v", err)
	}
	if got, readErr := os.ReadFile(final); readErr != nil || string(got) != "partial" {
		t.Fatal("corrupt final was replaced")
	}
}

func TestRestoreBackupSnapshotRecoversStagingAfterInstalledPrefix(t *testing.T) {
	path, _, first, catalog := receiptRecoveryFixture(t)
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	plan, err := state.applyReceipt(context.Background(), first, catalog)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCheckReceipt(plan, first.Key(), first.CheckerIdentity(), CheckPassed, setupDigest("second-recovery"), RecoveryNone, setupTime(2))
	if err != nil {
		t.Fatal(err)
	}
	plan, err = state.applyReceipt(context.Background(), second, catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	snapshotRoot := t.TempDir()
	if err = os.Chmod(snapshotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(snapshotRoot, "snapshot.json")
	if _, err = CreateBackupSnapshot(context.Background(), path, snapshot, plan.Identity()); err != nil {
		t.Fatal(err)
	}
	destinationRoot := t.TempDir()
	if err = os.Chmod(destinationRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(destinationRoot, "restored.json")
	partial, err := OpenStateFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer partial.Close()
	if err = partial.persistReceipt(2, first); err != nil {
		t.Fatal(err)
	}
	if err = partial.Close(); err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(destination+".receipts", receiptRecordName(3, second.Identity())+".next")
	if err = os.WriteFile(staging, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreBackupSnapshot(context.Background(), snapshot, destination, plan.RootIdentity(), plan.Identity())
	if err != nil || restored.Identity() != plan.Identity() || len(restored.Receipts()) != 2 {
		t.Fatalf("restore after prefix=%v", err)
	}
	if _, err = os.Lstat(staging); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging remains: %v", err)
	}
}
