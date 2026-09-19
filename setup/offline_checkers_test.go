package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func initializedSetupState(t *testing.T) (string, Plan) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.json")
	state, err := OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(0))
	if err != nil {
		t.Fatal(err)
	}
	if err = state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	return path, plan
}

func TestLocalAdministratorCheckerBindsApprovalAndProcessIdentity(t *testing.T) {
	_, plan := initializedSetupState(t)
	checker, err := NewLocalAdministratorChecker(plan, "owner")
	if err != nil {
		t.Fatal(err)
	}
	result := checker.Check(context.Background(), plan)
	if result.State() != CheckPassed || result.RecoveryAction() != RecoveryNone {
		t.Fatalf("pass=%s/%s", result.State(), result.RecoveryAction())
	}
	denied, err := NewLocalAdministratorChecker(plan, "another-owner")
	if err != nil {
		t.Fatal(err)
	}
	if result = denied.Check(context.Background(), plan); result.State() != CheckBlocked || result.RecoveryAction() != RecoveryConfigureIdentity {
		t.Fatalf("denied=%s/%s", result.State(), result.RecoveryAction())
	}
	other, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	if result = checker.Check(context.Background(), other); result.State() != CheckBlocked {
		t.Fatalf("crossed=%s", result.State())
	}
	var nilChecker *LocalAdministratorChecker
	if result = nilChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("nil=%s", result.State())
	}
	if strings.Contains(fmt.Sprintf("%#v", checker), "owner") {
		t.Fatal("approval escaped formatter")
	}
}

func TestBackupSnapshotCheckerRequiresExactSeparateProtectedCopy(t *testing.T) {
	statePath, plan := initializedSetupState(t)
	backupRoot := t.TempDir()
	if err := os.Chmod(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(backupRoot, "plan.snapshot.json")
	got, err := CreateBackupSnapshot(context.Background(), statePath, backupPath, plan.Identity())
	if err != nil || got.Identity() != plan.Identity() {
		t.Fatalf("create=%v identity=%s", err, got.Identity())
	}
	encoded, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _ := EncodePlan(plan)
	if string(encoded) != string(canonical) {
		t.Fatal("snapshot is not canonical plan")
	}
	checker, err := NewBackupSnapshotChecker(statePath, backupPath, plan)
	if err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckPassed {
		t.Fatalf("pass=%s", result.State())
	}
	if _, err = CreateBackupSnapshot(context.Background(), statePath, backupPath, plan.Identity()); !errors.Is(err, ErrBackupSnapshotExists) {
		t.Fatalf("overwrite=%v", err)
	}
	if _, err = CreateBackupSnapshot(context.Background(), statePath, filepath.Join(t.TempDir(), "wrong.json"), setupDigest("wrong")); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("fence=%v", err)
	}
	if err = os.Chmod(backupPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if result := checker.Check(context.Background(), plan); result.State() != CheckBlocked || result.RecoveryAction() != RecoveryProvideBackup {
		t.Fatalf("mode=%s/%s", result.State(), result.RecoveryAction())
	}
	if err = os.Chmod(backupPath, 0o600); err != nil {
		t.Fatal(err)
	}
	linkRoot := t.TempDir()
	_ = os.Chmod(linkRoot, 0o700)
	link := filepath.Join(linkRoot, "snapshot-link")
	if err = os.Symlink(backupPath, link); err != nil {
		t.Fatal(err)
	}
	linkChecker, _ := NewBackupSnapshotChecker(statePath, link, plan)
	if result := linkChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("symlink=%s", result.State())
	}
	state, err := OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := NewLocalAdministratorChecker(plan, "owner")
	runner, _ := NewRunner(state, []Checker{admin}, testRunnerClock{setupTime(1)})
	newer, _, err := runner.Run(context.Background(), CheckLocalAdministratorValidated)
	_ = state.Close()
	if err != nil {
		t.Fatal(err)
	}
	stale, _ := NewBackupSnapshotChecker(statePath, backupPath, newer)
	if result := stale.Check(context.Background(), newer); result.State() != CheckBlocked {
		t.Fatalf("stale=%s", result.State())
	}
}

func TestBackupSnapshotRejectsCrossWiringAndUnsafeLocation(t *testing.T) {
	statePath, plan := initializedSetupState(t)
	nested := filepath.Join(statePath+".receipts", "backup.json")
	if _, err := CreateBackupSnapshot(context.Background(), statePath, nested, plan.Identity()); !errors.Is(err, ErrInvalidBackupSnapshot) {
		t.Fatalf("nested ledger=%v", err)
	}
	if _, err := InspectStateFile(context.Background(), statePath); err != nil {
		t.Fatalf("source corrupted: %v", err)
	}
	sameParent := filepath.Join(filepath.Dir(statePath), "backup.json")
	if _, err := CreateBackupSnapshot(context.Background(), statePath, sameParent, plan.Identity()); !errors.Is(err, ErrInvalidBackupSnapshot) {
		t.Fatalf("same parent=%v", err)
	}
	if checker, err := NewBackupSnapshotChecker(statePath, sameParent, plan); !errors.Is(err, ErrInvalidCheckerRuntime) || checker != nil {
		t.Fatalf("checker=%#v err=%v", checker, err)
	}
	backupRoot := t.TempDir()
	if err := os.Chmod(backupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(backupRoot, "backup.json")
	if _, err := CreateBackupSnapshot(context.Background(), statePath, backupPath, plan.Identity()); err != nil {
		t.Fatal(err)
	}
	checker, _ := NewBackupSnapshotChecker(statePath, backupPath, plan)
	other, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-b", "owner", setupTime(0))
	if result := checker.Check(context.Background(), other); result.State() != CheckBlocked {
		t.Fatalf("crossed=%s", result.State())
	}
	var nilChecker *BackupSnapshotChecker
	if result := nilChecker.Check(context.Background(), plan); result.State() != CheckBlocked {
		t.Fatalf("nil=%s", result.State())
	}
	if strings.Contains(fmt.Sprintf("%#v", checker), backupPath) || strings.Contains(fmt.Sprintf("%#v", checker), statePath) {
		t.Fatal("path escaped formatter")
	}
}

func TestRestoreBackupSnapshotRebuildsVerifiedReceiptLedger(t *testing.T) {
	statePath, plan := initializedSetupState(t)
	state, err := OpenStateFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	checker, _ := NewLocalAdministratorChecker(plan, "owner")
	runner, _ := NewRunner(state, []Checker{checker}, testRunnerClock{setupTime(1)})
	current, _, err := runner.Run(context.Background(), CheckLocalAdministratorValidated)
	if err != nil {
		t.Fatal(err)
	}
	_ = state.Close()
	backupRoot := t.TempDir()
	_ = os.Chmod(backupRoot, 0o700)
	snapshot := filepath.Join(backupRoot, "plan.snapshot.json")
	if _, err = CreateBackupSnapshot(context.Background(), statePath, snapshot, current.Identity()); err != nil {
		t.Fatal(err)
	}
	restoreRoot := t.TempDir()
	_ = os.Chmod(restoreRoot, 0o700)
	destination := filepath.Join(restoreRoot, "restored.json")
	restored, err := RestoreBackupSnapshot(context.Background(), snapshot, destination, current.RootIdentity(), current.Identity())
	if err != nil || restored.Identity() != current.Identity() {
		t.Fatalf("restore=%v identity=%s", err, restored.Identity())
	}
	inspected, err := InspectStateFile(context.Background(), destination)
	if err != nil || inspected.Identity() != current.Identity() || len(inspected.Receipts()) != 1 {
		t.Fatalf("inspect=%v receipts=%d", err, len(inspected.Receipts()))
	}
	partialRoot := t.TempDir()
	_ = os.Chmod(partialRoot, 0o700)
	partialPath := filepath.Join(partialRoot, "partial.json")
	partial, err := OpenStateFile(partialPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt := current.Receipts()[0]
	if err = partial.persistReceipt(2, receipt); err != nil {
		t.Fatal(err)
	}
	_ = partial.Close()
	resumed, err := RestoreBackupSnapshot(context.Background(), snapshot, partialPath, current.RootIdentity(), current.Identity())
	if err != nil || resumed.Identity() != current.Identity() {
		t.Fatalf("resume=%v", err)
	}
	if _, err = RestoreBackupSnapshot(context.Background(), snapshot, destination, current.RootIdentity(), current.Identity()); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("overwrite=%v", err)
	}
	missingRoot := t.TempDir()
	_ = os.Chmod(missingRoot, 0o700)
	missing := filepath.Join(missingRoot, "missing.json")
	if _, err = RestoreBackupSnapshot(context.Background(), snapshot, missing, setupDigest("wrong"), current.Identity()); !errors.Is(err, ErrStateConflict) {
		t.Fatalf("root fence=%v", err)
	}
	for _, path := range []string{missing, missing + ".lock", missing + ".receipts"} {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("created %s", path)
		}
	}
}

func TestBackupSnapshotCreationIsExclusiveAndCancellationHasNoArtifacts(t *testing.T) {
	statePath, plan := initializedSetupState(t)
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	path := filepath.Join(root, "backup.json")
	var wait sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := CreateBackupSnapshot(context.Background(), statePath, path, plan.Identity())
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	passed, exists := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else if errors.Is(err, ErrBackupSnapshotExists) {
			exists++
		} else {
			t.Fatalf("unexpected=%v", err)
		}
	}
	if passed != 1 || exists != 7 {
		t.Fatalf("passed=%d exists=%d", passed, exists)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	destination := filepath.Join(root, "canceled.json")
	if _, err := CreateBackupSnapshot(canceled, statePath, destination, plan.Identity()); !errors.Is(err, ErrInvalidBackupSnapshot) {
		t.Fatalf("cancel=%v", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("canceled snapshot exists")
	}
}
