package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrInvalidBackupSnapshot identifies an unsafe, malformed, or unprotected snapshot.
	ErrInvalidBackupSnapshot = errors.New("invalid setup backup snapshot")
	// ErrBackupSnapshotExists prevents replacement of an existing snapshot path.
	ErrBackupSnapshotExists = errors.New("setup backup snapshot exists")
)

// LocalAdministratorChecker records a named recovery owner's approval of the current process identity.
type LocalAdministratorChecker struct{ rootIdentity, tenantID, repositoryID, recoveryOwner, approvedBy, processIdentityDigest, configurationIdentity string }

// NewLocalAdministratorChecker binds one approval to the setup root, scope, recovery owner, and current operating-system identity.
func NewLocalAdministratorChecker(plan Plan, approvedBy string) (*LocalAdministratorChecker, error) {
	if plan.Validate() != nil || !validSetupLabel(approvedBy) {
		return nil, ErrInvalidCheckerRuntime
	}
	processIdentity, _ := currentProcessIdentity()
	processIdentityDigest := checkerConfigIdentity(CheckLocalAdministratorValidated, processIdentity)
	value := plan.RootIdentity() + "\x00" + plan.TenantID() + "\x00" + plan.RepositoryID() + "\x00" + plan.RecoveryOwner() + "\x00" + approvedBy + "\x00" + processIdentityDigest
	return &LocalAdministratorChecker{plan.RootIdentity(), plan.TenantID(), plan.RepositoryID(), plan.RecoveryOwner(), approvedBy, processIdentityDigest, checkerConfigIdentity(CheckLocalAdministratorValidated, value)}, nil
}
func (c *LocalAdministratorChecker) Key() CheckKey { return CheckLocalAdministratorValidated }
func (c *LocalAdministratorChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckLocalAdministratorValidated)
}
func (c *LocalAdministratorChecker) Check(ctx context.Context, plan Plan) CheckResult {
	outcome, state := "valid", CheckBlocked
	identity, supported := currentProcessIdentity()
	switch {
	case !supported:
		outcome, state = "identity_unavailable", CheckUnavailable
	case c == nil || ctx == nil || ctx.Err() != nil || plan.Validate() != nil:
		outcome = "invalid"
	case plan.RootIdentity() != c.rootIdentity || plan.TenantID() != c.tenantID || plan.RepositoryID() != c.repositoryID || plan.RecoveryOwner() != c.recoveryOwner:
		outcome = "scope_mismatch"
	case c.approvedBy != c.recoveryOwner:
		outcome = "approval_mismatch"
	case checkerConfigIdentity(CheckLocalAdministratorValidated, identity) != c.processIdentityDigest:
		outcome = "identity_changed"
	}
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckLocalAdministratorValidated), configurationIdentity, outcome)
	if outcome == "valid" {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckLocalAdministratorValidated, state, evidence)
}
func (c *LocalAdministratorChecker) String() string { return "setup local administrator checker" }
func (c *LocalAdministratorChecker) GoString() string {
	return "setup.LocalAdministratorChecker{<redacted>}"
}
func (c *LocalAdministratorChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}

// BackupSnapshotChecker validates one separate protected canonical copy of the current plan and receipt history.
type BackupSnapshotChecker struct{ backupPath, planIdentity, rootIdentity, configurationIdentity string }

// NewBackupSnapshotChecker binds a separate snapshot path to the exact current plan.
func NewBackupSnapshotChecker(primaryPath, backupPath string, plan Plan) (*BackupSnapshotChecker, error) {
	primary, backup, ok := separateSnapshotPaths(primaryPath, backupPath)
	if !ok || plan.Validate() != nil {
		return nil, ErrInvalidCheckerRuntime
	}
	value := primary + "\x00" + backup + "\x00" + plan.Identity() + "\x00" + plan.RootIdentity()
	return &BackupSnapshotChecker{backup, plan.Identity(), plan.RootIdentity(), checkerConfigIdentity(CheckBackupValidated, value)}, nil
}
func (c *BackupSnapshotChecker) Key() CheckKey { return CheckBackupValidated }
func (c *BackupSnapshotChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckBackupValidated)
}
func (c *BackupSnapshotChecker) Check(ctx context.Context, plan Plan) CheckResult {
	outcome, state := "valid", CheckBlocked
	switch {
	case !fileOwnershipSupported():
		outcome, state = "ownership_unavailable", CheckUnavailable
	case c == nil || ctx == nil || ctx.Err() != nil || plan.Validate() != nil:
		outcome = "invalid"
	case plan.Identity() != c.planIdentity || plan.RootIdentity() != c.rootIdentity:
		outcome = "plan_mismatch"
	default:
		snapshot, err := InspectBackupSnapshot(ctx, c.backupPath)
		if err != nil {
			outcome = "snapshot_invalid"
		} else if snapshot.Identity() != plan.Identity() || snapshot.RootIdentity() != plan.RootIdentity() {
			outcome = "snapshot_mismatch"
		}
	}
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckBackupValidated), configurationIdentity, outcome)
	if outcome == "valid" {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckBackupValidated, state, evidence)
}
func (c *BackupSnapshotChecker) String() string   { return "setup backup snapshot checker" }
func (c *BackupSnapshotChecker) GoString() string { return "setup.BackupSnapshotChecker{<redacted>}" }
func (c *BackupSnapshotChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}

// CreateBackupSnapshot writes one canonical protected copy after an exact current-plan fence.
func CreateBackupSnapshot(ctx context.Context, primaryPath, backupPath, expectedPlanIdentity string) (Plan, error) {
	if ctx == nil || ctx.Err() != nil || !nonzeroSetupDigest(expectedPlanIdentity) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	primary, backup, ok := separateSnapshotPaths(primaryPath, backupPath)
	if !ok {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	plan, err := InspectStateFile(ctx, primary)
	if err != nil {
		return Plan{}, err
	}
	if plan.Identity() != expectedPlanIdentity {
		return Plan{}, ErrStateConflict
	}
	if !fileOwnershipSupported() || !stablePrivateDirectory(filepath.Dir(backup)) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	if _, err = os.Lstat(backup); err == nil {
		return Plan{}, ErrBackupSnapshotExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	encoded, err := EncodePlan(plan)
	if err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	file, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Plan{}, ErrBackupSnapshotExists
		}
		return Plan{}, ErrInvalidBackupSnapshot
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(backup)
			_ = syncSetupDirectory(filepath.Dir(backup))
		}
	}()
	info, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(backup)
	if statErr != nil || pathErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) || !fileOwnedByCurrentProcess(info) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	if _, err = file.Write(encoded); err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	if err = file.Sync(); err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	if err = file.Close(); err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	if err = syncSetupDirectory(filepath.Dir(backup)); err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	if ctx.Err() != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	again, againErr := os.Lstat(backup)
	if againErr != nil || !again.Mode().IsRegular() || again.Mode().Perm() != 0o600 || !os.SameFile(info, again) || !stablePrivateDirectory(filepath.Dir(backup)) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	copied, readErr := InspectBackupSnapshot(ctx, backup)
	if readErr != nil || copied.Identity() != plan.Identity() {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	keep = true
	return copied, nil
}

// RestoreBackupSnapshot materializes a protected state file and receipt ledger without overwriting state.
func RestoreBackupSnapshot(ctx context.Context, snapshotPath, destinationPath, expectedRootIdentity, expectedPlanIdentity string) (Plan, error) {
	if ctx == nil || ctx.Err() != nil || !nonzeroSetupDigest(expectedRootIdentity) || !nonzeroSetupDigest(expectedPlanIdentity) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	snapshot, err := filepath.Abs(snapshotPath)
	if err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	destination, err := filepath.Abs(destinationPath)
	if err != nil || snapshot == destination || !fileOwnershipSupported() || !stablePrivateDirectory(filepath.Dir(destination)) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	plan, err := InspectBackupSnapshot(ctx, snapshot)
	if err != nil {
		return Plan{}, err
	}
	if plan.RootIdentity() != expectedRootIdentity || plan.Identity() != expectedPlanIdentity {
		return Plan{}, ErrStateConflict
	}
	if _, err = os.Lstat(destination); err == nil {
		return Plan{}, ErrStateConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return Plan{}, ErrInvalidStatePath
	}
	state, err := OpenStateFile(destination)
	if err != nil {
		return Plan{}, err
	}
	defer state.Close()
	if err = state.restoreSnapshot(ctx, plan); err != nil {
		return Plan{}, err
	}
	restored, err := state.Current(ctx)
	if err != nil || restored.Identity() != plan.Identity() {
		return Plan{}, ErrStatePersistence
	}
	return restored, nil
}
func (s *StateFile) restoreSnapshot(ctx context.Context, plan Plan) error {
	if s == nil || plan.Validate() != nil {
		return ErrInvalidBackupSnapshot
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateOperation(ctx); err != nil {
		return err
	}
	if _, err := os.Lstat(s.path); err == nil {
		return ErrStateConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrStatePersistence
	}
	entries, err := os.ReadDir(s.receiptRoot)
	if err != nil {
		return ErrStatePersistence
	}
	expected := make(map[string]CheckReceipt, len(plan.receipts))
	for index, receipt := range plan.receipts {
		expected[receiptRecordName(uint64(index)+2, receipt.Identity())] = receipt
	}
	for _, entry := range entries {
		want, ok := expected[entry.Name()]
		if !ok || entry.IsDir() {
			return ErrStateConflict
		}
		got, readErr := s.readReceipt(filepath.Join(s.receiptRoot, entry.Name()))
		if readErr != nil || got.Identity() != want.Identity() {
			return ErrStateConflict
		}
		delete(expected, entry.Name())
	}
	for index, receipt := range plan.receipts {
		if _, missing := expected[receiptRecordName(uint64(index)+2, receipt.Identity())]; missing {
			if err = s.persistReceipt(uint64(index)+2, receipt); err != nil {
				return err
			}
		}
	}
	if ctx.Err() != nil {
		return ErrStatePersistence
	}
	encoded, err := EncodePlan(plan)
	if err != nil {
		return err
	}
	return s.writeExclusive(encoded)
}

// InspectBackupSnapshot reads a stable protected snapshot without filesystem mutation.
func InspectBackupSnapshot(ctx context.Context, path string) (Plan, error) {
	if ctx == nil || ctx.Err() != nil || !fileOwnershipSupported() {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	absolute, err := filepath.Abs(path)
	if err != nil || !stablePrivateDirectory(filepath.Dir(absolute)) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	first, err := readBackupSnapshot(absolute)
	if err != nil {
		return Plan{}, err
	}
	if ctx.Err() != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	second, err := readBackupSnapshot(absolute)
	if err != nil || second.Identity() != first.Identity() || !stablePrivateDirectory(filepath.Dir(absolute)) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	return second, nil
}
func readBackupSnapshot(path string) (Plan, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || !fileOwnedByCurrentProcess(info) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	file, err := os.Open(path)
	if err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return Plan{}, ErrInvalidBackupSnapshot
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, maxSetupStateBytes+1))
	closeErr := file.Close()
	again, againErr := os.Lstat(path)
	if readErr != nil || closeErr != nil || len(encoded) == 0 || len(encoded) >= maxSetupStateBytes || againErr != nil || !os.SameFile(info, again) {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	plan, err := DecodePlan(encoded)
	if err != nil {
		return Plan{}, ErrInvalidBackupSnapshot
	}
	return plan, nil
}
func separateSnapshotPaths(primaryPath, backupPath string) (string, string, bool) {
	if primaryPath == "" || backupPath == "" {
		return "", "", false
	}
	primary, err := filepath.Abs(primaryPath)
	if err != nil {
		return "", "", false
	}
	backup, err := filepath.Abs(backupPath)
	if err != nil || primary == backup {
		return "", "", false
	}
	relative, relErr := filepath.Rel(filepath.Dir(primary), filepath.Dir(backup))
	if relErr != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", "", false
	}
	return primary, backup, true
}
