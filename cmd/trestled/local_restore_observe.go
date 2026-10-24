package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

// observeLocalRecoveryPoint requires stopped in-place state, and never starts
// recovery, dispatch, or a listener. A true pending result is not restart approval.
// The point is provisional until retained assets are joined and the codec validates it.
func observeLocalRecoveryPoint(ctx context.Context, statePath string, repository evidence.RepositoryIdentity) (point localRecoveryPoint, pending bool, result error) {
	setupPath := filepath.Join(statePath, "setup", "plan.json")
	err := controlplane.WithRestoredJournal(ctx, statePath, func(stateRoot *os.Root, receipts []controlplane.ReviewRunReceipt) (callbackErr error) {
		snapshot, err := inspectLocalSourceOwnerRecordedSnapshot(ctx, statePath)
		if err != nil {
			return err
		}
		defer func() { callbackErr = errors.Join(callbackErr, snapshot.Close()) }()
		artifactRoot := snapshot.ArtifactRoot
		diagnosticsRoot, err := stateRoot.OpenRoot("diagnostics")
		if err != nil {
			return err
		}
		defer func() { callbackErr = errors.Join(callbackErr, diagnosticsRoot.Close()) }()
		auditRoot, err := stateRoot.OpenRoot("audit")
		if err != nil {
			return err
		}
		defer func() { callbackErr = errors.Join(callbackErr, auditRoot.Close()) }()
		type heldLock struct {
			lock *filelock.Lock
			root *os.Root
			leaf string
		}
		var locks []heldLock
		defer func() {
			for i := len(locks) - 1; i >= 0; i-- {
				callbackErr = errors.Join(callbackErr, locks[i].lock.Close())
			}
		}()
		for _, request := range []struct {
			path, leaf string
			root       *os.Root
		}{
			{filepath.Join(statePath, "artifacts", ".artifact-writer.lock"), ".artifact-writer.lock", artifactRoot},
			{filepath.Join(statePath, "diagnostics", ".diagnostic-writer.lock"), ".diagnostic-writer.lock", diagnosticsRoot},
			{filepath.Join(statePath, "audit", ".writer.lock"), ".writer.lock", auditRoot},
			{setupPath + ".lock", "", nil},
		} {
			lock, err := filelock.AcquireExisting(request.path)
			if err != nil {
				return err
			}
			locks = append(locks, heldLock{lock, request.root, request.leaf})
			var info os.FileInfo
			if request.root != nil {
				info, err = request.root.Lstat(request.leaf)
			} else {
				info, err = os.Lstat(request.path)
			}
			if err != nil || !recordedPrivateSingleLink(info) || !lock.SameFile(info) {
				return errRestoreObservationMismatch
			}
		}
		checkChild := func(name string, root *os.Root) error {
			linked, err := stateRoot.Lstat(name)
			if err != nil {
				return err
			}
			opened, err := root.Stat(".")
			if err != nil {
				return err
			}
			absolute, err := checkedLocalSourceDirectoryInfo(filepath.Join(statePath, name))
			if err != nil {
				return err
			}
			if !ownerDirectoryInfo(opened) || !recordedEqual(linked, opened) || !recordedEqual(absolute, opened) {
				return errRestoreObservationMismatch
			}
			return nil
		}
		for name, root := range map[string]*os.Root{"artifacts": artifactRoot, "diagnostics": diagnosticsRoot, "audit": auditRoot} {
			if err := checkChild(name, root); err != nil {
				return err
			}
		}
		before, err := inventoryRestoredTree(ctx, stateRoot)
		if err != nil {
			return err
		}
		for _, entry := range before {
			if strings.HasPrefix(entry.Path, "webhook-inbox/") {
				return errRestoreObservationMismatch
			}
		}
		owner, plan, err := inspectRestoredOwner(ctx, statePath, setupPath, stateRoot, artifactRoot, repository)
		if err != nil {
			return err
		}
		gitRoot, _, err := openDaemonLocalGitRoot(owner.GitObjectsPath, repository)
		if err != nil {
			return err
		}
		defer func() { callbackErr = errors.Join(callbackErr, gitRoot.Close()) }()
		gitBefore, err := inventoryRecoveryTree(ctx, gitRoot, true)
		if err != nil {
			return err
		}
		encodedOwner, err := encodeLocalSourceOwnerRecord(owner)
		if err != nil {
			return err
		}
		point = localRecoveryPoint{Contract: localRecoveryPointContract, Version: 1, StatePath: statePath, SetupPath: setupPath, RepositoryAuthority: repository.Authority(), RepositoryNamespace: repository.Namespace(), RepositoryName: repository.Name(), OwnerIdentity: localRecoveryBytesIdentity(encodedOwner), SetupIdentity: plan.Identity(), Entries: before, GitEntries: gitBefore, Runs: []localRecoveryRun{}}
		for _, receipt := range receipts {
			scope := receipt.Scope()
			if scope.TenantID() != plan.TenantID() || scope.RepositoryID() != plan.RepositoryID() {
				return errRestoreObservationMismatch
			}
			diagnosticIdentity := ""
			set, err := diagnostics.ObserveFileSet(ctx, diagnosticsRoot, scope)
			if err == nil {
				diagnosticIdentity = set.Identity()
			} else if !errors.Is(err, diagnostics.ErrSetNotFound) {
				return err
			}
			events, err := audit.ObserveFileStream(ctx, auditRoot, scope)
			if err != nil {
				return err
			}
			auditHead := ""
			if len(events) > 0 {
				auditHead = events[len(events)-1].Identity()
			}
			witness := localRestoreRun{Scope: scope, ReceiptIdentity: receipt.Identity(), DiagnosticIdentity: diagnosticIdentity, AuditHeadIdentity: auditHead}
			if err := inspectRestoredRun(ctx, receipt, artifactRoot, diagnosticsRoot, auditRoot, witness); err != nil {
				return err
			}
			point.Runs = append(point.Runs, localRecoveryRun{Tenant: scope.TenantID(), Repository: scope.RepositoryID(), Run: scope.ReviewRunID(), Receipt: receipt.Identity(), Diagnostic: diagnosticIdentity, AuditHead: auditHead})
			if receipt.Status() == controlplane.ReviewRunActive {
				pending = true
			}
		}
		if err := inspectRestoredStoreLeaves(ctx, stateRoot, artifactRoot, diagnosticsRoot, auditRoot, before, receipts); err != nil {
			return err
		}
		sort.Slice(point.Runs, func(i, j int) bool { return recoveryRunKey(point.Runs[i]) < recoveryRunKey(point.Runs[j]) })
		finalOwner, finalPlan, err := inspectRestoredOwner(ctx, statePath, setupPath, stateRoot, artifactRoot, repository)
		if err != nil {
			return err
		}
		if owner != finalOwner || plan.Identity() != finalPlan.Identity() {
			return errRestoreObservationMismatch
		}
		after, err := inventoryRestoredTree(ctx, stateRoot)
		if err != nil {
			return err
		}
		gitAfter, err := inventoryRecoveryTree(ctx, gitRoot, true)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(gitBefore, gitAfter) {
			return errRestoreObservationMismatch
		}
		if !reflect.DeepEqual(before, after) {
			return errRestoreObservationMismatch
		}
		if err := recheckLocalSourceOwnerRecordedSnapshot(ctx, snapshot, stateRoot, artifactRoot); err != nil {
			return err
		}
		for name, root := range map[string]*os.Root{"artifacts": artifactRoot, "diagnostics": diagnosticsRoot, "audit": auditRoot} {
			if err := checkChild(name, root); err != nil {
				return err
			}
		}
		for _, held := range locks {
			var info os.FileInfo
			if held.root != nil {
				info, err = held.root.Lstat(held.leaf)
			} else {
				info, err = os.Lstat(setupPath + ".lock")
			}
			if err != nil || !recordedPrivateSingleLink(info) || !held.lock.SameFile(info) {
				return errRestoreObservationMismatch
			}
		}
		return nil
	})
	if err != nil {
		return localRecoveryPoint{}, false, err
	}
	return point, pending, nil
}
