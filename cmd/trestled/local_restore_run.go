package main

import (
	"context"
	"errors"
	"os"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

// localRestoreRun is a comparison witness, not receipt or restart authority.
type localRestoreRun struct {
	Scope              audit.ReviewScope
	ReceiptIdentity    string
	DiagnosticIdentity string
	AuditHeadIdentity  string
}

// inspectRestoredRun compares replayed identity and each persisted successful
// task output without applying artifact expiry or invoking any effect recovery.
func inspectRestoredRun(ctx context.Context, receipt controlplane.ReviewRunReceipt, artifacts, diagnosticRoot, auditRoot *os.Root, expected localRestoreRun) error {
	if ctx == nil || ctx.Err() != nil || receipt.Validate() != nil || expected.Scope.Validate() != nil || receipt.Scope().Identity() != expected.Scope.Identity() || receipt.Identity() != expected.ReceiptIdentity {
		return errRestoreObservationMismatch
	}
	for _, task := range receipt.Tasks() {
		if task.OutputIdentity() == "" {
			continue
		}
		value, err := artifact.ObserveFileArtifact(ctx, artifacts, receipt.Scope(), task.OutputIdentity())
		if errors.Is(err, artifact.ErrArtifactNotFound) {
			_, completed, deletionErr := artifact.ObserveFileDeletion(ctx, artifacts, receipt.Scope(), task.OutputIdentity())
			if deletionErr != nil || !completed {
				return errors.Join(errRestoreObservationMismatch, deletionErr)
			}
			continue
		}
		if err != nil {
			return err
		}
		if value.Identity() != task.OutputIdentity() || value.Scope().Identity() != receipt.Scope().Identity() {
			return errRestoreObservationMismatch
		}
	}
	set, err := diagnostics.ObserveFileSet(ctx, diagnosticRoot, receipt.Scope())
	if expected.DiagnosticIdentity == "" {
		if !errors.Is(err, diagnostics.ErrSetNotFound) {
			return errors.Join(errRestoreObservationMismatch, err)
		}
	} else {
		if err != nil {
			return err
		}
		if set.Identity() != expected.DiagnosticIdentity || set.Scope().Identity() != receipt.Scope().Identity() {
			return errRestoreObservationMismatch
		}
	}
	events, err := audit.ObserveFileStream(ctx, auditRoot, receipt.Scope())
	if err != nil {
		return err
	}
	head := ""
	if len(events) > 0 {
		head = events[len(events)-1].Identity()
	}
	if head != expected.AuditHeadIdentity {
		return errRestoreObservationMismatch
	}
	return nil
}
