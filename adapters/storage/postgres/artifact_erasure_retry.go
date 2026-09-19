package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/georgejieh/open-trestle/artifact"
)

type erasureCommitOutcome uint8

const (
	erasureKnownAbort erasureCommitOutcome = iota
	erasureKnownCommit
	erasureCommitUnknown
)

// retryErasureMutation is only for database-only closures. Every closure must
// reset all outputs at entry. Only known commit permits callers to release them.
// Raw Commit errors are classified before redaction, unlike the frozen retry API.
func (s *Store) retryErasureMutation(ctx context.Context, tenant string, mutation func(*sql.Tx) error) (erasureCommitOutcome, error) {
	if nilContext(ctx) || s == nil || s.database == nil || mutation == nil || !validScopeValue(tenant) {
		return erasureKnownAbort, artifact.ErrErasureJournalUnavailable
	}
	for attempt := 0; attempt < serializableMutationAttempts; attempt++ {
		if ctx.Err() != nil {
			return erasureKnownAbort, artifact.ErrErasureJournalUnavailable
		}
		tx, err := s.beginTenantTransaction(ctx, tenant, sql.LevelSerializable)
		if err != nil {
			// The frozen begin helper only exposes this sentinel after known cleanup.
			if err == errTransactionAborted {
				continue
			}
			// Other begin-helper errors also cover failed GUC cleanup. The frozen
			// helper intentionally hides that distinction; do not claim known abort.
			return erasureCommitUnknown, artifact.ErrErasureUnknownOutcome
		}
		if err = mutation(tx); err != nil {
			rollbackErr := tx.Rollback()
			if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				return erasureCommitUnknown, artifact.ErrErasureUnknownOutcome
			}
			if err == errTransactionAborted || classifyTransactionError(err) == errTransactionAborted {
				if ctx.Err() != nil {
					return erasureKnownAbort, artifact.ErrErasureJournalUnavailable
				}
				continue
			}
			return erasureKnownAbort, erasurePublicError(err)
		}
		// This is the only dispatch-authorizing result. ErrTxDone after an unknown
		// Commit is not an observed rollback and cannot convert unknown into abort.
		raw := tx.Commit()
		if raw == nil {
			return erasureKnownCommit, nil
		}
		rollbackErr := tx.Rollback()
		if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return erasureCommitUnknown, artifact.ErrErasureUnknownOutcome
		}
		if classifyTransactionError(raw) == errTransactionAborted && ctx.Err() == nil {
			continue
		}
		return erasureCommitUnknown, artifact.ErrErasureUnknownOutcome
	}
	return erasureKnownAbort, artifact.ErrErasureJournalUnavailable
}

func erasurePublicError(err error) error {
	// Only fixed domain errors escape. Never return a driver message or joined raw error.
	for _, allowed := range []error{ErrCorruptRecord, artifact.ErrInvalidErasureContract,
		artifact.ErrErasureIdentityMismatch, artifact.ErrErasureAuthorityRequired,
		artifact.ErrErasureBindingMismatch, artifact.ErrErasureLegacyInventoryRequired,
		artifact.ErrErasureAdmissionMissing, artifact.ErrErasureConflict,
		artifact.ErrArtifactDeleted, artifact.ErrArtifactExpired,
		artifact.ErrErasureUnknownOutcome} {
		if errors.Is(err, allowed) {
			return allowed
		}
	}
	return artifact.ErrErasureJournalUnavailable
}
