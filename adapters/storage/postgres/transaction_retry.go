package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

const serializableMutationAttempts = 3

var errTransactionAborted = errors.New("PostgreSQL transaction aborted")

func classifyTransactionError(err error) error {
	if err == nil {
		return nil
	}
	var failure *pgconn.PgError
	if errors.As(err, &failure) && failure != nil && (failure.Code == "40001" || failure.Code == "40P01") {
		return errTransactionAborted
	}
	return ErrDatabaseUnavailable
}

func redactTransactionError(err error) error {
	if err == errTransactionAborted {
		return ErrDatabaseUnavailable
	}
	return err
}

// Only database-only mutations may run here; each attempt must recheck its authoritative state.
func (s *Store) retrySerializableMutation(ctx context.Context, tenantID string, contextDone error, mutation func(*sql.Tx) error) error {
	for attempt := 0; attempt < serializableMutationAttempts; attempt++ {
		if ctx.Err() != nil {
			return contextDone
		}
		err := s.serializableMutationAttempt(ctx, tenantID, mutation)
		if err != errTransactionAborted {
			return err
		}
		if ctx.Err() != nil {
			return contextDone
		}
	}
	return ErrDatabaseUnavailable
}

func (s *Store) serializableMutationAttempt(ctx context.Context, tenantID string, mutation func(*sql.Tx) error) (returnErr error) {
	tx, err := s.beginTenantTransaction(ctx, tenantID, sql.LevelSerializable)
	if err != nil {
		return err
	}
	defer func() {
		// Commit has already closed the transaction when Rollback returns ErrTxDone.
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) && returnErr == errTransactionAborted {
			returnErr = ErrDatabaseUnavailable
		}
	}()
	if err := mutation(tx); err != nil {
		return err
	}
	return classifyTransactionError(tx.Commit())
}
