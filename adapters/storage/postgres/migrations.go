// Package postgres provides tenant-scoped PostgreSQL persistence for canonical runtime ledgers.
package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
)

var (
	// ErrInvalidDatabase identifies a missing database or operation context.
	ErrInvalidDatabase = errors.New("invalid PostgreSQL store")
	// ErrDatabaseUnavailable identifies a failed database transaction or statement.
	ErrDatabaseUnavailable = errors.New("PostgreSQL store unavailable")
	// ErrMigrationConflict identifies a changed migration already recorded at the same version.
	ErrMigrationConflict = errors.New("PostgreSQL migration checksum conflict")
	// ErrCorruptRecord identifies canonical bytes inconsistent with indexed database fields.
	ErrCorruptRecord = errors.New("corrupt PostgreSQL store record")
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const migrationLockID int64 = 871_731_909_447_271

var orderedMigrations = []string{
	"migrations/0001_core.sql",
	"migrations/0002_diagnostic_metadata.sql",
	"migrations/0003_webhook_metadata.sql",
	"migrations/0004_artifact_metadata.sql",
	"migrations/0005_task_notifications.sql",
	"migrations/0006_publication_attempts.sql",
	"migrations/0007_publication_guard_authority.sql",
	"migrations/0008_database_authority.sql",
	"migrations/0009_shared_rate_limits.sql",
	"migrations/0010_artifact_kinds_and_origins.sql",
	"migrations/0011_investigation_artifact_kinds.sql",
	"migrations/0012_artifact_erasure.sql",
	"migrations/0013_artifact_erasure_resume.sql",
}

// VerifyMigrations confirms that every embedded migration was applied unchanged.
func VerifyMigrations(ctx context.Context, database *sql.DB) error {
	if ctx == nil || database == nil || ctx.Err() != nil {
		return ErrInvalidDatabase
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelReadCommitted})
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err = verifyDatabaseAuthoritySchemas(ctx, tx); err != nil {
		return err
	}
	if err = verifyMigrationsTransaction(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
func verifyMigrationsTransaction(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || tx == nil || ctx.Err() != nil {
		return ErrInvalidDatabase
	}
	rows, err := tx.QueryContext(ctx, "SELECT version, checksum FROM open_trestle_schema_migrations ORDER BY version ASC")
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var version int
		var checksum string
		if err = rows.Scan(&version, &checksum); err != nil {
			return ErrDatabaseUnavailable
		}
		index++
		if version != index || index > len(orderedMigrations) {
			return ErrMigrationConflict
		}
		want, checksumErr := migrationChecksum(orderedMigrations[index-1])
		if checksumErr != nil || checksum != want {
			return ErrMigrationConflict
		}
	}
	if rows.Err() != nil {
		return ErrDatabaseUnavailable
	}
	if err = rows.Close(); err != nil {
		return ErrDatabaseUnavailable
	}
	if index != len(orderedMigrations) {
		return ErrMigrationConflict
	}
	return nil
}

// ApplyMigrations applies the embedded schema under a transaction-scoped advisory lock.
func ApplyMigrations(ctx context.Context, database *sql.DB) error {
	if ctx == nil || database == nil || ctx.Err() != nil {
		return ErrInvalidDatabase
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockID); err != nil {
		return ErrDatabaseUnavailable
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS open_trestle_schema_migrations (
version integer PRIMARY KEY CHECK (version > 0),
checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
applied_at timestamptz NOT NULL DEFAULT transaction_timestamp()
)`); err != nil {
		return ErrDatabaseUnavailable
	}
	for index, name := range orderedMigrations {
		migration, err := migrationFiles.ReadFile(name)
		if err != nil {
			return ErrDatabaseUnavailable
		}
		checksum, err := migrationChecksum(name)
		if err != nil {
			return ErrDatabaseUnavailable
		}
		version := index + 1
		var existing string
		err = tx.QueryRowContext(ctx, "SELECT checksum FROM open_trestle_schema_migrations WHERE version = $1", version).Scan(&existing)
		if err == nil {
			if existing != checksum {
				return ErrMigrationConflict
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrDatabaseUnavailable
		}
		if _, err := tx.ExecContext(ctx, string(migration)); err != nil {
			return ErrDatabaseUnavailable
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO open_trestle_schema_migrations (version, checksum) VALUES ($1, $2)", version, checksum); err != nil {
			return ErrDatabaseUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}

func migrationChecksum(name string) (string, error) {
	migration, err := migrationFiles.ReadFile(name)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(migration)
	return hex.EncodeToString(digest[:]), nil
}
