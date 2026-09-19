package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ErrDatabaseAuthorityMismatch identifies missing, malformed, or substituted database authority.
var ErrDatabaseAuthorityMismatch = errors.New("PostgreSQL database authority mismatch")

// VerifiedDatabaseAuthority binds one migrated database, schema, runtime role, and durable namespace.
type VerifiedDatabaseAuthority struct{ identity, databaseName, schemaName, roleName, namespaceID string }

func (v VerifiedDatabaseAuthority) Identity() string            { return v.identity }
func (v VerifiedDatabaseAuthority) DatabaseNamespaceID() string { return v.namespaceID }
func (v VerifiedDatabaseAuthority) Validate() error {
	if !validDatabaseIdentifier(v.databaseName) || !validDatabaseIdentifier(v.schemaName) || !validDatabaseIdentifier(v.roleName) || !validNamespaceUUID(v.namespaceID) || v.identity != deriveDatabaseAuthorityIdentity(v) {
		return ErrDatabaseAuthorityMismatch
	}
	return nil
}

// VerifyDatabaseAuthority reads the singleton authority in a read-only transaction.
func VerifyDatabaseAuthority(ctx context.Context, database *sql.DB) (VerifiedDatabaseAuthority, error) {
	if ctx == nil || ctx.Err() != nil || database == nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseAuthorityMismatch
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelReadCommitted})
	if err != nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err = verifyDatabaseAuthoritySchemas(ctx, tx); err != nil {
		return VerifiedDatabaseAuthority{}, err
	}
	value, err := readDatabaseAuthority(ctx, tx)
	if err != nil {
		return VerifiedDatabaseAuthority{}, err
	}
	if err = tx.Commit(); err != nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseUnavailable
	}
	return value, nil
}

// VerifyDatabaseStorageAuthority verifies migrations and authority in one repeatable-read snapshot.
func VerifyDatabaseStorageAuthority(ctx context.Context, database *sql.DB) (VerifiedDatabaseAuthority, error) {
	if ctx == nil || ctx.Err() != nil || database == nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseAuthorityMismatch
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err = verifyDatabaseAuthoritySchemas(ctx, tx); err != nil {
		return VerifiedDatabaseAuthority{}, err
	}
	if err = verifyMigrationsTransaction(ctx, tx); err != nil {
		return VerifiedDatabaseAuthority{}, err
	}
	value, err := readDatabaseAuthority(ctx, tx)
	if err != nil {
		return VerifiedDatabaseAuthority{}, err
	}
	if err = tx.Commit(); err != nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseUnavailable
	}
	return value, nil
}
func verifyDatabaseAuthoritySchemas(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return ErrDatabaseAuthorityMismatch
	}
	var current string
	var migrations, authority sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT pg_catalog.current_schema(),
(SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_schema_migrations')),
(SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_database_authority'))`).Scan(&current, &migrations, &authority)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDatabaseAuthorityMismatch
		}
		return ErrDatabaseUnavailable
	}
	if !migrations.Valid || !authority.Valid || !validDatabaseIdentifier(current) || migrations.String != current || authority.String != current {
		return ErrDatabaseAuthorityMismatch
	}
	return nil
}

func readDatabaseAuthority(ctx context.Context, tx *sql.Tx) (VerifiedDatabaseAuthority, error) {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseAuthorityMismatch
	}
	var value VerifiedDatabaseAuthority
	err := tx.QueryRowContext(ctx, "SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true").Scan(&value.databaseName, &value.schemaName, &value.roleName, &value.namespaceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VerifiedDatabaseAuthority{}, ErrDatabaseAuthorityMismatch
		}
		return VerifiedDatabaseAuthority{}, ErrDatabaseUnavailable
	}
	value.namespaceID = strings.ToLower(value.namespaceID)
	value.identity = deriveDatabaseAuthorityIdentity(value)
	if value.Validate() != nil {
		return VerifiedDatabaseAuthority{}, ErrDatabaseAuthorityMismatch
	}
	return value, nil
}
func deriveDatabaseAuthorityIdentity(v VerifiedDatabaseAuthority) string {
	encoded, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Database  string `json:"database"`
		Schema    string `json:"schema"`
		Role      string `json:"role"`
		Namespace string `json:"namespace"`
	}{"open-trestle/postgresql-database-authority", 1, v.databaseName, v.schemaName, v.roleName, v.namespaceID})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func (v VerifiedDatabaseAuthority) String() string { return "verified PostgreSQL database authority" }
func (v VerifiedDatabaseAuthority) GoString() string {
	return "postgres.VerifiedDatabaseAuthority{<redacted>}"
}
func (v VerifiedDatabaseAuthority) Format(state fmt.State, verb rune) {
	value := v.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = v.GoString()
	}
	_, _ = state.Write([]byte(value))
}
