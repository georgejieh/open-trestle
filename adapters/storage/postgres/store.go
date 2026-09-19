package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
)

const maxStreamEvents = 10_000

// Store implements canonical review-run and audit ledgers in PostgreSQL.
type Store struct {
	database             *sql.DB
	publicationAuthority VerifiedPublicationAuthority
	notificationRandom   io.Reader
}

// New validates a database handle without applying migrations or opening a connection.
func New(database *sql.DB) (*Store, error) {
	if database == nil {
		return nil, ErrInvalidDatabase
	}
	return &Store{database: database, notificationRandom: rand.Reader}, nil
}

// NewWithPublicationAuthority verifies and binds one database-owned publication namespace.
func NewWithPublicationAuthority(ctx context.Context, database *sql.DB, expectedAuthorityIdentity string) (*Store, error) {
	verified, err := VerifyPublicationAuthority(ctx, database, expectedAuthorityIdentity)
	if err != nil {
		return nil, err
	}
	store, err := New(database)
	if err != nil {
		return nil, err
	}
	store.publicationAuthority = verified
	return store, nil
}

func validNonzeroDigest(value string) bool {
	if !validDigest(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, entry := range decoded {
		if entry != 0 {
			return true
		}
	}
	return false
}

func (s *Store) beginTenant(ctx context.Context, tenantID string, isolation sql.IsolationLevel) (*sql.Tx, error) {
	tx, err := s.beginTenantTransaction(ctx, tenantID, isolation)
	return tx, redactTransactionError(err)
}

func (s *Store) beginTenantTransaction(ctx context.Context, tenantID string, isolation sql.IsolationLevel) (*sql.Tx, error) {
	if s == nil || s.database == nil || nilContext(ctx) || ctx.Err() != nil || !validScopeValue(tenantID) {
		return nil, ErrInvalidDatabase
	}
	tx, err := s.database.BeginTx(ctx, &sql.TxOptions{Isolation: isolation})
	if err != nil {
		return nil, classifyTransactionError(err)
	}
	if _, err := tx.ExecContext(ctx, "SELECT set_config('open_trestle.tenant_id', $1, true)", tenantID); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return nil, ErrDatabaseUnavailable
		}
		return nil, classifyTransactionError(err)
	}
	return tx, nil
}

func ensureScope(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) error {
	return redactTransactionError(ensureScopeTransaction(ctx, tx, scope))
}

func ensureScopeTransaction(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_review_scopes
(tenant_id, repository_id, review_run_id, scope_identity)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity()); err != nil {
		return classifyTransactionError(err)
	}
	var identity string
	err := tx.QueryRowContext(ctx, `SELECT scope_identity
FROM open_trestle_review_scopes
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&identity)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCorruptRecord
	}
	if err != nil {
		return classifyTransactionError(err)
	}
	if identity != scope.Identity() {
		return ErrCorruptRecord
	}
	return nil
}

func lockScope(ctx context.Context, tx *sql.Tx, scopeIdentity string) error {
	return redactTransactionError(lockScopeTransaction(ctx, tx, scopeIdentity))
}

func lockScopeTransaction(ctx context.Context, tx *sql.Tx, scopeIdentity string) error {
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", scopeIdentity); err != nil {
		return classifyTransactionError(err)
	}
	return nil
}
func commit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value && strings.Trim(value, "0") != ""
}
func validScopeValue(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if candidate <= 0x20 || candidate == 0x7f {
			return false
		}
	}
	return true
}
func nilContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	value := reflect.ValueOf(ctx)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func (s *Store) String() string   { return "PostgreSQL runtime store" }
func (s *Store) GoString() string { return "postgres.Store{<redacted>}" }
func (s *Store) Format(state fmt.State, verb rune) {
	value := "PostgreSQL runtime store"
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = "postgres.Store{<redacted>}"
	}
	_, _ = state.Write([]byte(value))
}
