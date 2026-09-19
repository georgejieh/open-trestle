package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

var ErrPublicationAuthorityMismatch = errors.New("PostgreSQL publication authority mismatch")

type VerifiedPublicationAuthority struct{ identity, databaseName, schemaName, namespaceID, authorityIdentity string }

func (v VerifiedPublicationAuthority) Identity() string            { return v.identity }
func (v VerifiedPublicationAuthority) DatabaseNamespaceID() string { return v.namespaceID }
func (v VerifiedPublicationAuthority) AuthorityIdentity() string   { return v.authorityIdentity }
func (v VerifiedPublicationAuthority) Validate() error {
	if !validDatabaseIdentifier(v.databaseName) || !validDatabaseIdentifier(v.schemaName) || !validNamespaceUUID(v.namespaceID) || !validNonzeroDigest(v.authorityIdentity) || v.identity != deriveVerifiedPublicationAuthorityIdentity(v) {
		return ErrPublicationAuthorityMismatch
	}
	return nil
}
func VerifyPublicationAuthority(ctx context.Context, database *sql.DB, expected string) (VerifiedPublicationAuthority, error) {
	if ctx == nil || ctx.Err() != nil || database == nil || !validNonzeroDigest(expected) {
		return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelReadCommitted})
	if err != nil {
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if err = verifyPublicationAuthoritySchema(ctx, tx); err != nil {
		return VerifiedPublicationAuthority{}, err
	}
	var value VerifiedPublicationAuthority
	err = tx.QueryRowContext(ctx, `SELECT pg_catalog.current_database(), pg_catalog.current_schema(), database_namespace_id::text, authority_identity FROM open_trestle_publication_guard_authority WHERE singleton = true`).Scan(&value.databaseName, &value.schemaName, &value.namespaceID, &value.authorityIdentity)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
		}
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	value.namespaceID = strings.ToLower(value.namespaceID)
	if value.authorityIdentity != expected {
		return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
	}
	value.identity = deriveVerifiedPublicationAuthorityIdentity(value)
	if value.Validate() != nil {
		return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
	}
	if err := tx.Commit(); err != nil {
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	return value, nil
}
func InitializePublicationAuthority(ctx context.Context, database *sql.DB, expected string) (VerifiedPublicationAuthority, error) {
	if ctx == nil || ctx.Err() != nil || database == nil || !validNonzeroDigest(expected) {
		return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
	}
	tx, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLockID); err != nil {
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	if err := verifyPublicationAuthoritySchema(ctx, tx); err != nil {
		return VerifiedPublicationAuthority{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_publication_guard_authority (authority_identity) VALUES ($1) ON CONFLICT (singleton) DO NOTHING`, expected); err != nil {
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	var value VerifiedPublicationAuthority
	err = tx.QueryRowContext(ctx, `SELECT pg_catalog.current_database(), pg_catalog.current_schema(), database_namespace_id::text, authority_identity FROM open_trestle_publication_guard_authority WHERE singleton = true`).Scan(&value.databaseName, &value.schemaName, &value.namespaceID, &value.authorityIdentity)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
		}
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	if value.authorityIdentity != expected {
		return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
	}
	value.namespaceID = strings.ToLower(value.namespaceID)
	value.identity = deriveVerifiedPublicationAuthorityIdentity(value)
	if value.Validate() != nil {
		return VerifiedPublicationAuthority{}, ErrPublicationAuthorityMismatch
	}
	if err := tx.Commit(); err != nil {
		return VerifiedPublicationAuthority{}, ErrDatabaseUnavailable
	}
	return value, nil
}
func verifyPublicationAuthoritySchema(ctx context.Context, tx *sql.Tx) error {
	if ctx == nil || ctx.Err() != nil || tx == nil {
		return ErrPublicationAuthorityMismatch
	}
	var current string
	var authority sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT pg_catalog.current_schema(),
(SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_publication_guard_authority'))`).Scan(&current, &authority)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrPublicationAuthorityMismatch
		}
		return ErrDatabaseUnavailable
	}
	if !authority.Valid || !validDatabaseIdentifier(current) || authority.String != current {
		return ErrPublicationAuthorityMismatch
	}
	return nil
}

func deriveVerifiedPublicationAuthorityIdentity(v VerifiedPublicationAuthority) string {
	encoded, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Database  string `json:"database"`
		Schema    string `json:"schema"`
		Namespace string `json:"namespace"`
		Authority string `json:"authority"`
	}{"open-trestle/postgresql-publication-authority", 1, v.databaseName, v.schemaName, v.namespaceID, v.authorityIdentity})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func validDatabaseIdentifier(value string) bool {
	return value != "" && len(value) <= 63 && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}
func validNamespaceUUID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
