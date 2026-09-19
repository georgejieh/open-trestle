package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

const journalSQLArtifactLock = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
const journalSQLAuthorityIdentity = `SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true`
const journalSQLAuthoritySchemas = `SELECT pg_catalog.current_schema(), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_schema_migrations')), (SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_database_authority'))`
const journalSQLMetadataInsert = `INSERT INTO open_trestle_artifacts (tenant_id, repository_id, review_run_id, scope_identity, artifact_identity, payload_digest, kind, classification, origin, protection, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`
const journalSQLMetadataRead = `SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at FROM open_trestle_artifacts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4`
const journalSQLMigrationRows = `SELECT version, checksum FROM open_trestle_schema_migrations ORDER BY version ASC`
const journalSQLScopeInsert = `INSERT INTO open_trestle_review_scopes (tenant_id, repository_id, review_run_id, scope_identity) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`
const journalSQLScopeRead = `SELECT scope_identity FROM open_trestle_review_scopes WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`
const journalSQLTenantGuc = `SELECT set_config('open_trestle.tenant_id', $1, true)`
const journalSQLAdmissionInsert = `INSERT INTO open_trestle_artifact_admissions (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, canonical_admission, canonical_namespace, admitted_policy, database_authority_identity, admitted_policy_identity, admitted_at_milliseconds, confirmed_version, confirmed_ciphertext_digest, confirmed_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NULL, NULL, NULL)`
const journalSQLAdmissionLockRead = `SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5 FOR UPDATE OF a`
const journalSQLAdmissionRead = `SELECT a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_admissions AS a LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.namespace_identity = $4 AND a.artifact_identity = $5`
const journalSQLConfirmationCas = `UPDATE open_trestle_artifact_admissions AS a SET confirmed_version = $8, confirmed_ciphertext_digest = $9, confirmed_at_milliseconds = $10 WHERE a.tenant_id = $1 AND a.repository_id = $2 AND a.review_run_id = $3 AND a.scope_identity = $4 AND a.namespace_identity = $5 AND a.artifact_identity = $6 AND a.admission_identity = $7 AND a.confirmed_version IS NULL AND a.confirmed_ciphertext_digest IS NULL AND a.confirmed_at_milliseconds IS NULL AND NOT EXISTS (SELECT 1 FROM open_trestle_artifact_erasure_operations AS o WHERE o.tenant_id = a.tenant_id AND o.repository_id = a.repository_id AND o.review_run_id = a.review_run_id AND o.namespace_identity = a.namespace_identity AND o.artifact_identity = a.artifact_identity)`
const journalSQLKeyOccupancy = `SELECT namespace_identity, admission_identity FROM open_trestle_artifact_admissions WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4`
const journalSQLLegacyLineage = `SELECT EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_authorizations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4), EXISTS (SELECT 1 FROM open_trestle_artifact_deletion_receipts WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4)`
const journalSQLOperationInsert = `INSERT INTO open_trestle_artifact_erasure_operations (tenant_id, repository_id, review_run_id, scope_identity, namespace_identity, artifact_identity, admission_identity, operation_identity, canonical_operation, canonical_authorization, accepted_policy, authorization_identity, authorization_document_digest, protected_policy_identity, database_authority_identity, prepared_at_milliseconds, accepted_at_milliseconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`
const journalSQLOperationPresence = `SELECT operation_identity FROM open_trestle_artifact_erasure_operations WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND namespace_identity = $4 AND artifact_identity = $5`
const journalSQLOperationRead = `SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.artifact_identity = $5`
const journalSQLOperationRefRead = `SELECT o.tenant_id, o.repository_id, o.review_run_id, o.scope_identity, o.namespace_identity, o.artifact_identity, o.admission_identity, o.operation_identity, o.canonical_operation, o.canonical_authorization, o.accepted_policy, o.authorization_identity, o.authorization_document_digest, o.protected_policy_identity, o.database_authority_identity, o.prepared_at_milliseconds, o.accepted_at_milliseconds, a.tenant_id, a.repository_id, a.review_run_id, a.scope_identity, a.namespace_identity, a.artifact_identity, a.admission_identity, a.canonical_admission, a.canonical_namespace, a.admitted_policy, a.database_authority_identity, a.admitted_policy_identity, a.admitted_at_milliseconds, a.confirmed_version, a.confirmed_ciphertext_digest, a.confirmed_at_milliseconds, s.scope_identity, m.scope_identity, m.artifact_identity, m.payload_digest, m.kind, m.classification, m.origin, m.protection, m.created_at, m.expires_at FROM open_trestle_artifact_erasure_operations AS o LEFT JOIN open_trestle_artifact_admissions AS a ON a.tenant_id = o.tenant_id AND a.repository_id = o.repository_id AND a.review_run_id = o.review_run_id AND a.scope_identity = o.scope_identity AND a.namespace_identity = o.namespace_identity AND a.artifact_identity = o.artifact_identity AND a.admission_identity = o.admission_identity LEFT JOIN open_trestle_review_scopes AS s ON s.tenant_id = a.tenant_id AND s.repository_id = a.repository_id AND s.review_run_id = a.review_run_id LEFT JOIN open_trestle_artifacts AS m ON m.tenant_id = a.tenant_id AND m.repository_id = a.repository_id AND m.review_run_id = a.review_run_id AND m.artifact_identity = a.artifact_identity WHERE o.tenant_id = $1 AND o.repository_id = $2 AND o.review_run_id = $3 AND o.namespace_identity = $4 AND o.operation_identity = $5`

// Query results are fully materialized only within a fixed row/column/byte bound.
// Scanning into any preserves SQL NULL and native driver types for strict checks.
func readErasureRows(ctx context.Context, tx *sql.Tx, query string, columns, maximum int, args ...any) ([][]any, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, classifyTransactionError(err)
	}
	defer rows.Close()
	var result [][]any
	size := 0
	for rows.Next() {
		if len(result) >= maximum {
			return nil, ErrCorruptRecord
		}
		row := make([]any, columns)
		dest := make([]any, columns)
		for i := range row {
			dest[i] = &row[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, classifyTransactionError(err)
		}
		for _, cell := range row {
			switch v := cell.(type) {
			case string:
				size += len(v)
				if len(v) > 16384 {
					return nil, ErrCorruptRecord
				}
			case []byte:
				size += len(v)
				if len(v) > 16384 {
					return nil, ErrCorruptRecord
				}
			case int64, bool, time.Time, nil:
			default:
				return nil, ErrCorruptRecord
			}
			if size > 2<<20 {
				return nil, ErrCorruptRecord
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, classifyTransactionError(err)
	}
	if err := rows.Close(); err != nil {
		return nil, classifyTransactionError(err)
	}
	return result, nil
}
func erasureText(row []any, i int) string          { v, _ := row[i].(string); return v }
func erasureInt(row []any, i int) int64            { v, _ := row[i].(int64); return v }
func erasureBool(row []any, i int, want bool) bool { v, ok := row[i].(bool); return ok && v == want }
func erasureExactText(row []any, i int, want string) bool {
	v, ok := row[i].(string)
	return ok && v == want
}
func erasureExactInt(row []any, i int, want int64) bool {
	v, ok := row[i].(int64)
	return ok && v == want
}
func erasureBytes(row []any, i, maximum int) ([]byte, bool) {
	v, ok := row[i].([]byte)
	return v, ok && len(v) > 0 && len(v) <= maximum
}
func erasureTime(row []any, i int, want time.Time) bool {
	v, ok := row[i].(time.Time)
	return ok && v.Equal(want)
}
func erasureDigest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func erasureNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func erasureVersion(v string) bool {
	if len(v) < 9 || len(v) > 512 || !utf8.ValidString(v) || !strings.HasPrefix(v, "version:") || v == "version:null" {
		return false
	}
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func erasureKeyArgs(scope audit.ReviewScope, identity string) []any {
	return []any{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), identity}
}
func erasureReadArgs(scope audit.ReviewScope, namespace, identity string) []any {
	return []any{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), namespace, identity}
}
func erasureInsertArgs(a artifact.ArtifactAdmission) []any {
	return []any{a.Scope().TenantID(), a.Scope().RepositoryID(), a.Scope().ReviewRunID(), a.Scope().Identity(), a.NamespaceIdentity(), a.ArtifactIdentity(), a.Identity()}
}
func execErasureOne(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return classifyTransactionError(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return classifyTransactionError(err)
	}
	if n != 1 {
		return ErrCorruptRecord
	}
	return nil
}
func ensureErasureScopeTransaction(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) error {
	result, err := tx.ExecContext(ctx, journalSQLScopeInsert, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity())
	if err != nil {
		return classifyTransactionError(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return classifyTransactionError(err)
	}
	if count < 0 || count > 1 {
		return ErrCorruptRecord
	}
	rows, err := readErasureRows(ctx, tx, journalSQLScopeRead, 1, 1, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
	if err != nil {
		return err
	}
	if len(rows) != 1 || !erasureExactText(rows[0], 0, scope.Identity()) {
		return ErrCorruptRecord
	}
	return nil
}

// VerifiedErasureIndex is an opaque snapshot bound to exactly one index and DB.
// It is not continuous catalog revocation or operational provider evidence.
type VerifiedErasureIndex struct {
	index            *ArtifactIndex
	database         *sql.DB
	authority        VerifiedDatabaseAuthority
	descriptorDigest string
}

func (VerifiedErasureIndex) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("verified erasure index{redacted}"))
}
func (VerifiedErasureIndex) String() string   { return "verified erasure index{redacted}" }
func (VerifiedErasureIndex) GoString() string { return "verified erasure index{redacted}" }
func (w VerifiedErasureIndex) matches(index *ArtifactIndex) bool {
	return index != nil && index.store != nil && index.store.database != nil && w.index == index && w.database == index.store.database && w.authority.Validate() == nil && w.descriptorDigest == erasureSchemaDescriptorDigest()
}
func VerifyArtifactErasureIndex(ctx context.Context, index *ArtifactIndex) (VerifiedErasureIndex, error) {
	if err := validateArtifactIndex(ctx, index); err != nil {
		return VerifiedErasureIndex{}, err
	}
	tx, err := index.store.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return VerifiedErasureIndex{}, artifact.ErrErasureJournalUnavailable
	}
	defer tx.Rollback()
	if err := verifyDatabaseAuthoritySchemas(ctx, tx); err != nil {
		return VerifiedErasureIndex{}, err
	}
	if err := verifyMigrationsTransaction(ctx, tx); err != nil {
		return VerifiedErasureIndex{}, err
	}
	authority, err := readDatabaseAuthority(ctx, tx)
	if err != nil {
		return VerifiedErasureIndex{}, err
	}
	if err := verifyArtifactErasureSchema(ctx, tx, authority.schemaName, authority.roleName); err != nil {
		return VerifiedErasureIndex{}, erasurePublicError(err)
	}
	if err := tx.Commit(); err != nil {
		return VerifiedErasureIndex{}, artifact.ErrErasureJournalUnavailable
	}
	return VerifiedErasureIndex{index: index, database: index.store.database, authority: authority, descriptorDigest: erasureSchemaDescriptorDigest()}, nil
}

type EnvelopeDependencies struct {
	Backend        *s3.Backend
	Keys           artifact.EnvelopeKeyProvider
	Clock          artifact.ErasureClock
	IndexAuthority VerifiedErasureIndex
}

func NewIndexedEnvelopeStore(index *ArtifactIndex, deps EnvelopeDependencies, policy artifact.ProtectedErasurePolicy) (*IndexedArtifactStore, error) {
	journal, err := newArtifactAdmissionJournal(index, deps.IndexAuthority, policy, deps.Clock)
	if err != nil {
		return nil, err
	}
	envelope, err := artifact.NewEnvelopeStoreWithAdmissionPreparation(artifact.EnvelopeAdmissionPreparationOptions{Backend: deps.Backend, Keys: deps.Keys, Journal: journal, Policy: policy, Clock: deps.Clock})
	if err != nil {
		return nil, err
	}
	return &IndexedArtifactStore{index: index, artifacts: envelope, admission: envelope, journal: journal}, nil
}

type artifactAdmissionJournal struct {
	index     *ArtifactIndex
	authority VerifiedErasureIndex
	policy    artifact.ProtectedErasurePolicy
	clock     artifact.ErasureClock
}

func (artifactAdmissionJournal) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact admission journal{redacted}"))
}
func newArtifactAdmissionJournal(index *ArtifactIndex, w VerifiedErasureIndex, policy artifact.ProtectedErasurePolicy, clock artifact.ErasureClock) (*artifactAdmissionJournal, error) {
	if !w.matches(index) {
		return nil, ErrDatabaseAuthorityMismatch
	}
	if policy.Validate() != nil {
		return nil, artifact.ErrErasureAuthorityRequired
	}
	if erasureNil(clock) {
		return nil, artifact.ErrInvalidErasureContract
	}
	if policy.DatabaseAuthorityIdentity() != w.authority.Identity() {
		return nil, artifact.ErrErasureBindingMismatch
	}
	return &artifactAdmissionJournal{index: index, authority: w, policy: policy, clock: clock}, nil
}
func (j *artifactAdmissionJournal) DatabaseAuthorityIdentity() string {
	if j == nil || !j.authority.matches(j.index) {
		return ""
	}
	return j.authority.authority.Identity()
}
func (j *artifactAdmissionJournal) validate(ctx context.Context, scope audit.ReviewScope, namespace, identity string) error {
	if nilContext(ctx) || ctx.Err() != nil {
		return artifact.ErrErasureJournalUnavailable
	}
	if scope.Validate() != nil || !validDigest(namespace) || !validDigest(identity) {
		return artifact.ErrInvalidErasureContract
	}
	if j == nil || !j.authority.matches(j.index) || erasureNil(j.clock) {
		return artifact.ErrErasureJournalRequired
	}
	if j.policy.Validate() != nil {
		return artifact.ErrErasureAuthorityRequired
	}
	if j.policy.DatabaseAuthorityIdentity() != j.DatabaseAuthorityIdentity() || j.policy.NamespaceIdentity() != namespace {
		return artifact.ErrErasureBindingMismatch
	}
	return nil
}

var _ artifact.AdmissionPreparationJournal = (*artifactAdmissionJournal)(nil)

type persistedAdmissionRow struct {
	admission                 artifact.ArtifactAdmission
	namespace                 artifact.StorageNamespace
	policy                    persistedErasurePolicy
	policyBytes               []byte
	version, ciphertextDigest string
	confirmedAt               int64
}

func (persistedAdmissionRow) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("persisted admission{redacted}"))
}

func (j *artifactAdmissionJournal) decodeAdmissionRow(row []any, scope audit.ReviewScope, namespace, identity string) (persistedAdmissionRow, error) {
	var result persistedAdmissionRow
	if len(row) != 26 {
		return result, ErrCorruptRecord
	}
	encoded, ok := erasureBytes(row, 7, 16384)
	if !ok {
		return result, ErrCorruptRecord
	}
	a, err := artifact.ParseArtifactAdmission(encoded)
	if err != nil {
		return result, ErrCorruptRecord
	}
	canonical, err := artifact.EncodeArtifactAdmission(a)
	if err != nil || !bytes.Equal(canonical, encoded) || a.Scope() != scope || a.NamespaceIdentity() != namespace || a.ArtifactIdentity() != identity || a.Protection() != artifact.ProtectionEnvelopeEncrypted {
		return result, ErrCorruptRecord
	}
	nsBytes, ok := erasureBytes(row, 8, 4096)
	if !ok {
		return result, ErrCorruptRecord
	}
	ns, err := artifact.ParseStorageNamespace(nsBytes)
	if err != nil || ns.Identity() != namespace {
		return result, ErrCorruptRecord
	}
	nsCanonical, err := artifact.EncodeStorageNamespace(ns)
	if err != nil || !bytes.Equal(nsBytes, nsCanonical) {
		return result, ErrCorruptRecord
	}
	policyBytes, ok := erasureBytes(row, 9, 16384)
	if !ok {
		return result, ErrCorruptRecord
	}
	policy, err := parsePersistedErasurePolicy(policyBytes)
	if err != nil || !policy.matchesNamespace(ns, j.DatabaseAuthorityIdentity()) || !policy.allows(a.AdmittedAt()) {
		return result, ErrCorruptRecord
	}
	// Stable configured namespace binding, but no current policy activity check on reads.
	if ns.BackendConfigurationIdentity() != j.policy.BackendConfigurationIdentity() || ns.Prefix() != j.policy.Prefix() || ns.NamespaceEpochIdentity() != j.policy.NamespaceEpochIdentity() {
		return result, artifact.ErrErasureBindingMismatch
	}
	expected := map[int]string{0: scope.TenantID(), 1: scope.RepositoryID(), 2: scope.ReviewRunID(), 3: scope.Identity(), 4: namespace, 5: identity, 6: a.Identity(), 10: j.DatabaseAuthorityIdentity(), 11: policy.Identity,
		16: scope.Identity(), 17: scope.Identity(), 18: identity, 19: a.PayloadDigest(), 20: a.Kind().String(), 21: a.Classification().String(), 22: a.Origin().String(), 23: a.Protection().String()}
	for i, want := range expected {
		if !erasureExactText(row, i, want) {
			return result, ErrCorruptRecord
		}
	}
	if !erasureExactInt(row, 12, a.AdmittedAt().UnixMilli()) || !erasureTime(row, 24, a.CreatedAt()) || !erasureTime(row, 25, a.ExpiresAt()) {
		return result, ErrCorruptRecord
	}
	if row[13] != nil || row[14] != nil || row[15] != nil {
		version, digest := erasureText(row, 13), erasureText(row, 14)
		millis := erasureInt(row, 15)
		if !erasureVersion(version) || !validDigest(digest) || millis <= 0 || millis > erasureMaxMilliseconds || millis < a.AdmittedAt().UnixMilli() || millis >= a.ExpiresAt().UnixMilli() || !policy.allows(time.UnixMilli(millis).UTC()) {
			return result, ErrCorruptRecord
		}
		result.version, result.ciphertextDigest, result.confirmedAt = version, digest, millis
	}
	result.admission, result.namespace, result.policy, result.policyBytes = a, ns, policy, policyBytes
	return result, nil
}
func (j *artifactAdmissionJournal) queryAdmission(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, namespace, identity string, lock bool) (persistedAdmissionRow, bool, error) {
	query := journalSQLAdmissionRead
	if lock {
		query = journalSQLAdmissionLockRead
	}
	rows, err := readErasureRows(ctx, tx, query, 26, 1, erasureReadArgs(scope, namespace, identity)...)
	if err != nil {
		return persistedAdmissionRow{}, false, err
	}
	if len(rows) == 0 {
		return persistedAdmissionRow{}, false, nil
	}
	result, err := j.decodeAdmissionRow(rows[0], scope, namespace, identity)
	if err != nil {
		return persistedAdmissionRow{}, false, err
	}
	return result, true, nil
}
func erasureNoLegacy(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, identity string) error {
	rows, err := readErasureRows(ctx, tx, journalSQLLegacyLineage, 2, 1, erasureKeyArgs(scope, identity)...)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return ErrCorruptRecord
	}
	for i := 0; i < 2; i++ {
		b, ok := rows[0][i].(bool)
		if !ok {
			return ErrCorruptRecord
		}
		if b {
			return artifact.ErrErasureLegacyInventoryRequired
		}
	}
	return nil
}
func erasureOccupancy(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, namespace, identity string) (bool, error) {
	rows, err := readErasureRows(ctx, tx, journalSQLKeyOccupancy, 2, 1, erasureKeyArgs(scope, identity)...)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	if !validDigest(erasureText(rows[0], 0)) || !validDigest(erasureText(rows[0], 1)) {
		return false, ErrCorruptRecord
	}
	if erasureText(rows[0], 0) != namespace {
		return false, artifact.ErrErasureConflict
	}
	return true, nil
}
func erasureUnprepared(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, namespace, identity string) error {
	rows, err := readErasureRows(ctx, tx, journalSQLOperationPresence, 1, 1, erasureReadArgs(scope, namespace, identity)...)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		return artifact.ErrArtifactDeleted
	}
	return nil
}
func (j *artifactAdmissionJournal) requireCurrentPolicy(row persistedAdmissionRow) error {
	if row.policy.Identity != j.policy.Identity() || !bytes.Equal(row.policyBytes, j.policy.Bytes()) {
		return artifact.ErrErasureConflict
	}
	return nil
}
func sameErasurePreimage(a, b artifact.ArtifactAdmission) bool {
	// Original artifact identity includes media type, provenance and all immutable
	// artifact fields. Both complete canonical records must already validate.
	return a.Validate() == nil && b.Validate() == nil && a.Scope() == b.Scope() && a.NamespaceIdentity() == b.NamespaceIdentity() && a.ArtifactIdentity() == b.ArtifactIdentity()
}

func (j *artifactAdmissionJournal) queryOperation(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, namespace, identity string, byRef bool) (artifact.ErasureOperation, bool, error) {
	query := journalSQLOperationRead
	if byRef {
		query = journalSQLOperationRefRead
	}
	rows, err := readErasureRows(ctx, tx, query, 43, 1, erasureReadArgs(scope, namespace, identity)...)
	if err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	if len(rows) == 0 {
		return artifact.ErasureOperation{}, false, nil
	}
	row := rows[0]
	encoded, ok := erasureBytes(row, 8, 16384)
	if !ok {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	// Explicit caller scope is mandatory. Parsed operations are metadata only.
	op, err := artifact.ParseErasureOperation(encoded, scope)
	if err != nil || op.NamespaceIdentity() != namespace || byRef && op.Identity() != identity || !byRef && op.ArtifactIdentity() != identity {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	canonical, err := artifact.EncodeErasureOperation(op)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	a, err := j.decodeAdmissionRow(row[17:], scope, namespace, op.ArtifactIdentity())
	if err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	authBytes, ok := erasureBytes(row, 9, 8192)
	if !ok {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	grant, err := artifact.ParseErasureAuthorizationV2(authBytes)
	if err != nil {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	authCanonical, err := artifact.EncodeErasureAuthorizationV2(grant)
	if err != nil || !bytes.Equal(authBytes, authCanonical) {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	policyBytes, ok := erasureBytes(row, 10, 16384)
	if !ok {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	policy, err := parsePersistedErasurePolicy(policyBytes)
	if err != nil || !policy.matchesNamespace(a.namespace, j.DatabaseAuthorityIdentity()) || !policy.matchesGrant(grant) || !bytes.Equal(policyBytes, a.policyBytes) {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	prepared, accepted := erasureInt(row, 15), erasureInt(row, 16)
	if prepared != op.PreparedAt().UnixMilli() || prepared < a.admission.AdmittedAt().UnixMilli() || accepted < prepared || accepted > erasureMaxMilliseconds ||
		!policy.allows(op.PreparedAt()) || !policy.allows(time.UnixMilli(accepted).UTC()) ||
		!grant.AllowsAdmission(a.admission, op.PreparedAt()) || !grant.AllowsAdmission(a.admission, time.UnixMilli(accepted).UTC()) {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	docDigest := erasureDigest(authBytes)
	expected := map[int]string{0: scope.TenantID(), 1: scope.RepositoryID(), 2: scope.ReviewRunID(), 3: scope.Identity(), 4: namespace, 5: op.ArtifactIdentity(), 6: a.admission.Identity(), 7: op.Identity(), 11: grant.Identity(), 12: docDigest, 13: policy.Identity, 14: j.DatabaseAuthorityIdentity()}
	for i, want := range expected {
		if !erasureExactText(row, i, want) {
			return artifact.ErasureOperation{}, false, ErrCorruptRecord
		}
	}
	if op.AdmissionIdentity() != a.admission.Identity() || op.OriginalAuthorizationIdentity() != grant.Identity() || op.AuthorizationDocumentDigest() != docDigest ||
		op.PolicyIdentity() != grant.PolicyIdentity() || op.ProtectedPolicyIdentity() != policy.Identity || op.Ownership() != policy.Ownership || op.ErasureProtocol() != policy.Protocol || op.LegacyReceiptIdentity() != "" {
		return artifact.ErasureOperation{}, false, ErrCorruptRecord
	}
	if err := erasureNoLegacy(ctx, tx, scope, op.ArtifactIdentity()); err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	return op, true, nil
}

func (j *artifactAdmissionJournal) AdmitArtifact(ctx context.Context, a artifact.ArtifactAdmission) (artifact.ArtifactAdmission, bool, error) {
	if err := j.validate(ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity()); err != nil {
		return artifact.ArtifactAdmission{}, false, err
	}
	if a.Validate() != nil {
		return artifact.ArtifactAdmission{}, false, artifact.ErrInvalidErasureContract
	}
	if a.Protection() != artifact.ProtectionEnvelopeEncrypted {
		return artifact.ArtifactAdmission{}, false, artifact.ErrStoreProtectionMismatch
	}
	now := j.clock.Now()
	if !validErasureInstant(now) || a.AdmittedAt().After(now) || now.Before(a.CreatedAt()) {
		return artifact.ArtifactAdmission{}, false, artifact.ErrInvalidErasureContract
	}
	if !now.Before(a.ExpiresAt()) {
		return artifact.ArtifactAdmission{}, false, artifact.ErrArtifactExpired
	}
	if !j.policy.AllowsAt(a.AdmittedAt()) || !j.policy.AllowsAt(now) {
		return artifact.ArtifactAdmission{}, false, artifact.ErrErasureBindingMismatch
	}
	ns, err := artifact.NewStorageNamespace(j.policy.BackendConfigurationIdentity(), j.policy.Prefix(), j.policy.NamespaceEpochIdentity())
	if err != nil || ns.Identity() != a.NamespaceIdentity() {
		return artifact.ArtifactAdmission{}, false, artifact.ErrErasureBindingMismatch
	}
	encoded, err := artifact.EncodeArtifactAdmission(a)
	if err != nil {
		return artifact.ArtifactAdmission{}, false, err
	}
	nsBytes, err := artifact.EncodeStorageNamespace(ns)
	if err != nil {
		return artifact.ArtifactAdmission{}, false, err
	}
	policyBytes := j.policy.Bytes()
	var winner artifact.ArtifactAdmission
	inserted := false
	scope := a.Scope()
	outcome, err := j.index.store.retryErasureMutation(ctx, scope.TenantID(), func(tx *sql.Tx) error {
		winner, inserted = artifact.ArtifactAdmission{}, false
		if err := lockScopeTransaction(ctx, tx, "artifact:"+scope.Identity()+":"+a.ArtifactIdentity()); err != nil {
			return err
		}
		if err := ensureErasureScopeTransaction(ctx, tx, scope); err != nil {
			return err
		}
		metadata, err := readErasureRows(ctx, tx, journalSQLMetadataRead, 7, 1, erasureKeyArgs(scope, a.ArtifactIdentity())...)
		if err != nil {
			return err
		}
		occupied, err := erasureOccupancy(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity())
		if err != nil {
			return err
		}
		if err := erasureNoLegacy(ctx, tx, scope, a.ArtifactIdentity()); err != nil {
			return err
		}
		if occupied {
			row, found, err := j.queryAdmission(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity(), true)
			if err != nil {
				return err
			}
			if !found {
				return ErrCorruptRecord
			}
			if err := j.requireCurrentPolicy(row); err != nil {
				return err
			}
			if !sameErasurePreimage(a, row.admission) {
				return artifact.ErrErasureConflict
			}
			if err := erasureUnprepared(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity()); err != nil {
				return err
			}
			winner = row.admission
			return nil
		}
		if len(metadata) != 0 {
			return artifact.ErrErasureLegacyInventoryRequired
		}
		if err := erasureUnprepared(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity()); err != nil {
			return err
		}
		if err := execErasureOne(ctx, tx, journalSQLMetadataInsert, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), a.ArtifactIdentity(), a.PayloadDigest(), a.Kind().String(), a.Classification().String(), a.Origin().String(), a.Protection().String(), a.CreatedAt(), a.ExpiresAt()); err != nil {
			return err
		}
		args := append(erasureInsertArgs(a), encoded, nsBytes, policyBytes, j.DatabaseAuthorityIdentity(), j.policy.Identity(), a.AdmittedAt().UnixMilli())
		if err := execErasureOne(ctx, tx, journalSQLAdmissionInsert, args...); err != nil {
			return err
		}
		winner, inserted = a, true
		return nil
	})
	if outcome != erasureKnownCommit || err != nil {
		return artifact.ArtifactAdmission{}, false, err
	}
	return winner, inserted, nil
}

func (j *artifactAdmissionJournal) ConfirmAdmission(ctx context.Context, a artifact.ArtifactAdmission, version, digest string, at time.Time) error {
	if err := j.validate(ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity()); err != nil {
		return err
	}
	if a.Validate() != nil || !erasureVersion(version) || !validDigest(digest) || !validErasureInstant(at) || at.Before(a.AdmittedAt()) {
		return artifact.ErrInvalidErasureContract
	}
	if !at.Before(a.ExpiresAt()) {
		return artifact.ErrArtifactExpired
	}
	if !j.policy.AllowsAt(at) {
		return artifact.ErrErasureBindingMismatch
	}
	now := j.clock.Now()
	if !validErasureInstant(now) || at.After(now) {
		return artifact.ErrInvalidErasureContract
	}
	if !now.Before(a.ExpiresAt()) {
		return artifact.ErrArtifactExpired
	}
	if !j.policy.AllowsAt(now) {
		return artifact.ErrErasureBindingMismatch
	}
	scope := a.Scope()
	outcome, err := j.index.store.retryErasureMutation(ctx, scope.TenantID(), func(tx *sql.Tx) error {
		if err := lockScopeTransaction(ctx, tx, "artifact:"+scope.Identity()+":"+a.ArtifactIdentity()); err != nil {
			return err
		}
		occupied, err := erasureOccupancy(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity())
		if err != nil {
			return err
		}
		if !occupied {
			return artifact.ErrErasureAdmissionMissing
		}
		row, found, err := j.queryAdmission(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity(), true)
		if err != nil {
			return err
		}
		if !found {
			return ErrCorruptRecord
		}
		if err := erasureNoLegacy(ctx, tx, scope, a.ArtifactIdentity()); err != nil {
			return err
		}
		if err := erasureUnprepared(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity()); err != nil {
			return err
		}
		if err := j.requireCurrentPolicy(row); err != nil {
			return err
		}
		if row.admission.Identity() != a.Identity() {
			return artifact.ErrErasureConflict
		}
		if row.version != "" {
			if row.version != version || row.ciphertextDigest != digest {
				return artifact.ErrErasureConflict
			}
			return nil // Preserve the first exact confirmation time.
		}
		result, err := tx.ExecContext(ctx, journalSQLConfirmationCas, append(erasureInsertArgs(a), version, digest, at.UnixMilli())...)
		if err != nil {
			return classifyTransactionError(err)
		}
		count, err := result.RowsAffected()
		if err != nil {
			return classifyTransactionError(err)
		}
		if count == 1 {
			return nil
		}
		if count != 0 {
			return ErrCorruptRecord
		}
		// Zero is never success, even if a reread looks identical. Diagnose state,
		// then roll back this attempt instead of inferring a successful CAS.
		if err := erasureUnprepared(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity()); err != nil {
			return err
		}
		if _, found, err := j.queryAdmission(ctx, tx, scope, a.NamespaceIdentity(), a.ArtifactIdentity(), true); err != nil {
			return err
		} else if !found {
			return ErrCorruptRecord
		}
		return artifact.ErrErasureConflict
	})
	if outcome != erasureKnownCommit {
		return err
	}
	return err
}

func (j *artifactAdmissionJournal) AcceptErasure(ctx context.Context, g artifact.ErasureAuthorizationV2, at time.Time) (artifact.ErasureOperation, bool, error) {
	if err := j.validate(ctx, g.Scope(), g.NamespaceIdentity(), g.ArtifactIdentity()); err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	if err := g.ValidateProtected(j.policy); err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	now := j.clock.Now()
	if !validErasureInstant(at) || !validErasureInstant(now) || at.After(now) {
		return artifact.ErasureOperation{}, false, artifact.ErrInvalidErasureContract
	}
	if !j.policy.AllowsAt(at) || !j.policy.AllowsAt(now) || at.Before(g.IssuedAt()) || !at.Before(g.ExpiresAt()) || now.Before(g.IssuedAt()) || !now.Before(g.ExpiresAt()) {
		return artifact.ErasureOperation{}, false, artifact.ErrErasureBindingMismatch
	}
	grantBytes, err := artifact.EncodeErasureAuthorizationV2(g)
	if err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	policyBytes := j.policy.Bytes()
	scope := g.Scope()
	var winner artifact.ErasureOperation
	inserted := false
	outcome, err := j.index.store.retryErasureMutation(ctx, scope.TenantID(), func(tx *sql.Tx) error {
		winner, inserted = artifact.ErasureOperation{}, false
		if err := lockScopeTransaction(ctx, tx, "artifact:"+scope.Identity()+":"+g.ArtifactIdentity()); err != nil {
			return err
		}
		occupied, err := erasureOccupancy(ctx, tx, scope, g.NamespaceIdentity(), g.ArtifactIdentity())
		if err != nil {
			return err
		}
		if !occupied {
			return artifact.ErrErasureAdmissionMissing
		}
		row, found, err := j.queryAdmission(ctx, tx, scope, g.NamespaceIdentity(), g.ArtifactIdentity(), true)
		if err != nil {
			return err
		}
		if !found {
			return ErrCorruptRecord
		}
		if err := erasureNoLegacy(ctx, tx, scope, g.ArtifactIdentity()); err != nil {
			return err
		}
		if err := j.requireCurrentPolicy(row); err != nil {
			return err
		}
		if at.Before(row.admission.AdmittedAt()) || !g.AllowsAdmission(row.admission, at) || !g.AllowsAdmission(row.admission, now) {
			return artifact.ErrErasureBindingMismatch
		}
		candidate, err := artifact.NewErasureOperationCandidate(g, row.admission, j.policy, at)
		if err != nil {
			return err
		}
		previous, found, err := j.queryOperation(ctx, tx, scope, g.NamespaceIdentity(), g.ArtifactIdentity(), false)
		if err != nil {
			return err
		}
		if found {
			if previous.OriginalAuthorizationIdentity() != g.Identity() || previous.AuthorizationDocumentDigest() != g.ProtectedDocumentDigest() || previous.ProtectedPolicyIdentity() != j.policy.Identity() {
				return artifact.ErrErasureConflict
			}
			winner = previous
			return nil
		}
		encoded, err := artifact.EncodeErasureOperation(candidate)
		if err != nil {
			return err
		}
		args := append(erasureInsertArgs(row.admission), candidate.Identity(), encoded, grantBytes, policyBytes, g.Identity(), g.ProtectedDocumentDigest(), j.policy.Identity(), j.DatabaseAuthorityIdentity(), at.UnixMilli(), now.UnixMilli())
		if err := execErasureOne(ctx, tx, journalSQLOperationInsert, args...); err != nil {
			return err
		}
		winner, inserted = candidate, true
		return nil
	})
	if outcome != erasureKnownCommit || err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	return winner, inserted, nil
}

// Journal reads use the frozen tenant helper: RR and ReadOnly=false. No writes,
// advisory locks, provider calls, clocks, or protected file loads occur here.
func (j *artifactAdmissionJournal) readSnapshot(ctx context.Context, scope audit.ReviewScope, read func(*sql.Tx) error) error {
	tx, err := j.index.store.beginTenantTransaction(ctx, scope.TenantID(), sql.LevelRepeatableRead)
	if err != nil {
		return erasurePublicError(err)
	}
	defer tx.Rollback()
	if err := read(tx); err != nil {
		return erasurePublicError(err)
	}
	if err := tx.Commit(); err != nil {
		return artifact.ErrErasureJournalUnavailable
	}
	return nil
}
func (j *artifactAdmissionJournal) ReadAdmission(ctx context.Context, scope audit.ReviewScope, namespace, identity string) (artifact.ArtifactAdmission, bool, error) {
	if err := j.validate(ctx, scope, namespace, identity); err != nil {
		return artifact.ArtifactAdmission{}, false, err
	}
	var result artifact.ArtifactAdmission
	found := false
	err := j.readSnapshot(ctx, scope, func(tx *sql.Tx) error {
		row, present, err := j.queryAdmission(ctx, tx, scope, namespace, identity, false)
		if err != nil {
			return err
		}
		if err := erasureNoLegacy(ctx, tx, scope, identity); err != nil {
			return err
		}
		if present {
			result, found = row.admission, true
		}
		return nil
	})
	if err != nil {
		return artifact.ArtifactAdmission{}, false, err
	}
	return result, found, nil
}
func (j *artifactAdmissionJournal) ReadPreparedErasure(ctx context.Context, ref artifact.ErasureOperationRef) (artifact.ErasureOperation, bool, error) {
	if err := j.validate(ctx, ref.Scope(), ref.NamespaceIdentity(), ref.OperationIdentity()); err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	if ref.Validate() != nil {
		return artifact.ErasureOperation{}, false, artifact.ErrInvalidErasureContract
	}
	var result artifact.ErasureOperation
	found := false
	err := j.readSnapshot(ctx, ref.Scope(), func(tx *sql.Tx) error {
		var err error
		result, found, err = j.queryOperation(ctx, tx, ref.Scope(), ref.NamespaceIdentity(), ref.OperationIdentity(), true)
		return err
	})
	if err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	return result, found, nil
}
func (j *artifactAdmissionJournal) FindPreparedErasure(ctx context.Context, scope audit.ReviewScope, namespace, identity string) (artifact.ErasureOperation, bool, error) {
	if err := j.validate(ctx, scope, namespace, identity); err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	var result artifact.ErasureOperation
	found := false
	err := j.readSnapshot(ctx, scope, func(tx *sql.Tx) error {
		// Validate the complete admission even when no operation exists. This also
		// makes the final Get check cover metadata corruption, not just presence.
		_, _, err := j.queryAdmission(ctx, tx, scope, namespace, identity, false)
		if err != nil {
			return err
		}
		if err := erasureNoLegacy(ctx, tx, scope, identity); err != nil {
			return err
		}
		result, found, err = j.queryOperation(ctx, tx, scope, namespace, identity, false)
		return err
	})
	if err != nil {
		return artifact.ErasureOperation{}, false, err
	}
	return result, found, nil
}

// CheckAdmissionReadable is a read check, not a Put permit or new authorization.
// The required admission and absence of preparation share one final snapshot.
func (j *artifactAdmissionJournal) CheckAdmissionReadable(ctx context.Context, expected artifact.ArtifactAdmission) error {
	if err := j.validate(ctx, expected.Scope(), expected.NamespaceIdentity(), expected.ArtifactIdentity()); err != nil {
		return err
	}
	if expected.Validate() != nil {
		return artifact.ErrInvalidErasureContract
	}
	expectedBytes, err := artifact.EncodeArtifactAdmission(expected)
	if err != nil {
		return err
	}
	return j.readSnapshot(ctx, expected.Scope(), func(tx *sql.Tx) error {
		row, found, err := j.queryAdmission(ctx, tx, expected.Scope(), expected.NamespaceIdentity(), expected.ArtifactIdentity(), false)
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureAdmissionMissing
		}
		actualBytes, err := artifact.EncodeArtifactAdmission(row.admission)
		if err != nil {
			return ErrCorruptRecord
		}
		if !bytes.Equal(actualBytes, expectedBytes) {
			return artifact.ErrErasureConflict
		}
		if err := erasureNoLegacy(ctx, tx, expected.Scope(), expected.ArtifactIdentity()); err != nil {
			return err
		}
		_, prepared, err := j.queryOperation(ctx, tx, expected.Scope(), expected.NamespaceIdentity(), expected.ArtifactIdentity(), false)
		if err != nil {
			return err
		}
		if prepared {
			return artifact.ErrArtifactDeleted
		}
		return nil
	})
}

func (s *IndexedArtifactStore) getIndexedAdmittedArtifact(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	// The core validates the payload against its original admission. Its final
	// journal snapshot validates every indexed metadata field against that same
	// admission and refuses preparation. Do not add a weaker separate read window.
	return s.admission.Get(ctx, scope, identity, at)
}
