package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/apilimit"
)

const (
	runtimeRequestRateLimitNamespace   = "api/preauthentication/v1"
	runtimePrincipalRateLimitNamespace = "api/principal/v1"
	sharedRateLimitMaximumKeyBytes     = apilimit.MaximumKeyBytes
	sharedRateLimitMaximumLimit        = 10_000
	sharedRateLimitMaximumKeys         = 10_000
	sharedRateLimitMaximumWindow       = time.Hour
)

var (
	// ErrInvalidSharedRateLimiter identifies unsafe shared-limiter authority or operation input.
	ErrInvalidSharedRateLimiter = errors.New("invalid shared PostgreSQL rate limiter")
	// ErrSharedRateLimitCapacity identifies an exhausted namespace cardinality safety bound.
	ErrSharedRateLimitCapacity = errors.New("shared PostgreSQL rate limiter capacity unavailable")
	// ErrSharedRateLimitConfigurationConflict identifies a live row owned by different limiter authority.
	ErrSharedRateLimitConfigurationConflict = errors.New("shared PostgreSQL rate limiter configuration conflict")
)

const sharedRateLimitUpdateSQL = `WITH current AS (
    SELECT request_count, expires_at <= transaction_timestamp() AS expired
    FROM open_trestle_rate_limit_windows
    WHERE namespace = $1 AND key_digest = $2 AND configuration_identity = $5
    FOR UPDATE
), updated AS (
    UPDATE open_trestle_rate_limit_windows AS limits
    SET window_started_at = CASE WHEN current.expired THEN date_bin(make_interval(secs => $3 / 1000.0), transaction_timestamp(), timestamptz '2000-01-01 00:00:00+00') ELSE limits.window_started_at END,
        request_count = CASE WHEN current.expired THEN 1 WHEN current.request_count < $4 THEN current.request_count + 1 ELSE current.request_count END,
        expires_at = CASE WHEN current.expired THEN date_bin(make_interval(secs => $3 / 1000.0), transaction_timestamp(), timestamptz '2000-01-01 00:00:00+00') + make_interval(secs => $3 / 1000.0) ELSE limits.expires_at END
    FROM current
    WHERE limits.namespace = $1 AND limits.key_digest = $2 AND limits.configuration_identity = $5
    RETURNING CASE WHEN current.expired THEN true ELSE current.request_count < $4 END AS allowed
)
SELECT allowed FROM updated`
const sharedRateLimitCleanupSQL = `DELETE FROM open_trestle_rate_limit_windows WHERE namespace = $1 AND expires_at <= transaction_timestamp()`
const sharedRateLimitConflictSQL = `SELECT configuration_identity FROM open_trestle_rate_limit_windows WHERE namespace = $1 AND key_digest = $2`
const sharedRateLimitCountSQL = `SELECT count(*) FROM open_trestle_rate_limit_windows WHERE namespace = $1`
const sharedRateLimitInsertSQL = `WITH clock AS (
    SELECT date_bin(make_interval(secs => $3 / 1000.0), transaction_timestamp(), timestamptz '2000-01-01 00:00:00+00') AS window_started_at
)
INSERT INTO open_trestle_rate_limit_windows (namespace, key_digest, configuration_identity, window_started_at, request_count, expires_at)
SELECT $1, $2, $4, window_started_at, 1, window_started_at + make_interval(secs => $3 / 1000.0) FROM clock`

// SharedRateLimitConfig binds one bounded database fixed-window namespace.
type SharedRateLimitConfig struct {
	Namespace                 string
	Limit                     uint32
	Window                    time.Duration
	MaximumKeys               int
	DatabaseAuthorityIdentity string
}

// SharedRateLimiter enforces one database-clock fixed window across processes.
type SharedRateLimiter struct {
	database                                                    *sql.DB
	namespace, databaseAuthorityIdentity, configurationIdentity string
	limit                                                       uint32
	window                                                      time.Duration
	maximumKeys                                                 int
	namespaceLockID                                             int64
}

// NewSharedRateLimiter constructs a limiter without opening a connection or creating schema.
func NewSharedRateLimiter(database *sql.DB, configuration SharedRateLimitConfig) (*SharedRateLimiter, error) {
	if database == nil || !validSharedRateLimitNamespace(configuration.Namespace) || configuration.Limit == 0 || configuration.Limit > sharedRateLimitMaximumLimit || configuration.Window < time.Second || configuration.Window > sharedRateLimitMaximumWindow || configuration.Window%time.Millisecond != 0 || configuration.MaximumKeys <= 0 || configuration.MaximumKeys > sharedRateLimitMaximumKeys || !validNonzeroDigest(configuration.DatabaseAuthorityIdentity) {
		return nil, ErrInvalidSharedRateLimiter
	}
	identity := sharedRateLimitConfigurationIdentity(configuration)
	lockDigest := sha256.Sum256([]byte("open-trestle/postgres-rate-limit-lock/v1\x00" + configuration.DatabaseAuthorityIdentity + "\x00" + configuration.Namespace))
	return &SharedRateLimiter{database: database, namespace: strings.Clone(configuration.Namespace), databaseAuthorityIdentity: configuration.DatabaseAuthorityIdentity, configurationIdentity: identity, limit: configuration.Limit, window: configuration.Window, maximumKeys: configuration.MaximumKeys, namespaceLockID: int64(binary.BigEndian.Uint64(lockDigest[:8]))}, nil
}
func (l *SharedRateLimiter) ConfigurationIdentity() string {
	if l == nil {
		return ""
	}
	configuration := SharedRateLimitConfig{l.namespace, l.limit, l.window, l.maximumKeys, l.databaseAuthorityIdentity}
	if sharedRateLimitConfigurationIdentity(configuration) != l.configurationIdentity {
		return ""
	}
	return l.configurationIdentity
}
func (l *SharedRateLimiter) Allow(ctx context.Context, key string, at time.Time) (bool, error) {
	if l == nil || ctx == nil || ctx.Err() != nil || l.ConfigurationIdentity() == "" || len(key) == 0 || len(key) > sharedRateLimitMaximumKeyBytes || !utf8.ValidString(key) || at.IsZero() {
		return false, ErrInvalidSharedRateLimiter
	}
	digest := sharedRateLimitKeyDigest(l.namespace, key)
	tx, err := l.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, ErrDatabaseUnavailable
	}
	defer tx.Rollback()
	allowed, found, err := l.updateExisting(ctx, tx, digest)
	if err != nil {
		return false, err
	}
	if found {
		if err = tx.Commit(); err != nil {
			return false, ErrDatabaseUnavailable
		}
		return allowed, nil
	}
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", l.namespaceLockID); err != nil {
		return false, ErrDatabaseUnavailable
	}
	allowed, found, err = l.updateExisting(ctx, tx, digest)
	if err != nil {
		return false, err
	}
	if found {
		if err = tx.Commit(); err != nil {
			return false, ErrDatabaseUnavailable
		}
		return allowed, nil
	}
	if _, err = tx.ExecContext(ctx, sharedRateLimitCleanupSQL, l.namespace); err != nil {
		return false, ErrDatabaseUnavailable
	}
	var conflictingConfiguration string
	err = tx.QueryRowContext(ctx, sharedRateLimitConflictSQL, l.namespace, digest).Scan(&conflictingConfiguration)
	if err == nil {
		return false, ErrSharedRateLimitConfigurationConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, ErrDatabaseUnavailable
	}
	var count int64
	if err = tx.QueryRowContext(ctx, sharedRateLimitCountSQL, l.namespace).Scan(&count); err != nil || count < 0 || count > int64(l.maximumKeys) {
		return false, ErrDatabaseUnavailable
	}
	if count == int64(l.maximumKeys) {
		return false, ErrSharedRateLimitCapacity
	}
	result, err := tx.ExecContext(ctx, sharedRateLimitInsertSQL, l.namespace, digest, l.window.Milliseconds(), l.configurationIdentity)
	if err != nil {
		return false, ErrDatabaseUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return false, ErrDatabaseUnavailable
	}
	if err = tx.Commit(); err != nil {
		return false, ErrDatabaseUnavailable
	}
	return true, nil
}
func (l *SharedRateLimiter) updateExisting(ctx context.Context, tx *sql.Tx, digest string) (bool, bool, error) {
	var allowed bool
	err := tx.QueryRowContext(ctx, sharedRateLimitUpdateSQL, l.namespace, digest, l.window.Milliseconds(), int64(l.limit), l.configurationIdentity).Scan(&allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, ErrDatabaseUnavailable
	}
	return allowed, true, nil
}
func (l *SharedRateLimiter) String() string   { return "shared PostgreSQL rate limiter" }
func (l *SharedRateLimiter) GoString() string { return "postgres.SharedRateLimiter{<redacted>}" }
func (l *SharedRateLimiter) Format(state fmt.State, verb rune) {
	value := l.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = l.GoString()
	}
	_, _ = state.Write([]byte(value))
}

// NewRuntimeAPIRateLimiters constructs the exact request and principal limiters used by a PostgreSQL daemon.
func NewRuntimeAPIRateLimiters(database *sql.DB, databaseAuthorityIdentity string) (*SharedRateLimiter, *SharedRateLimiter, error) {
	request, err := NewSharedRateLimiter(database, runtimeRequestRateLimitConfig(databaseAuthorityIdentity))
	if err != nil {
		return nil, nil, err
	}
	principal, err := NewSharedRateLimiter(database, runtimePrincipalRateLimitConfig(databaseAuthorityIdentity))
	if err != nil {
		return nil, nil, err
	}
	return request, principal, nil
}

// RuntimeAPIRateLimitAuthorityIdentity derives the complete content-free runtime limiter authority.
func RuntimeAPIRateLimitAuthorityIdentity(databaseAuthorityIdentity string) (string, error) {
	if !validNonzeroDigest(databaseAuthorityIdentity) {
		return "", ErrInvalidSharedRateLimiter
	}
	request := runtimeRequestRateLimitConfig(databaseAuthorityIdentity)
	principal := runtimePrincipalRateLimitConfig(databaseAuthorityIdentity)
	type dimension struct {
		Namespace          string `json:"namespace"`
		Limit              uint32 `json:"limit"`
		WindowMilliseconds int64  `json:"window_milliseconds"`
		MaximumKeys        int    `json:"maximum_keys"`
	}
	encoded, err := json.Marshal(struct {
		Contract                       string    `json:"contract"`
		SchemaVersion                  int       `json:"schema_version"`
		DatabaseAuthorityIdentity      string    `json:"database_authority_identity"`
		MigrationVersion               int       `json:"migration_version"`
		Relation                       string    `json:"relation"`
		Clock                          string    `json:"clock"`
		Algorithm                      string    `json:"algorithm"`
		KeyDigest                      string    `json:"key_digest"`
		RawKeysStored                  bool      `json:"raw_keys_stored"`
		Isolation                      string    `json:"isolation"`
		ConfigurationMismatch          string    `json:"configuration_mismatch"`
		CardinalityExhaustion          string    `json:"cardinality_exhaustion"`
		ExistingKeyLock                string    `json:"existing_key_lock"`
		NewKeyLock                     string    `json:"new_key_lock"`
		ExpiredCleanup                 string    `json:"expired_cleanup"`
		FailurePosture                 string    `json:"failure_posture"`
		RequestKeyAuthority            string    `json:"request_key_authority"`
		PrincipalKeyAuthority          string    `json:"principal_key_authority"`
		Request                        dimension `json:"request"`
		Principal                      dimension `json:"principal"`
		OperationDeadlineMilliseconds  int64     `json:"operation_deadline_milliseconds"`
		DeniedHTTPStatus               int       `json:"denied_http_status"`
		DeniedErrorCode                string    `json:"denied_error_code"`
		DeniedRetryAfterSeconds        int       `json:"denied_retry_after_seconds"`
		UnavailableHTTPStatus          int       `json:"unavailable_http_status"`
		UnavailableErrorCode           string    `json:"unavailable_error_code"`
		UnavailableRetryAfterSeconds   int       `json:"unavailable_retry_after_seconds"`
		RequestConfigurationIdentity   string    `json:"request_configuration_identity"`
		PrincipalConfigurationIdentity string    `json:"principal_configuration_identity"`
	}{"open-trestle/postgres-runtime-api-rate-limit-authority", 1, databaseAuthorityIdentity, 9, "open_trestle_rate_limit_windows", "transaction_timestamp", "fixed_window", "sha256_domain_separated", false, "read_committed", "fail_closed_unavailable", "unavailable", "row_for_update", "namespace_advisory_transaction_lock", "bounded_namespace_delete", "fail_closed_unavailable", apilimit.RequestKeyAuthority, apilimit.PrincipalKeyAuthority, dimension{request.Namespace, request.Limit, request.Window.Milliseconds(), request.MaximumKeys}, dimension{principal.Namespace, principal.Limit, principal.Window.Milliseconds(), principal.MaximumKeys}, apilimit.OperationTimeout.Milliseconds(), apilimit.DeniedHTTPStatus, apilimit.DeniedErrorCode, apilimit.DeniedRetryAfterSeconds, apilimit.UnavailableHTTPStatus, apilimit.UnavailableErrorCode, apilimit.UnavailableRetryAfterSeconds, sharedRateLimitConfigurationIdentity(request), sharedRateLimitConfigurationIdentity(principal)})
	if err != nil {
		return "", ErrInvalidSharedRateLimiter
	}
	return digestSharedRateLimit(encoded), nil
}
func runtimeRequestRateLimitConfig(authority string) SharedRateLimitConfig {
	return SharedRateLimitConfig{runtimeRequestRateLimitNamespace, apilimit.RequestLimit, apilimit.Window, apilimit.RequestMaximumKeys, authority}
}
func runtimePrincipalRateLimitConfig(authority string) SharedRateLimitConfig {
	return SharedRateLimitConfig{runtimePrincipalRateLimitNamespace, apilimit.PrincipalLimit, apilimit.Window, apilimit.PrincipalMaximumKeys, authority}
}
func sharedRateLimitConfigurationIdentity(c SharedRateLimitConfig) string {
	encoded, _ := json.Marshal(struct {
		Contract                  string `json:"contract"`
		SchemaVersion             int    `json:"schema_version"`
		Namespace                 string `json:"namespace"`
		Limit                     uint32 `json:"limit"`
		WindowMilliseconds        int64  `json:"window_milliseconds"`
		MaximumKeys               int    `json:"maximum_keys"`
		MaximumKeyBytes           int    `json:"maximum_key_bytes"`
		DatabaseAuthorityIdentity string `json:"database_authority_identity"`
		Clock                     string `json:"clock"`
		KeyStorage                string `json:"key_storage"`
	}{"open-trestle/postgres-shared-rate-limiter", 1, c.Namespace, c.Limit, c.Window.Milliseconds(), c.MaximumKeys, sharedRateLimitMaximumKeyBytes, c.DatabaseAuthorityIdentity, "database_transaction", "sha256_digest_only"})
	return digestSharedRateLimit(encoded)
}
func sharedRateLimitKeyDigest(namespace, key string) string {
	return digestSharedRateLimit([]byte("key\x00" + namespace + "\x00" + key))
}
func digestSharedRateLimit(value []byte) string {
	digest := sha256.Sum256(append([]byte("open-trestle/postgres-shared-rate-limit/v1\x00"), value...))
	return hex.EncodeToString(digest[:])
}
func validSharedRateLimitNamespace(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, candidate := range value {
		if !(candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || index > 0 && (candidate == '.' || candidate == '_' || candidate == ':' || candidate == '/' || candidate == '-')) {
			return false
		}
	}
	return true
}
