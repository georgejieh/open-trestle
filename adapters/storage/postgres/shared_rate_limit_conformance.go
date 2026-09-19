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
	"sync"
	"time"
)

const (
	sharedRateLimitConformanceLimit       uint32 = 2
	sharedRateLimitConformanceMaximumKeys        = 2
	sharedRateLimitConformanceWindow             = time.Minute
	sharedRateLimitConformanceRequests           = 8
)

var (
	ErrInvalidSharedRateLimitConformance     = errors.New("invalid shared rate-limit conformance")
	ErrSharedRateLimitConformanceUnavailable = errors.New("shared rate-limit conformance unavailable")
	ErrSharedRateLimitConformanceFailed      = errors.New("shared rate-limit conformance failed")
)

type SharedRateLimitConformanceObservation struct{ identity, authorityIdentity, runtimeAuthorityIdentity, configurationIdentity string }

func (o SharedRateLimitConformanceObservation) Identity() string          { return o.identity }
func (o SharedRateLimitConformanceObservation) AuthorityIdentity() string { return o.authorityIdentity }
func (o SharedRateLimitConformanceObservation) RuntimeAuthorityIdentity() string {
	return o.runtimeAuthorityIdentity
}
func (o SharedRateLimitConformanceObservation) Validate() error {
	if !validNonzeroDigest(o.authorityIdentity) || !validNonzeroDigest(o.runtimeAuthorityIdentity) || !validNonzeroDigest(o.configurationIdentity) || o.identity != sharedRateLimitObservationIdentity(o.authorityIdentity, o.runtimeAuthorityIdentity, o.configurationIdentity) {
		return ErrSharedRateLimitConformanceFailed
	}
	return nil
}
func (o SharedRateLimitConformanceObservation) String() string {
	return "shared rate-limit conformance observation"
}
func (o SharedRateLimitConformanceObservation) GoString() string {
	return "postgres.SharedRateLimitConformanceObservation{<redacted>}"
}
func (o SharedRateLimitConformanceObservation) Format(state fmt.State, verb rune) {
	value := o.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = o.GoString()
	}
	_, _ = state.Write([]byte(value))
}

// SharedRateLimitConformanceAuthorityIdentity binds runtime limits and the disposable setup probe.
func SharedRateLimitConformanceAuthorityIdentity(databaseAuthorityIdentity, credentialReferenceIdentity, setupRootIdentity string) (string, error) {
	if !validNonzeroDigest(databaseAuthorityIdentity) || !validNonzeroDigest(credentialReferenceIdentity) || !validNonzeroDigest(setupRootIdentity) {
		return "", ErrInvalidSharedRateLimitConformance
	}
	runtimeAuthority, err := RuntimeAPIRateLimitAuthorityIdentity(databaseAuthorityIdentity)
	if err != nil {
		return "", ErrInvalidSharedRateLimitConformance
	}
	namespace := sharedRateLimitConformanceNamespace(setupRootIdentity)
	configuration := SharedRateLimitConfig{Namespace: namespace, Limit: sharedRateLimitConformanceLimit, Window: sharedRateLimitConformanceWindow, MaximumKeys: sharedRateLimitConformanceMaximumKeys, DatabaseAuthorityIdentity: databaseAuthorityIdentity}
	keyDigests := []string{sharedRateLimitKeyDigest(namespace, "shared-key-a"), sharedRateLimitKeyDigest(namespace, "shared-key-b"), sharedRateLimitKeyDigest(namespace, "shared-key-c")}
	encoded, err := json.Marshal(struct {
		Contract                         string   `json:"contract"`
		SchemaVersion                    int      `json:"schema_version"`
		DatabaseAuthorityIdentity        string   `json:"database_authority_identity"`
		CredentialReferenceIdentity      string   `json:"credential_reference_identity"`
		SetupRootIdentity                string   `json:"setup_root_identity"`
		DatabaseAuthorityVerified        bool     `json:"database_authority_verified"`
		RuntimeAuthorityIdentity         string   `json:"runtime_authority_identity"`
		ConformanceConfigurationIdentity string   `json:"conformance_configuration_identity"`
		NamespaceDerivation              string   `json:"namespace_derivation"`
		SessionLock                      string   `json:"session_lock"`
		Limit                            uint32   `json:"limit"`
		WindowMilliseconds               int64    `json:"window_milliseconds"`
		MaximumKeys                      int      `json:"maximum_keys"`
		Requests                         int      `json:"requests"`
		SequentialOutcomes               []bool   `json:"sequential_outcomes"`
		CardinalityExhaustion            string   `json:"cardinality_exhaustion"`
		ConformanceKeyDigests            []string `json:"conformance_key_digests"`
		ForcedExpiryMethod               string   `json:"forced_expiry_method"`
		ForcedExpiryRows                 int      `json:"forced_expiry_rows"`
		ConcurrentAttempts               int      `json:"concurrent_attempts"`
		ConcurrentPermits                int      `json:"concurrent_permits"`
		ExpectedRows                     int      `json:"expected_rows"`
		FinalRequestCounts               []int    `json:"final_request_counts"`
		FinalWindowStates                []string `json:"final_window_states"`
		Cleanup                          string   `json:"cleanup"`
		ResidualAdmissionTTLMilliseconds int64    `json:"residual_admission_ttl_milliseconds"`
		ExpiredRowsRemovedOnRetry        bool     `json:"expired_rows_removed_on_retry"`
		NetworkRequests                  int      `json:"network_requests"`
	}{"open-trestle/postgres-shared-rate-limit-conformance-authority", 1, databaseAuthorityIdentity, credentialReferenceIdentity, setupRootIdentity, true, runtimeAuthority, sharedRateLimitConfigurationIdentity(configuration), "sha256_setup_root_prefix", "namespace_derived_session_advisory_lock", sharedRateLimitConformanceLimit, sharedRateLimitConformanceWindow.Milliseconds(), sharedRateLimitConformanceMaximumKeys, sharedRateLimitConformanceRequests, []bool{true, true, false, true, false, true}, "unavailable", keyDigests, "scoped_backdate_2m_1m", 2, 2, 1, 2, []int{2, 1}, []string{"active", "expired"}, "exact_namespace_delete_and_absence", sharedRateLimitConformanceWindow.Milliseconds(), true, 0})
	if err != nil {
		return "", ErrInvalidSharedRateLimitConformance
	}
	return digestSharedRateLimit(encoded), nil
}
func sharedRateLimitConformanceNamespace(root string) string {
	digest := sha256.Sum256([]byte("open-trestle/rate-limit-conformance-namespace/v1\x00" + root))
	return "conformance/" + hex.EncodeToString(digest[:16])
}
func sharedRateLimitConformanceLockID(root string) int64 {
	digest := sha256.Sum256([]byte("open-trestle/rate-limit-conformance-session-lock/v1\x00" + sharedRateLimitConformanceNamespace(root)))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

// VerifySharedRateLimitConformance runs two limiter instances against one verified database and cleans its namespace.
func VerifySharedRateLimitConformance(ctx context.Context, database *sql.DB, expectedDatabaseAuthorityIdentity, credentialReferenceIdentity, setupRootIdentity string) (observation SharedRateLimitConformanceObservation, returnErr error) {
	if ctx == nil || ctx.Err() != nil || database == nil || !validNonzeroDigest(expectedDatabaseAuthorityIdentity) {
		return observation, ErrInvalidSharedRateLimitConformance
	}
	verified, err := VerifyDatabaseStorageAuthority(ctx, database)
	if err != nil {
		if errors.Is(err, ErrDatabaseUnavailable) {
			return observation, ErrSharedRateLimitConformanceUnavailable
		}
		return observation, ErrInvalidSharedRateLimitConformance
	}
	if verified.Identity() != expectedDatabaseAuthorityIdentity {
		return observation, ErrInvalidSharedRateLimitConformance
	}
	authority, err := SharedRateLimitConformanceAuthorityIdentity(verified.Identity(), credentialReferenceIdentity, setupRootIdentity)
	if err != nil {
		return observation, err
	}
	namespace := sharedRateLimitConformanceNamespace(setupRootIdentity)
	lockID := sharedRateLimitConformanceLockID(setupRootIdentity)
	connection, err := database.Conn(ctx)
	if err != nil {
		return observation, ErrSharedRateLimitConformanceUnavailable
	}
	locked, ownsNamespace := false, false
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cleanupErr := cleanupSharedRateLimitConformance(cleanupContext, connection, namespace, locked, ownsNamespace, lockID)
		if cleanupErr != nil {
			observation = SharedRateLimitConformanceObservation{}
			returnErr = ErrSharedRateLimitConformanceUnavailable
		}
	}()
	if _, err = connection.ExecContext(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return observation, ErrSharedRateLimitConformanceUnavailable
	}
	locked = true
	if err = prepareSharedRateLimitConformance(ctx, connection, namespace); err != nil {
		return observation, err
	}
	ownsNamespace = true
	configuration := SharedRateLimitConfig{namespace, sharedRateLimitConformanceLimit, sharedRateLimitConformanceWindow, sharedRateLimitConformanceMaximumKeys, verified.Identity()}
	first, err := NewSharedRateLimiter(database, configuration)
	if err != nil {
		return observation, ErrSharedRateLimitConformanceFailed
	}
	second, err := NewSharedRateLimiter(database, configuration)
	if err != nil {
		return observation, ErrSharedRateLimitConformanceFailed
	}
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	sequential := make([]bool, 0, 6)
	for index, attempt := range []struct {
		limiter *SharedRateLimiter
		key     string
	}{{first, "shared-key-a"}, {second, "shared-key-a"}, {first, "shared-key-a"}, {first, "shared-key-b"}, {second, "shared-key-c"}} {
		allowed, allowErr := attempt.limiter.Allow(ctx, attempt.key, at)
		if index == 4 {
			if allowed || !errors.Is(allowErr, ErrSharedRateLimitCapacity) {
				return observation, ErrSharedRateLimitConformanceFailed
			}
			sequential = append(sequential, false)
			continue
		}
		if allowErr != nil {
			return observation, ErrSharedRateLimitConformanceUnavailable
		}
		sequential = append(sequential, allowed)
	}
	if len(sequential) != 5 || !sequential[0] || !sequential[1] || sequential[2] || !sequential[3] || sequential[4] {
		return observation, ErrSharedRateLimitConformanceFailed
	}
	result, err := connection.ExecContext(ctx, `UPDATE open_trestle_rate_limit_windows SET window_started_at = transaction_timestamp() - interval '2 minutes', expires_at = transaction_timestamp() - interval '1 minute' WHERE namespace = $1 AND configuration_identity = $2`, namespace, first.ConfigurationIdentity())
	if err != nil {
		return observation, ErrSharedRateLimitConformanceUnavailable
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 2 {
		return observation, ErrSharedRateLimitConformanceFailed
	}
	allowed, err := first.Allow(ctx, "shared-key-a", at)
	if err != nil || !allowed {
		if err != nil {
			return observation, ErrSharedRateLimitConformanceUnavailable
		}
		return observation, ErrSharedRateLimitConformanceFailed
	}
	sequential = append(sequential, allowed)
	concurrent := make(chan bool, 2)
	failures := make(chan error, 2)
	var wait sync.WaitGroup
	for _, limiter := range []*SharedRateLimiter{first, second} {
		wait.Add(1)
		go func(value *SharedRateLimiter) {
			defer wait.Done()
			permit, permitErr := value.Allow(ctx, "shared-key-a", at)
			if permitErr != nil {
				failures <- permitErr
				return
			}
			concurrent <- permit
		}(limiter)
	}
	wait.Wait()
	close(concurrent)
	close(failures)
	if len(failures) != 0 {
		return observation, ErrSharedRateLimitConformanceUnavailable
	}
	permits := 0
	for value := range concurrent {
		if value {
			permits++
		}
	}
	if permits != 1 {
		return observation, ErrSharedRateLimitConformanceFailed
	}
	keyA, keyB := sharedRateLimitKeyDigest(namespace, "shared-key-a"), sharedRateLimitKeyDigest(namespace, "shared-key-b")
	var count, matching, activeA, expiredB int
	if err = connection.QueryRowContext(ctx, `SELECT count(*),
count(*) FILTER (WHERE configuration_identity = $2 AND key_digest IN ($3, $4)),
count(*) FILTER (WHERE configuration_identity = $2 AND key_digest = $3 AND request_count = 2 AND expires_at > transaction_timestamp()),
count(*) FILTER (WHERE configuration_identity = $2 AND key_digest = $4 AND request_count = 1 AND expires_at <= transaction_timestamp())
FROM open_trestle_rate_limit_windows WHERE namespace = $1`, namespace, first.ConfigurationIdentity(), keyA, keyB).Scan(&count, &matching, &activeA, &expiredB); err != nil {
		return observation, ErrSharedRateLimitConformanceUnavailable
	}
	if count != 2 || matching != 2 || activeA != 1 || expiredB != 1 {
		return observation, ErrSharedRateLimitConformanceFailed
	}
	observation = SharedRateLimitConformanceObservation{authorityIdentity: authority, runtimeAuthorityIdentity: mustRuntimeRateLimitAuthority(verified.Identity()), configurationIdentity: first.ConfigurationIdentity()}
	observation.identity = sharedRateLimitObservationIdentity(observation.authorityIdentity, observation.runtimeAuthorityIdentity, observation.configurationIdentity)
	if observation.Validate() != nil {
		return SharedRateLimitConformanceObservation{}, ErrSharedRateLimitConformanceFailed
	}
	return observation, nil
}
func prepareSharedRateLimitConformance(ctx context.Context, connection *sql.Conn, namespace string) error {
	if _, err := connection.ExecContext(ctx, `DELETE FROM open_trestle_rate_limit_windows WHERE namespace = $1 AND expires_at <= transaction_timestamp()`, namespace); err != nil {
		return ErrSharedRateLimitConformanceUnavailable
	}
	var count int
	if err := connection.QueryRowContext(ctx, `SELECT count(*) FROM open_trestle_rate_limit_windows WHERE namespace = $1`, namespace).Scan(&count); err != nil {
		return ErrSharedRateLimitConformanceUnavailable
	}
	if count != 0 {
		return ErrSharedRateLimitConformanceUnavailable
	}
	return nil
}
func cleanupSharedRateLimitConformance(ctx context.Context, connection *sql.Conn, namespace string, locked, ownsNamespace bool, lockID int64) error {
	if connection == nil {
		return ErrSharedRateLimitConformanceUnavailable
	}
	if !locked {
		if err := connection.Close(); err != nil {
			return ErrSharedRateLimitConformanceUnavailable
		}
		return nil
	}
	if !ownsNamespace {
		var unlocked bool
		unlockErr := connection.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&unlocked)
		closeErr := connection.Close()
		if unlockErr != nil || !unlocked || closeErr != nil {
			return ErrSharedRateLimitConformanceUnavailable
		}
		return nil
	}
	_, deleteErr := connection.ExecContext(ctx, `DELETE FROM open_trestle_rate_limit_windows WHERE namespace = $1`, namespace)
	var count int
	countErr := connection.QueryRowContext(ctx, `SELECT count(*) FROM open_trestle_rate_limit_windows WHERE namespace = $1`, namespace).Scan(&count)
	var unlocked bool
	unlockErr := connection.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&unlocked)
	closeErr := connection.Close()
	if deleteErr != nil || countErr != nil || count != 0 || unlockErr != nil || !unlocked || closeErr != nil {
		return ErrSharedRateLimitConformanceUnavailable
	}
	return nil
}
func mustRuntimeRateLimitAuthority(databaseAuthority string) string {
	identity, _ := RuntimeAPIRateLimitAuthorityIdentity(databaseAuthority)
	return identity
}
func sharedRateLimitObservationIdentity(authority, runtime, configuration string) string {
	encoded, _ := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Authority     string `json:"authority_identity"`
		Runtime       string `json:"runtime_authority_identity"`
		Configuration string `json:"conformance_configuration_identity"`
	}{"open-trestle/postgres-shared-rate-limit-conformance-observation", 1, authority, runtime, configuration})
	return digestSharedRateLimit(encoded)
}
