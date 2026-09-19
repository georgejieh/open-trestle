package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func sharedLimiterFixture(t *testing.T, namespace string, limit uint32, maxKeys int) (*SharedRateLimiter, sqlmock.Sqlmock, *sql.DB) {
	t.Helper()
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewSharedRateLimiter(database, SharedRateLimitConfig{Namespace: namespace, Limit: limit, Window: time.Minute, MaximumKeys: maxKeys, DatabaseAuthorityIdentity: strings.Repeat("a", 64)})
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return limiter, mock, database
}
func TestSharedRateLimiterUpdatesExistingWindowWithoutRawKey(t *testing.T) {
	limiter, mock, _ := sharedLimiterFixture(t, "api/preauthentication/v1", 2, 10)
	raw := "192.0.2.10"
	digest := sharedRateLimitKeyDigest(limiter.namespace, raw)
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnRows(sqlmock.NewRows([]string{"allowed"}).AddRow(true))
	mock.ExpectCommit()
	allowed, err := limiter.Allow(context.Background(), raw, time.Unix(1000, 0))
	if err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSharedRateLimiterDeniesExistingExhaustedWindow(t *testing.T) {
	limiter, mock, _ := sharedLimiterFixture(t, "api/principal/v1", 1, 10)
	digest := sharedRateLimitKeyDigest(limiter.namespace, "principal")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(1), limiter.configurationIdentity).WillReturnRows(sqlmock.NewRows([]string{"allowed"}).AddRow(false))
	mock.ExpectCommit()
	allowed, err := limiter.Allow(context.Background(), "principal", time.Unix(1000, 0))
	if err != nil || allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSharedRateLimiterSerializesNewKeysAndBoundsCardinality(t *testing.T) {
	limiter, mock, _ := sharedLimiterFixture(t, "api/preauthentication/v1", 2, 2)
	digest := sharedRateLimitKeyDigest(limiter.namespace, "new")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(limiter.namespaceLockID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(sharedRateLimitCleanupSQL)).WithArgs(limiter.namespace).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitConflictSQL)).WithArgs(limiter.namespace, digest).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitCountSQL)).WithArgs(limiter.namespace).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectExec(regexp.QuoteMeta(sharedRateLimitInsertSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), limiter.configurationIdentity).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	allowed, err := limiter.Allow(context.Background(), "new", time.Unix(1000, 0))
	if err != nil || !allowed {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSharedRateLimiterDeniesNewKeyAtCapacity(t *testing.T) {
	limiter, mock, _ := sharedLimiterFixture(t, "api/preauthentication/v1", 2, 2)
	digest := sharedRateLimitKeyDigest(limiter.namespace, "new")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(limiter.namespaceLockID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(sharedRateLimitCleanupSQL)).WithArgs(limiter.namespace).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitConflictSQL)).WithArgs(limiter.namespace, digest).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitCountSQL)).WithArgs(limiter.namespace).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectRollback()
	allowed, err := limiter.Allow(context.Background(), "new", time.Unix(1000, 0))
	if allowed || !errors.Is(err, ErrSharedRateLimitCapacity) {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSharedRateLimiterFailsClosedOnDatabaseError(t *testing.T) {
	limiter, mock, _ := sharedLimiterFixture(t, "api/preauthentication/v1", 2, 2)
	mock.ExpectBegin().WillReturnError(errors.New("offline"))
	allowed, err := limiter.Allow(context.Background(), "key", time.Unix(1000, 0))
	if allowed || !errors.Is(err, ErrDatabaseUnavailable) {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestSharedRateLimiterConfigurationIdentityAndRuntimeAuthority(t *testing.T) {
	database, mock, _ := sqlmock.New()
	defer database.Close()
	_ = mock
	config := SharedRateLimitConfig{Namespace: "api/preauthentication/v1", Limit: 120, Window: time.Minute, MaximumKeys: 10000, DatabaseAuthorityIdentity: strings.Repeat("a", 64)}
	limiter, err := NewSharedRateLimiter(database, config)
	if err != nil {
		t.Fatal(err)
	}
	if limiter.ConfigurationIdentity() != "de475db7dd75e69b4366701b2bcaef398d624da719ec7b5adf19336675c52a6d" {
		t.Fatalf("identity=%s", limiter.ConfigurationIdentity())
	}
	authority, err := RuntimeAPIRateLimitAuthorityIdentity(strings.Repeat("a", 64))
	if err != nil || authority != "26dbfa70c0ca302aec17dedc432a9c1a344ae52260cda67ef5daba6e5a617139" {
		t.Fatalf("authority=%s err=%v", authority, err)
	}
	if changed, _ := RuntimeAPIRateLimitAuthorityIdentity(strings.Repeat("b", 64)); changed == authority {
		t.Fatal("database authority not bound")
	}
}
func TestNewSharedRateLimiterRejectsInvalidConfiguration(t *testing.T) {
	database, _, _ := sqlmock.New()
	defer database.Close()
	base := SharedRateLimitConfig{Namespace: "api/request/v1", Limit: 1, Window: time.Minute, MaximumKeys: 1, DatabaseAuthorityIdentity: strings.Repeat("a", 64)}
	for _, mutate := range []func(*SharedRateLimitConfig){func(c *SharedRateLimitConfig) { c.Namespace = " bad" }, func(c *SharedRateLimitConfig) { c.Limit = 0 }, func(c *SharedRateLimitConfig) { c.Window = time.Millisecond }, func(c *SharedRateLimitConfig) { c.MaximumKeys = 0 }, func(c *SharedRateLimitConfig) { c.DatabaseAuthorityIdentity = strings.Repeat("0", 64) }} {
		candidate := base
		mutate(&candidate)
		if limiter, err := NewSharedRateLimiter(database, candidate); limiter != nil || !errors.Is(err, ErrInvalidSharedRateLimiter) {
			t.Fatalf("limiter=%#v err=%v", limiter, err)
		}
	}
}

func TestSharedRateLimitConformanceAuthorityBindsDatabaseCredentialAndRoot(t *testing.T) {
	identity, err := SharedRateLimitConformanceAuthorityIdentity(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	if identity != "a1a0288f6ebbfe38b6903b92170e55a79deff5a3c270d95b7b1473ca706c5d93" {
		t.Fatalf("identity=%s", identity)
	}
	for _, values := range [][3]string{{strings.Repeat("d", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}, {strings.Repeat("a", 64), strings.Repeat("d", 64), strings.Repeat("c", 64)}, {strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 64)}} {
		changed, _ := SharedRateLimitConformanceAuthorityIdentity(values[0], values[1], values[2])
		if changed == identity {
			t.Fatal("authority input not bound")
		}
	}
}

func TestConformanceCleanupDoesNotDeleteNamespaceItDidNotAcquire(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_advisory_unlock($1)")).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"unlocked"}).AddRow(true))
	if err = cleanupSharedRateLimitConformance(context.Background(), connection, "conformance/test", true, false, 42); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestConformanceCleanupDeletesOwnedNamespaceAndProvesAbsence(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("DELETE FROM open_trestle_rate_limit_windows").WithArgs("conformance/test").WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectQuery("SELECT count").WithArgs("conformance/test").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_advisory_unlock($1)")).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"unlocked"}).AddRow(true))
	if err = cleanupSharedRateLimitConformance(context.Background(), connection, "conformance/test", true, true, 42); err != nil {
		t.Fatal(err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeAPIRateLimitersUseExactDistinctNamespaces(t *testing.T) {
	database, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	request, principal, err := NewRuntimeAPIRateLimiters(database, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if request.namespace != runtimeRequestRateLimitNamespace || request.limit != 120 || request.window != time.Minute || request.maximumKeys != 10000 || principal.namespace != runtimePrincipalRateLimitNamespace || principal.limit != 600 || principal.window != time.Minute || principal.maximumKeys != 1024 || request.ConfigurationIdentity() == principal.ConfigurationIdentity() {
		t.Fatalf("request=%#v principal=%#v", request, principal)
	}
}

func TestSharedRateLimiterFailsClosedOnLiveConfigurationMismatch(t *testing.T) {
	limiter, mock, _ := sharedLimiterFixture(t, "api/preauthentication/v1", 2, 2)
	digest := sharedRateLimitKeyDigest(limiter.namespace, "new")
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(limiter.namespaceLockID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitUpdateSQL)).WithArgs(limiter.namespace, digest, int64(time.Minute/time.Millisecond), int64(2), limiter.configurationIdentity).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(sharedRateLimitCleanupSQL)).WithArgs(limiter.namespace).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(sharedRateLimitConflictSQL)).WithArgs(limiter.namespace, digest).WillReturnRows(sqlmock.NewRows([]string{"configuration_identity"}).AddRow(strings.Repeat("f", 64)))
	mock.ExpectRollback()
	allowed, err := limiter.Allow(context.Background(), "new", time.Unix(1000, 0))
	if allowed || !errors.Is(err, ErrSharedRateLimitConfigurationConflict) {
		t.Fatalf("allowed=%v err=%v", allowed, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
