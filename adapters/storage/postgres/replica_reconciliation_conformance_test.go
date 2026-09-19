package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestReplicaReconciliationConformanceAuthorityBindsDatabaseCredentialAndRoot(t *testing.T) {
	identity, err := ReplicaReconciliationConformanceAuthorityIdentity(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
	if err != nil || identity != "13f5f7d7f23316efed4047b6a4ec9c096509af2d78bde21aab59b91f0742901e" {
		t.Fatalf("identity=%s err=%v", identity, err)
	}
	repeated, err := ReplicaReconciliationConformanceAuthorityIdentity(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
	if err != nil || repeated != identity {
		t.Fatalf("repeated=%s err=%v", repeated, err)
	}
	for _, values := range [][3]string{{strings.Repeat("d", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}, {strings.Repeat("a", 64), strings.Repeat("d", 64), strings.Repeat("c", 64)}, {strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("d", 64)}} {
		changed, changeErr := ReplicaReconciliationConformanceAuthorityIdentity(values[0], values[1], values[2])
		if changeErr != nil || changed == identity {
			t.Fatalf("changed=%s err=%v", changed, changeErr)
		}
	}
}

func TestReplicaReconciliationConformanceConvergesTwoRuntimes(t *testing.T) {
	root := strings.Repeat("c", 64)
	databaseAuthority := strings.Repeat("a", 64)
	credentialReference := strings.Repeat("b", 64)
	authority, err := ReplicaReconciliationConformanceAuthorityIdentity(databaseAuthority, credentialReference, root)
	if err != nil {
		t.Fatal(err)
	}
	plan, outputIdentity, err := replicaReconciliationFixturePlan(root)
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	queue := controlplane.NewMemoryTaskNotificationQueue()
	runtime := replicaReconciliationRuntime{journal: journal, queue: queue}
	observation, err := runReplicaReconciliationConformance(context.Background(), runtime, runtime, plan, outputIdentity, authority, time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if observation.Validate() != nil || observation.AuthorityIdentity() != authority || observation.PlanIdentity() != plan.Identity() || observation.OutputIdentity() != outputIdentity {
		t.Fatalf("observation=%#v", observation)
	}
}

func TestReplicaReconciliationPreparationRejectsUnknownPlanWithoutDelete(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	plan, outputIdentity, err := replicaReconciliationFixturePlan(strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(plan.Scope().TenantID()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(plan.Scope().Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(plan.Scope().TenantID(), plan.Scope().RepositoryID(), plan.Scope().ReviewRunID()).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationPlanSQL)).WithArgs(plan.Scope().TenantID(), plan.Scope().RepositoryID(), plan.Scope().ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(strings.Repeat("d", 64), []byte("{}")))
	mock.ExpectRollback()
	if err := prepareReplicaReconciliationConformance(context.Background(), connection, plan, outputIdentity); !errors.Is(err, ErrReplicaReconciliationConformanceFailed) {
		t.Fatalf("err=%v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReplicaReconciliationPreparationDeletesOnlyValidatedPriorFixture(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	plan, outputIdentity, err := replicaReconciliationFixturePlan(strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := controlplane.EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	scope := plan.Scope()
	arguments := []driver.Value{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(scope.TenantID()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationPlanSQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(plan.Identity(), encoded))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteNotificationsSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteEventsSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeletePlanSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteScopeSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectCommit()
	if err := prepareReplicaReconciliationConformance(context.Background(), connection, plan, outputIdentity); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReplicaReconciliationPreparationDeletesValidatedPartialRun(t *testing.T) {
	root := strings.Repeat("c", 64)
	plan, outputIdentity, err := replicaReconciliationFixturePlan(root)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(context.Background(), plan, at); err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Advance(context.Background(), plan, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task(replicaReconciliationTaskKey)
	notification, err := controlplane.NewTaskNotification(state, runtime, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	planBytes, _ := controlplane.EncodeReviewRunPlan(plan)
	eventRows := sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event"})
	for _, event := range events {
		encoded, encodeErr := controlplane.EncodeRunEvent(event)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		eventRows.AddRow(event.Sequence(), event.Identity(), encoded)
	}
	noticeBytes, err := controlplane.EncodeTaskNotification(notification)
	if err != nil {
		t.Fatal(err)
	}
	noticeDigest := sha256.Sum256(noticeBytes)

	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	scope := plan.Scope()
	arguments := []driver.Value{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(scope.TenantID()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(1, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationPlanSQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(plan.Identity(), planBytes))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationEventsSQL)).WithArgs(arguments...).WillReturnRows(eventRows)
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationNotificationsSQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows([]string{"notice_identity", "canonical_notice", "canonical_checksum", "delivery_count", "lease_worker_identity", "lease_token_identity", "leased_at", "lease_expires_at", "acknowledged_at"}).AddRow(notification.Identity(), noticeBytes, hex.EncodeToString(noticeDigest[:]), 0, nil, nil, nil, nil, nil))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteNotificationsSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteEventsSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 2))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeletePlanSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteScopeSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectCommit()
	if err := prepareReplicaReconciliationConformance(context.Background(), connection, plan, outputIdentity); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReplicaReconciliationCleanupDoesNotDeleteScopeItDidNotAcquire(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan, outputIdentity, err := replicaReconciliationFixturePlan(strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_advisory_unlock($1)")).WithArgs(int64(42)).WillReturnRows(sqlmock.NewRows([]string{"unlocked"}).AddRow(true))
	if err := cleanupReplicaReconciliationConformance(context.Background(), connection, plan, outputIdentity, true, false, 42); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReplicaReconciliationPreparationDeletesValidatedCompletedRun(t *testing.T) {
	root := strings.Repeat("c", 64)
	plan, outputIdentity, err := replicaReconciliationFixturePlan(root)
	if err != nil {
		t.Fatal(err)
	}
	authority, _ := ReplicaReconciliationConformanceAuthorityIdentity(strings.Repeat("a", 64), strings.Repeat("b", 64), root)
	at := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	journal := controlplane.NewMemoryRunJournal()
	queue := controlplane.NewMemoryTaskNotificationQueue()
	runtime := replicaReconciliationRuntime{journal: journal, queue: queue}
	observation, err := runReplicaReconciliationConformance(context.Background(), runtime, runtime, plan, outputIdentity, authority, at)
	if err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(context.Background(), plan.Scope(), 0, 10)
	if err != nil || len(events) != 5 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	noticeJournal := controlplane.NewMemoryRunJournal()
	noticeCoordinator, _ := controlplane.NewCoordinator(noticeJournal)
	_, _ = noticeCoordinator.Open(context.Background(), plan, at)
	noticeState, _ := noticeCoordinator.Advance(context.Background(), plan, at.Add(time.Millisecond))
	noticeRuntime, _ := noticeState.Task(replicaReconciliationTaskKey)
	notification, err := controlplane.NewTaskNotification(noticeState, noticeRuntime, at.Add(time.Millisecond))
	if err != nil || notification.Identity() != observation.notificationIdentity {
		t.Fatalf("notification=%#v err=%v", notification, err)
	}
	planBytes, _ := controlplane.EncodeReviewRunPlan(plan)
	eventRows := sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event"})
	for _, event := range events {
		encoded, encodeErr := controlplane.EncodeRunEvent(event)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		eventRows.AddRow(event.Sequence(), event.Identity(), encoded)
	}
	noticeBytes, _ := controlplane.EncodeTaskNotification(notification)
	noticeDigest := sha256.Sum256(noticeBytes)
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	connection, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	scope := plan.Scope()
	arguments := []driver.Value{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(scope.TenantID()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(1, 1, 5, 1, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationPlanSQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(plan.Identity(), planBytes))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationEventsSQL)).WithArgs(arguments...).WillReturnRows(eventRows)
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationNotificationsSQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows([]string{"notice_identity", "canonical_notice", "canonical_checksum", "delivery_count", "lease_worker_identity", "lease_token_identity", "leased_at", "lease_expires_at", "acknowledged_at"}).AddRow(notification.Identity(), noticeBytes, hex.EncodeToString(noticeDigest[:]), 1, nil, nil, nil, nil, at.Add(3*time.Millisecond)))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteNotificationsSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteEventsSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 5))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeletePlanSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(replicaReconciliationDeleteScopeSQL)).WithArgs(arguments...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(regexp.QuoteMeta(replicaReconciliationInventorySQL)).WithArgs(arguments...).WillReturnRows(sqlmock.NewRows(replicaReconciliationInventoryColumns).AddRow(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
	mock.ExpectCommit()
	if err := prepareReplicaReconciliationConformance(context.Background(), connection, plan, outputIdentity); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestReplicaReconciliationClassifiesCorruptionSeparatelyFromAvailability(t *testing.T) {
	if err := classifyReplicaReconciliationOperationError(context.Background(), ErrCorruptRecord); !errors.Is(err, ErrReplicaReconciliationConformanceFailed) {
		t.Fatalf("corrupt=%v", err)
	}
	if err := classifyReplicaReconciliationOperationError(context.Background(), ErrDatabaseUnavailable); !errors.Is(err, ErrReplicaReconciliationConformanceUnavailable) {
		t.Fatalf("database=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := classifyReplicaReconciliationOperationError(ctx, context.Canceled); !errors.Is(err, ErrReplicaReconciliationConformanceUnavailable) {
		t.Fatalf("context=%v", err)
	}
}

func TestReplicaReconciliationAttemptsOnlyTransientDatabaseFailures(t *testing.T) {
	attempts := 0
	value, err := retryReplicaReconciliationOperation(context.Background(), func() (int, error) {
		attempts++
		if attempts < 3 {
			return 0, ErrDatabaseUnavailable
		}
		return 42, nil
	})
	if err != nil || value != 42 || attempts != 3 {
		t.Fatalf("value=%d attempts=%d err=%v", value, attempts, err)
	}
	attempts = 0
	_, err = retryReplicaReconciliationOperation(context.Background(), func() (int, error) {
		attempts++
		return 0, ErrCorruptRecord
	})
	if !errors.Is(err, ErrCorruptRecord) || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestReplicaReconciliationRetryValidatesNotificationLeaseState(t *testing.T) {
	available := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	if !validReplicaReconciliationNotificationLeaseState(0, sql.NullString{}, sql.NullString{}, sql.NullTime{}, sql.NullTime{}, sql.NullTime{}, available) {
		t.Fatal("pending notification rejected")
	}
	acknowledged := sql.NullTime{Time: available.Add(2 * time.Millisecond), Valid: true}
	if !validReplicaReconciliationNotificationLeaseState(1, sql.NullString{}, sql.NullString{}, sql.NullTime{}, sql.NullTime{}, acknowledged, available) {
		t.Fatal("acknowledged notification rejected")
	}
	leased := sql.NullTime{Time: available.Add(time.Millisecond), Valid: true}
	expires := sql.NullTime{Time: leased.Time.Add(replicaReconciliationNotificationLease), Valid: true}
	if !validReplicaReconciliationNotificationLeaseState(1, sql.NullString{String: replicaReconciliationFirstWorker, Valid: true}, sql.NullString{String: strings.Repeat("a", 64), Valid: true}, leased, expires, sql.NullTime{}, available) {
		t.Fatal("active notification lease rejected")
	}
	for _, invalid := range []struct {
		delivery int
		worker   sql.NullString
		token    sql.NullString
		leased   sql.NullTime
		expires  sql.NullTime
		acked    sql.NullTime
	}{{delivery: 2}, {delivery: 1}, {delivery: 0, acked: acknowledged}, {delivery: 1, worker: sql.NullString{String: "other", Valid: true}, token: sql.NullString{String: strings.Repeat("a", 64), Valid: true}, leased: leased, expires: expires}} {
		if validReplicaReconciliationNotificationLeaseState(invalid.delivery, invalid.worker, invalid.token, invalid.leased, invalid.expires, invalid.acked, available) {
			t.Fatalf("accepted invalid state=%#v", invalid)
		}
	}
}
