package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/webhook"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRunJournalPersistsCanonicalPlanAndEvent(t *testing.T) {
	plan, event := postgresRunFixture(t)
	encodedPlan, _ := controlplane.EncodeReviewRunPlan(plan)
	encodedEvent, _ := controlplane.EncodeRunEvent(event)
	scope := plan.Scope()
	t.Run("save", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		store, _ := New(database)
		expectTenantTransaction(mock, scope.TenantID())
		mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
		expectScope(mock, scope)
		mock.ExpectQuery("SELECT plan_identity, canonical_plan").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT plan_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
		mock.ExpectExec("INSERT INTO open_trestle_run_plans").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), plan.Identity(), encodedPlan).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		if err := store.SavePlan(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
		assertMock(t, mock)
	})
	t.Run("load", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		store, _ := New(database)
		expectTenantTransaction(mock, scope.TenantID())
		mock.ExpectQuery("SELECT plan_identity, canonical_plan").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(plan.Identity(), encodedPlan))
		mock.ExpectCommit()
		loaded, found, err := store.LoadPlan(context.Background(), scope)
		if err != nil || !found || loaded.Identity() != plan.Identity() {
			t.Fatalf("load=(%#v,%v,%v)", loaded, found, err)
		}
		assertMock(t, mock)
	})
	t.Run("append", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		store, _ := New(database)
		expectTenantTransaction(mock, scope.TenantID())
		mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
		expectScope(mock, scope)
		mock.ExpectQuery("SELECT plan_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT sequence, event_identity, canonical_event").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
		mock.ExpectExec("INSERT INTO open_trestle_run_events").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), event.PlanIdentity(), event.Sequence(), event.Identity(), event.PreviousIdentity(), encodedEvent, event.OccurredAt()).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		if err := store.Append(context.Background(), "", event); err != nil {
			t.Fatal(err)
		}
		assertMock(t, mock)
	})
	t.Run("read", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		store, _ := New(database)
		expectTenantTransaction(mock, scope.TenantID())
		mock.ExpectQuery("SELECT sequence, event_identity, canonical_event").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), uint64(0), 10).WillReturnRows(sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event"}).AddRow(1, event.Identity(), encodedEvent))
		mock.ExpectCommit()
		events, err := store.Read(context.Background(), scope, 0, 10)
		if err != nil || len(events) != 1 || events[0].Identity() != event.Identity() {
			t.Fatalf("events=(%#v,%v)", events, err)
		}
		assertMock(t, mock)
	})
}
func TestAuditLedgerUsesTenantTransactionAndCanonicalEvent(t *testing.T) {
	_, runEvent := postgresRunFixture(t)
	scope := runEvent.Scope()
	event, err := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, strings.Repeat("e", 64), []string{strings.Repeat("f", 64)}, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := audit.EncodeEvent(event)
	database, mock := newMockDatabase(t)
	ledger, _ := NewAuditLedger(database)
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("audit:" + scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	mock.ExpectQuery("SELECT sequence, event_identity, canonical_event").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_audit_events").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), event.Sequence(), event.Identity(), event.PreviousIdentity(), encoded, time.UnixMilli(event.OccurredAtUnixMilliseconds()).UTC()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := ledger.Append(context.Background(), "", event); err != nil {
		t.Fatal(err)
	}
	assertMock(t, mock)
}
func TestStoreRejectsCorruptIndexedCanonicalRecord(t *testing.T) {
	plan, _ := postgresRunFixture(t)
	scope := plan.Scope()
	encoded, _ := controlplane.EncodeReviewRunPlan(plan)
	database, mock := newMockDatabase(t)
	store, _ := New(database)
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectQuery("SELECT plan_identity, canonical_plan").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(strings.Repeat("f", 64), encoded))
	mock.ExpectRollback()
	if _, _, err := store.LoadPlan(context.Background(), scope); !errors.Is(err, ErrCorruptRecord) {
		t.Fatalf("err=%v", err)
	}
	assertMock(t, mock)
}
func TestMigrationDefinesForcedTenantIsolationAndChecksums(t *testing.T) {
	migration, err := migrationFiles.ReadFile("migrations/0001_core.sql")
	if err != nil {
		t.Fatal(err)
	}
	text := string(migration)
	for _, table := range []string{"open_trestle_review_scopes", "open_trestle_run_plans", "open_trestle_run_events", "open_trestle_audit_events"} {
		for _, want := range []string{"CREATE TABLE " + table, "ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY", "ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY", "CREATE POLICY " + table + "_tenant_isolation"} {
			if !strings.Contains(text, want) {
				t.Errorf("missing %s", want)
			}
		}
	}
	if strings.Contains(text, "canonical_delivery") || strings.Contains(text, "canonical_set") {
		t.Fatal("content-bearing records entered the ledger migration")
	}
	database, mock := newMockDatabase(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(migrationLockID).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS open_trestle_schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(1).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(text)).WillReturnResult(sqlmock.NewResult(0, 0))
	digest := sha256.Sum256(migration)
	checksum := hex.EncodeToString(digest[:])
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(1, checksum).WillReturnResult(sqlmock.NewResult(1, 1))
	second, err := migrationFiles.ReadFile("migrations/0002_diagnostic_metadata.sql")
	if err != nil {
		t.Fatal(err)
	}
	secondDigest := sha256.Sum256(second)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(2).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(second))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(2, hex.EncodeToString(secondDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	third, err := migrationFiles.ReadFile("migrations/0003_webhook_metadata.sql")
	if err != nil {
		t.Fatal(err)
	}
	metadataText := string(second) + "\n" + string(third)
	for _, table := range []string{"open_trestle_diagnostic_sets", "open_trestle_webhook_deliveries"} {
		for _, want := range []string{"CREATE TABLE " + table, "ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY", "ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY", "CREATE POLICY " + table + "_tenant_isolation"} {
			if !strings.Contains(metadataText, want) {
				t.Errorf("missing %s", want)
			}
		}
	}
	if strings.Contains(metadataText, "canonical_delivery") || strings.Contains(metadataText, "canonical_set") || strings.Contains(metadataText, "payload bytea") {
		t.Fatal("content-bearing records entered metadata migrations")
	}
	thirdDigest := sha256.Sum256(third)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(3).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(third))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(3, hex.EncodeToString(thirdDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	fourth, err := migrationFiles.ReadFile("migrations/0004_artifact_metadata.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"open_trestle_artifacts", "open_trestle_artifact_deletion_authorizations", "open_trestle_artifact_deletion_receipts"} {
		for _, want := range []string{"CREATE TABLE " + table, "ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY", "ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY", "CREATE POLICY " + table + "_tenant_isolation"} {
			if !strings.Contains(string(fourth), want) {
				t.Errorf("missing %s", want)
			}
		}
	}
	fourthDigest := sha256.Sum256(fourth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(4).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(fourth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(4, hex.EncodeToString(fourthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	fifth, err := migrationFiles.ReadFile("migrations/0005_task_notifications.sql")
	if err != nil {
		t.Fatal(err)
	}
	fifthText := string(fifth)
	for _, want := range []string{"CREATE TABLE open_trestle_task_notifications", "FORCE ROW LEVEL SECURITY", "CREATE POLICY open_trestle_task_notifications_tenant_isolation", "pg_notify('open_trestle_task_notifications', '')", "CREATE TRIGGER open_trestle_run_events_task_notification_signal"} {
		if !strings.Contains(fifthText, want) {
			t.Errorf("missing %s", want)
		}
	}
	fifthDigest := sha256.Sum256(fifth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(5).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(fifthText)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(5, hex.EncodeToString(fifthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	sixth, err := migrationFiles.ReadFile("migrations/0006_publication_attempts.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CREATE TABLE open_trestle_publication_attempts", "FORCE ROW LEVEL SECURITY", "CREATE POLICY open_trestle_publication_attempts_tenant_isolation"} {
		if !strings.Contains(string(sixth), want) {
			t.Errorf("missing %s", want)
		}
	}
	sixthDigest := sha256.Sum256(sixth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(6).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(sixth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(6, hex.EncodeToString(sixthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	seventh, err := migrationFiles.ReadFile("migrations/0007_publication_guard_authority.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CREATE TABLE open_trestle_publication_guard_authority", "database_namespace_id uuid", "DEFAULT gen_random_uuid()"} {
		if !strings.Contains(string(seventh), want) {
			t.Errorf("missing %s", want)
		}
	}
	seventhDigest := sha256.Sum256(seventh)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(7).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(seventh))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(7, hex.EncodeToString(seventhDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	eighth, err := migrationFiles.ReadFile("migrations/0008_database_authority.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CREATE TABLE open_trestle_database_authority", "database_namespace_id uuid", "INSERT INTO open_trestle_database_authority", "ON CONFLICT (singleton) DO NOTHING"} {
		if !strings.Contains(string(eighth), want) {
			t.Errorf("missing %s", want)
		}
	}
	eighthDigest := sha256.Sum256(eighth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(8).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(eighth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(8, hex.EncodeToString(eighthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	ninth, err := migrationFiles.ReadFile("migrations/0009_shared_rate_limits.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CREATE TABLE open_trestle_rate_limit_windows", "PRIMARY KEY (namespace, key_digest)", "open_trestle_rate_limit_windows_expiry"} {
		if !strings.Contains(string(ninth), want) {
			t.Errorf("missing %s", want)
		}
	}
	ninthDigest := sha256.Sum256(ninth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(9).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(ninth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(9, hex.EncodeToString(ninthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	tenth, err := migrationFiles.ReadFile("migrations/0010_artifact_kinds_and_origins.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ALTER TABLE open_trestle_artifacts", "'source_file'", "'publication_receipt'", "'memory'"} {
		if !strings.Contains(string(tenth), want) {
			t.Errorf("missing %s", want)
		}
	}
	tenthDigest := sha256.Sum256(tenth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(10).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(tenth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(10, hex.EncodeToString(tenthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	eleventh, err := migrationFiles.ReadFile("migrations/0011_investigation_artifact_kinds.sql")
	if err != nil {
		t.Fatal(err)
	}
	eleventhDigest := sha256.Sum256(eleventh)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(11).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(eleventh))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(11, hex.EncodeToString(eleventhDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	twelfth, err := migrationFiles.ReadFile("migrations/0012_artifact_erasure.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"open_trestle_artifact_admissions", "open_trestle_artifact_erasure_operations"} {
		for _, want := range []string{"CREATE TABLE " + table, "ALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY", "ALTER TABLE " + table + " FORCE ROW LEVEL SECURITY"} {
			if !strings.Contains(string(twelfth), want) {
				t.Errorf("missing %s", want)
			}
		}
	}
	twelfthDigest := sha256.Sum256(twelfth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(12).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(twelfth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(12, hex.EncodeToString(twelfthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	thirteenth, err := migrationFiles.ReadFile("migrations/0013_artifact_erasure_resume.sql")
	if err != nil {
		t.Fatal(err)
	}
	thirteenthDigest := sha256.Sum256(thirteenth)
	mock.ExpectQuery("SELECT checksum FROM open_trestle_schema_migrations").WithArgs(13).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(string(thirteenth))).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO open_trestle_schema_migrations").WithArgs(13, hex.EncodeToString(thirteenthDigest[:])).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := ApplyMigrations(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	assertMock(t, mock)
}
func postgresRunFixture(t *testing.T) (controlplane.ReviewRunPlan, controlplane.RunEvent) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-postgres")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 2, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	event, _ := controlplane.NewRunEvent(plan, 1, "", controlplane.RunEventOpened, controlplane.TaskDefinition{}, 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(1000))
	return plan, event
}
func newMockDatabase(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database, mock
}
func expectTenantTransaction(mock sqlmock.Sqlmock, tenant string) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(tenant).WillReturnResult(sqlmock.NewResult(0, 1))
}
func expectScope(mock sqlmock.Sqlmock, scope audit.ReviewScope) {
	mock.ExpectExec("INSERT INTO open_trestle_review_scopes").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT scope_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"scope_identity"}).AddRow(scope.Identity()))
}

func assertMock(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type diagnosticFixedClock struct{ at time.Time }

func (c diagnosticFixedClock) Now() time.Time { return c.at }
func TestDiagnosticStoreKeepsContentInProtectedArtifactStore(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-diagnostics")
	finding, _ := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Bounded title", "Untrusted detail", diagnostics.SeverityWarning, "src/main.go", 2, 3, []string{"evidence:one"})
	set, _ := diagnostics.NewSet(scope, strings.Repeat("c", 64), strings.Repeat("d", 40), strings.Repeat("e", 64), []diagnostics.Finding{finding})
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	database, mock := newMockDatabase(t)
	options := DiagnosticStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: diagnosticFixedClock{at: time.UnixMilli(100)}}
	store, err := NewDiagnosticStore(database, artifacts, options)
	if err != nil {
		t.Fatal(err)
	}
	value, err := store.newDiagnosticArtifact(set, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("diagnostics:" + scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_diagnostic_sets").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), set.Identity(), value.Identity(), value.ExpiresAt()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	created, err := store.PutDiagnosticSet(context.Background(), set)
	if err != nil || !created {
		t.Fatalf("put=(%v,%v)", created, err)
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"set_identity", "artifact_identity", "expires_at"}).AddRow(set.Identity(), value.Identity(), value.ExpiresAt()))
	mock.ExpectCommit()
	loaded, err := store.GetDiagnosticSet(context.Background(), scope)
	if err != nil || loaded.Identity() != set.Identity() {
		t.Fatalf("get=(%#v,%v)", loaded, err)
	}
	assertMock(t, mock)
}

type webhookFixedClock struct{ at time.Time }

func (c webhookFixedClock) Now() time.Time { return c.at }
func TestWebhookStoreKeepsDeliveryBodyInProtectedArtifactStore(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"private":"payload"}`), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := time.UnixMilli(1001)
	stored, _ := webhook.NewStoredDelivery(delivery, acceptedAt)
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	database, mock := newMockDatabase(t)
	options := WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: webhookFixedClock{at: acceptedAt}}
	store, err := NewWebhookStore(database, artifacts, options)
	if err != nil {
		t.Fatal(err)
	}
	value, reviewScope, err := store.newWebhookArtifact(stored)
	if err != nil {
		t.Fatal(err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("webhook:" + repositoryScope.Identity() + ":" + delivery.Source().String()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, reviewScope)
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`SELECT count\(\*\)[\s\S]*expires_at > \$4`).WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), acceptedAt.UTC()).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectExec("INSERT INTO open_trestle_webhook_deliveries").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), reviewScope.ReviewRunID(), reviewScope.Identity(), repositoryScope.Identity(), delivery.Source().String(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), stored.Receipt().AcceptedAt(), value.ExpiresAt()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	persisted, created, err := store.Put(context.Background(), delivery, acceptedAt)
	if err != nil || !created || persisted.Delivery().Identity() != delivery.Identity() {
		t.Fatalf("put=(%#v,%v,%v)", persisted, created, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	columns := []string{"review_run_id", "review_scope_identity", "repository_scope_identity", "deduplication_key", "delivery_identity", "artifact_identity", "accepted_at", "expires_at"}
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnRows(sqlmock.NewRows(columns).AddRow(reviewScope.ReviewRunID(), reviewScope.Identity(), repositoryScope.Identity(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), stored.Receipt().AcceptedAt(), value.ExpiresAt()))
	mock.ExpectCommit()
	loaded, found, err := store.Get(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey())
	if err != nil || !found || loaded.Delivery().Identity() != delivery.Identity() {
		t.Fatalf("get=(%#v,%v,%v)", loaded, found, err)
	}
	assertMock(t, mock)
}

func TestIndexedArtifactStorePersistsDeletionAuthorityAndReceipt(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-artifact-index")
	value, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{"secret":true}`), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	physical, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	database, mock := newMockDatabase(t)
	index, _ := NewArtifactIndex(database)
	store, err := NewIndexedArtifactStore(index, physical)
	if err != nil {
		t.Fatal(err)
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("artifact:" + scope.Identity() + ":" + value.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	expectArtifactMetadata(mock, scope, value, false)
	mock.ExpectExec("INSERT INTO open_trestle_artifacts").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), value.Identity(), value.PayloadDigest(), value.Kind().String(), value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	created, err := store.Put(context.Background(), value, time.UnixMilli(200))
	if err != nil || !created {
		t.Fatalf("put=(%v,%v)", created, err)
	}
	authorization, err := artifact.NewDeletionAuthorization(scope, value.Identity(), strings.Repeat("b", 64), "retention-service", strings.Repeat("c", 64), artifact.DeletionExpired, time.UnixMilli(900), time.UnixMilli(1100))
	if err != nil {
		t.Fatal(err)
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("artifact-auth:" + authorization.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectArtifactMetadata(mock, scope, value, true)
	mock.ExpectQuery("SELECT authorization_identity, artifact_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), authorization.Identity()).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_artifact_deletion_authorizations").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), authorization.Identity(), value.Identity(), authorization.PolicyIdentity(), authorization.PrincipalIdentity(), authorization.HoldClearanceIdentity(), authorization.Reason().String(), authorization.IssuedAt(), authorization.ExpiresAt()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	deletedAt := time.UnixMilli(1000)
	expectedReceipt, _ := physical.Delete(context.Background(), authorization, deletedAt)
	physical, _ = artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	_, _ = physical.Put(context.Background(), value, time.UnixMilli(200))
	store.artifacts = physical
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("artifact-delete:" + value.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectArtifactMetadata(mock, scope, value, true)
	mock.ExpectQuery("SELECT artifact_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), authorization.Identity()).WillReturnRows(sqlmock.NewRows([]string{"artifact_identity"}).AddRow(value.Identity()))
	mock.ExpectQuery("SELECT receipt_identity, payload_digest").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), value.Identity()).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_artifact_deletion_receipts").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), expectedReceipt.Identity(), value.Identity(), value.PayloadDigest(), authorization.Identity(), expectedReceipt.DeletedAt()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	receipt, err := store.Delete(context.Background(), authorization, deletedAt)
	if err != nil || receipt.Identity() != expectedReceipt.Identity() {
		t.Fatalf("delete=(%#v,%v)", receipt, err)
	}
	assertMock(t, mock)
}
func expectArtifactMetadata(mock sqlmock.Sqlmock, scope audit.ReviewScope, value artifact.Artifact, found bool) {
	expectation := mock.ExpectQuery("SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), value.Identity())
	if !found {
		expectation.WillReturnError(sql.ErrNoRows)
		return
	}
	expectation.WillReturnRows(sqlmock.NewRows([]string{"payload_digest", "kind", "classification", "origin", "protection", "created_at", "expires_at"}).AddRow(value.PayloadDigest(), value.Kind().String(), value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt()))
}

func TestArtifactIndexListsUndeletedExpiryCandidatesWithStableCursor(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-expiry")
	value, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{}`), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	database, mock := newMockDatabase(t)
	index, _ := NewArtifactIndex(database)
	expectTenantTransaction(mock, scope.TenantID())
	columns := []string{"review_run_id", "scope_identity", "artifact_identity", "payload_digest", "kind", "classification", "origin", "protection", "created_at", "expires_at"}
	mock.ExpectQuery("SELECT review_run_id, scope_identity, artifact_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), time.UnixMilli(1000).UTC(), time.UnixMilli(1).UTC(), "", 10).WillReturnRows(sqlmock.NewRows(columns).AddRow(scope.ReviewRunID(), scope.Identity(), value.Identity(), value.PayloadDigest(), value.Kind().String(), value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt()))
	mock.ExpectCommit()
	metadata, err := index.ListExpiredArtifacts(context.Background(), scope.TenantID(), scope.RepositoryID(), time.UnixMilli(1000), time.Time{}, "", 10)
	if err != nil || len(metadata) != 1 || metadata[0].ArtifactIdentity() != value.Identity() {
		t.Fatalf("metadata=(%#v,%v)", metadata, err)
	}
	assertMock(t, mock)
}

func TestVerifyMigrationsRequiresEveryExactChecksum(t *testing.T) {
	database, mock := newMockDatabase(t)
	mock.ExpectBegin()
	expectDatabaseAuthoritySchemas(mock, "public", "public")
	columns := []string{"version", "checksum"}
	rows := sqlmock.NewRows(columns)
	for index, name := range orderedMigrations {
		checksum, err := migrationChecksum(name)
		if err != nil {
			t.Fatal(err)
		}
		rows.AddRow(index+1, checksum)
	}
	mock.ExpectQuery("SELECT version, checksum FROM open_trestle_schema_migrations").WillReturnRows(rows)
	mock.ExpectCommit()
	if err := VerifyMigrations(context.Background(), database); err != nil {
		t.Fatal(err)
	}
	assertMock(t, mock)
}

func postgresNotificationFixture(t *testing.T) (controlplane.TaskNotification, []byte) {
	t.Helper()
	plan, _ := postgresRunFixture(t)
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	state, err := coordinator.Open(context.Background(), plan, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	state, err = coordinator.Advance(context.Background(), plan, time.UnixMilli(1001))
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("source")
	notice, err := controlplane.NewTaskNotification(state, runtime, time.UnixMilli(1001))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := controlplane.EncodeTaskNotification(notice)
	return notice, encoded
}
func TestTaskNotificationQueueUsesTenantScopeAndFencedDelivery(t *testing.T) {
	notice, encoded := postgresNotificationFixture(t)
	scope := notice.Scope()
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	token := hex.EncodeToString([]byte(strings.Repeat("b", 32)))
	template, _ := controlplane.NewTaskNotificationLease(notice, "worker-a", token, 1, time.UnixMilli(1002).UTC(), time.UnixMilli(2002).UTC())
	database, mock := newMockDatabase(t)
	store, _ := New(database)
	store.notificationRandom = strings.NewReader(strings.Repeat("b", 128))
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("task-notification:" + notice.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	mock.ExpectQuery("SELECT notice_identity, canonical_notice, canonical_checksum").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), notice.Identity()).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_task_notifications").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), notice.Identity(), notice.PlanIdentity(), notice.TaskStateRevision(), notice.TaskStateEventIdentity(), notice.TaskKey(), notice.TaskIdentity(), notice.HandlerIdentity(), notice.Attempt(), notice.AvailableAt(), encoded, checksum).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	created, err := store.EnqueueTaskNotification(context.Background(), notice)
	if err != nil || !created {
		t.Fatalf("enqueue=(%v,%v)", created, err)
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectQuery("SELECT notice_identity, plan_identity, task_state_revision").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), time.UnixMilli(1002).UTC()).WillReturnRows(sqlmock.NewRows([]string{"notice_identity", "plan_identity", "task_state_revision", "task_state_event_identity", "task_key", "task_identity", "handler_identity", "attempt", "available_at", "canonical_notice", "canonical_checksum", "delivery_count"}).AddRow(notice.Identity(), notice.PlanIdentity(), notice.TaskStateRevision(), notice.TaskStateEventIdentity(), notice.TaskKey(), notice.TaskIdentity(), notice.HandlerIdentity(), notice.Attempt(), notice.AvailableAt(), encoded, checksum, 0))
	mock.ExpectExec("UPDATE open_trestle_task_notifications").WithArgs("worker-a", template.TokenIdentity(), time.UnixMilli(1002).UTC(), time.UnixMilli(2002).UTC(), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), notice.Identity(), 0).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	lease, found, err := store.ClaimTaskNotification(context.Background(), scope, "worker-a", time.UnixMilli(1002).UTC(), time.Second)
	if err != nil || !found || lease.Identity() != template.Identity() {
		t.Fatalf("claim=(%#v,%v,%v), expectations=%v", lease, found, err, mock.ExpectationsWereMet())
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec("UPDATE open_trestle_task_notifications").WithArgs(time.UnixMilli(1003).UTC(), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), notice.Identity(), 1, "worker-a", template.TokenIdentity(), lease.LeasedAt(), lease.ExpiresAt()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.AcknowledgeTaskNotification(context.Background(), lease, time.UnixMilli(1003).UTC()); err != nil {
		t.Fatalf("ack=%v expectations=%v", err, mock.ExpectationsWereMet())
	}
	assertMock(t, mock)
	var _ controlplane.TaskNotificationQueue = store
}

func TestPublicationAttemptGuardClaimsAndCompletesExactScopedAttempt(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-publication")
	operation, attempt, request, result := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	database, mock := newMockDatabase(t)
	expectPublicationAuthorityVerification(mock, strings.Repeat("f", 64), "11111111-1111-4111-8111-111111111111")
	store, _ := NewWithPublicationAuthority(context.Background(), database, strings.Repeat("f", 64))
	at := time.UnixMilli(100).UTC()
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("publication-operation:" + operation).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	mock.ExpectQuery("SELECT attempt_identity, request_identity, status").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), operation).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_publication_attempts").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), operation, attempt, request, at).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	claimed, err := store.ClaimPublicationAttempt(context.Background(), scope, operation, attempt, request, at)
	if err != nil || !claimed {
		t.Fatalf("claim=(%v,%v)", claimed, err)
	}
	otherAttempt := strings.Repeat("e", 64)
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("publication-operation:" + operation).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	mock.ExpectQuery("SELECT attempt_identity, request_identity, status").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), operation).WillReturnRows(sqlmock.NewRows([]string{"attempt_identity", "request_identity", "status"}).AddRow(attempt, request, "claimed"))
	mock.ExpectRollback()
	if claimed, conflictErr := store.ClaimPublicationAttempt(context.Background(), scope, operation, otherAttempt, request, at); claimed || !errors.Is(conflictErr, review.ErrPublicationAttemptGuardConflict) {
		t.Fatalf("second attempt=(%v,%v)", claimed, conflictErr)
	}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("publication-attempt:" + attempt).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT status, result_identity, claimed_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), attempt).WillReturnRows(sqlmock.NewRows([]string{"status", "result_identity", "claimed_at"}).AddRow("claimed", nil, at))
	mock.ExpectExec("UPDATE open_trestle_publication_attempts").WithArgs(result, at.Add(time.Millisecond), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), attempt).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.CompletePublicationAttempt(context.Background(), scope, attempt, result, at.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if store.Identity() == "" || store.IdempotencyGuarantee() != review.PublisherExactOperationKey {
		t.Fatal("guard identity")
	}
	assertMock(t, mock)
}

func TestPublicationAttemptGuardRequiresDatabaseAuthorityIdentity(t *testing.T) {
	database, mock := newMockDatabase(t)
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	if store.Identity() != "" || store.IdempotencyGuarantee() != 0 {
		t.Fatal("unbound store exposed publication authority")
	}
	expectPublicationAuthorityVerification(mock, strings.Repeat("a", 64), "11111111-1111-4111-8111-111111111111")
	first, err := NewWithPublicationAuthority(context.Background(), database, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	expectPublicationAuthorityVerification(mock, strings.Repeat("a", 64), "22222222-2222-4222-8222-222222222222")
	second, err := NewWithPublicationAuthority(context.Background(), database, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() == second.Identity() {
		t.Fatal("database namespace omitted from guard identity")
	}
	if invalid, err := NewWithPublicationAuthority(context.Background(), database, strings.Repeat("0", 64)); !errors.Is(err, ErrPublicationAuthorityMismatch) || invalid != nil {
		t.Fatalf("invalid=(%#v,%v)", invalid, err)
	}
	assertMock(t, mock)
}
func expectPublicationAuthorityVerification(mock sqlmock.Sqlmock, authority, namespace string) {
	mock.ExpectBegin()
	expectPublicationAuthoritySchema(mock, "public")
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_catalog.current_database(), pg_catalog.current_schema(), database_namespace_id::text, authority_identity FROM open_trestle_publication_guard_authority WHERE singleton = true")).WillReturnRows(sqlmock.NewRows([]string{"current_database", "current_schema", "database_namespace_id", "authority_identity"}).AddRow("trestle", "public", namespace, authority))
	mock.ExpectCommit()
}
