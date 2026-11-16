package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/webhook"
)

// The PostgreSQL inbox keeps one refusal per delivery, beside the delivery it
// refuses, naming its planner: the same planner's record stands, a superseded
// planner's record is replaced, and it is cleared only for its planner.
func TestWebhookStoreKeepsOneRefusalPerDelivery(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"private":"payload"}`), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	acceptedAt := time.UnixMilli(1001)
	stored, _ := webhook.NewStoredDelivery(delivery, acceptedAt)
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	database, mock := newMockDatabase(t)
	store, err := NewWebhookStore(database, artifacts, WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: webhookFixedClock{at: acceptedAt}})
	if err != nil {
		t.Fatal(err)
	}
	value, reviewScope, err := store.newWebhookArtifact(stored)
	if err != nil {
		t.Fatal(err)
	}
	planner := strings.Repeat("d", 64)
	record, err := webhook.NewRefusalRecord(stored, planner, "invalid_pull_request_payload", time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	mappingColumns := []string{"review_run_id", "review_scope_identity", "repository_scope_identity", "deduplication_key", "delivery_identity", "artifact_identity", "accepted_at", "expires_at"}
	mapping := func() *sqlmock.Rows {
		return sqlmock.NewRows(mappingColumns).AddRow(reviewScope.ReviewRunID(), reviewScope.Identity(), repositoryScope.Identity(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), acceptedAt, value.ExpiresAt())
	}
	refusalArgs := []driver.Value{repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()}
	refusalColumns := []string{"planner_identity", "delivery_identity", "record_identity", "reason", "refused_at_milliseconds"}
	refusalRow := func(reason string) *sqlmock.Rows {
		return sqlmock.NewRows(refusalColumns).AddRow(planner, delivery.Identity(), record.Identity(), reason, int64(2000))
	}
	const refusalRead = "SELECT planner_identity, delivery_identity, record_identity, reason, refused_at_milliseconds"
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnRows(mapping())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO open_trestle_webhook_refusals").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey(), planner, delivery.Identity(), record.Identity(), "invalid_pull_request_payload", int64(2000)).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if persisted, created, err := store.RecordRefusal(context.Background(), record); err != nil || !created || persisted.Identity() != record.Identity() {
		t.Fatalf("record=(%v,%v)", created, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnRows(mapping())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnRows(refusalRow("invalid_pull_request_payload"))
	mock.ExpectCommit()
	later, _ := webhook.NewRefusalRecord(stored, planner, "invalid_pull_request_payload", time.UnixMilli(3000))
	if persisted, created, err := store.RecordRefusal(context.Background(), later); err != nil || created || persisted.Identity() != record.Identity() {
		t.Fatalf("repeat record=(%v,%v)", created, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnRows(mapping())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnRows(refusalRow("invalid_pull_request_payload"))
	mock.ExpectCommit()
	different, _ := webhook.NewRefusalRecord(stored, planner, "planning_refused", time.UnixMilli(3000))
	if _, _, err := store.RecordRefusal(context.Background(), different); !errors.Is(err, webhook.ErrRefusalConflict) {
		t.Fatalf("conflicting refusal err=%v", err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnRows(refusalRow("invalid_pull_request_payload"))
	mock.ExpectCommit()
	if loaded, found, err := store.Refusal(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey(), planner); err != nil || !found || loaded.Identity() != record.Identity() || loaded.Reason() != "invalid_pull_request_payload" {
		t.Fatalf("refusal=(%v,%v)", found, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnRows(refusalRow("tampered_reason"))
	if _, _, err := store.Refusal(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey(), planner); err == nil {
		t.Fatal("refusal readback accepted a row whose identity does not match")
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnRows(refusalRow("invalid_pull_request_payload"))
	mock.ExpectCommit()
	if _, found, err := store.Refusal(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey(), strings.Repeat("e", 64)); err != nil || found {
		t.Fatalf("another planner read this planner's refusal: found=%t err=%v", found, err)
	}
	successor := strings.Repeat("e", 64)
	replacement, _ := webhook.NewRefusalRecord(stored, successor, "planning_refused", time.UnixMilli(4000))
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnRows(mapping())
	mock.ExpectQuery(refusalRead).WithArgs(refusalArgs...).WillReturnRows(refusalRow("invalid_pull_request_payload"))
	mock.ExpectExec(`UPDATE open_trestle_webhook_refusals\s+SET planner_identity = \$5`).WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey(), successor, delivery.Identity(), replacement.Identity(), "planning_refused", int64(4000)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if persisted, created, err := store.RecordRefusal(context.Background(), replacement); err != nil || !created || persisted.Identity() != replacement.Identity() {
		t.Fatalf("a superseded refusal was not replaced: created=%t err=%v", created, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectExec(`DELETE FROM open_trestle_webhook_refusals\s+WHERE tenant_id = \$1 AND repository_id = \$2 AND source = \$3 AND deduplication_key = \$4 AND planner_identity = \$5`).WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey(), successor).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.ClearRefusal(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey(), successor); err != nil {
		t.Fatalf("clear refusal: %v", err)
	}
	assertMock(t, mock)
}
