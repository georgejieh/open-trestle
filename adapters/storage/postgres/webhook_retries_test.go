package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/webhook"
)

// The PostgreSQL inbox upserts, reads and clears one delivery's one retry
// state beside the delivery it belongs to; the state names the planner that
// recorded it, and a later planner's state replaces it.
func TestWebhookStoreKeepsOneRetryStatePerDelivery(t *testing.T) {
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
	record, err := webhook.NewRetryRecord(stored, planner, 2, time.UnixMilli(5000))
	if err != nil {
		t.Fatal(err)
	}
	mappingColumns := []string{"review_run_id", "review_scope_identity", "repository_scope_identity", "deduplication_key", "delivery_identity", "artifact_identity", "accepted_at", "expires_at"}
	keyArgs := []driver.Value{repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(repositoryScope.TenantID(), repositoryScope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).WillReturnRows(sqlmock.NewRows(mappingColumns).AddRow(reviewScope.ReviewRunID(), reviewScope.Identity(), repositoryScope.Identity(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), acceptedAt, value.ExpiresAt()))
	mock.ExpectExec(`INSERT INTO open_trestle_webhook_retries[\s\S]*ON CONFLICT \(tenant_id, repository_id, source, deduplication_key\)\s+DO UPDATE SET planner_identity = EXCLUDED.planner_identity`).WithArgs(append(keyArgs, planner, delivery.Identity(), int64(2), int64(5000))...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := store.RecordRetry(context.Background(), record); err != nil {
		t.Fatalf("record retry: %v", err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT planner_identity, delivery_identity, failures, not_before_milliseconds").WithArgs(keyArgs...).WillReturnRows(sqlmock.NewRows([]string{"planner_identity", "delivery_identity", "failures", "not_before_milliseconds"}).AddRow(planner, delivery.Identity(), int64(2), int64(5000)))
	mock.ExpectCommit()
	if loaded, found, err := store.Retry(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey()); err != nil || !found || loaded != record {
		t.Fatalf("retry=(%t,%v)", found, err)
	}
	superseded := strings.Repeat("9", 64)
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT planner_identity, delivery_identity, failures, not_before_milliseconds").WithArgs(keyArgs...).WillReturnRows(sqlmock.NewRows([]string{"planner_identity", "delivery_identity", "failures", "not_before_milliseconds"}).AddRow(superseded, delivery.Identity(), int64(4), int64(5000)))
	mock.ExpectCommit()
	if loaded, found, err := store.Retry(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey()); err != nil || !found || loaded.PlannerIdentity() != superseded || loaded.Failures() != 4 {
		t.Fatalf("superseded retry=(%t,%v)", found, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectQuery("SELECT planner_identity, delivery_identity, failures, not_before_milliseconds").WithArgs(keyArgs...).WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()
	if _, found, err := store.Retry(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey()); err != nil || found {
		t.Fatalf("missing retry=(%t,%v)", found, err)
	}
	expectTenantTransaction(mock, repositoryScope.TenantID())
	mock.ExpectExec(`DELETE FROM open_trestle_webhook_retries\s+WHERE tenant_id = \$1 AND repository_id = \$2 AND source = \$3 AND deduplication_key = \$4$`).WithArgs(keyArgs...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.ClearRetry(context.Background(), repositoryScope, delivery.Source(), delivery.DeduplicationKey()); err != nil {
		t.Fatalf("clear retry: %v", err)
	}
	assertMock(t, mock)
}
