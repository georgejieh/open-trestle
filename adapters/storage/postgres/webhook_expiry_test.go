package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

type expiryBodyStore struct {
	artifact.Store
	reads int
}

func (s *expiryBodyStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.reads++
	return s.Store.Get(ctx, scope, id, at)
}

func TestWebhookExpiryDoesNotReadRetiredBody(t *testing.T) {
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "expired", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"action":"opened"}`), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := webhook.NewStoredDelivery(delivery, time.UnixMilli(1001))
	if err != nil {
		t.Fatal(err)
	}
	memory, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	bodies := &expiryBodyStore{Store: memory}
	database, mock := newMockDatabase(t)
	store, err := NewWebhookStore(database, bodies, WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Minute, Clock: webhookFixedClock{at: time.UnixMilli(62000)}})
	if err != nil {
		t.Fatal(err)
	}
	value, reviewScope, err := store.newWebhookArtifact(stored)
	if err != nil {
		t.Fatal(err)
	}
	expectTenantTransaction(mock, scope.TenantID())
	expectRedeliveryMapping(mock, stored, value, reviewScope)
	mock.ExpectCommit()
	_, found, err := store.Get(context.Background(), scope, delivery.Source(), delivery.DeduplicationKey())
	if !errors.Is(err, webhook.ErrDeliveryExpired) || found || bodies.reads != 0 {
		t.Fatalf("retired body materialized: found=%t reads=%d err=%v", found, bodies.reads, err)
	}
	assertMock(t, mock)
}

func TestWebhookListFiltersExpiryBeforeMaterializingPage(t *testing.T) {
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	now := time.UnixMilli(62000)
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "fresh", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"action":"opened"}`), now)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := webhook.NewStoredDelivery(delivery, now)
	if err != nil {
		t.Fatal(err)
	}
	memory, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	bodies := &expiryBodyStore{Store: memory}
	database, mock := newMockDatabase(t)
	store, err := NewWebhookStore(database, bodies, WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Minute, Clock: webhookFixedClock{at: now}})
	if err != nil {
		t.Fatal(err)
	}
	value, reviewScope, err := store.newWebhookArtifact(stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := memory.Put(context.Background(), value, now); err != nil {
		t.Fatal(err)
	}
	columns := []string{"review_run_id", "review_scope_identity", "repository_scope_identity", "deduplication_key", "delivery_identity", "artifact_identity", "accepted_at", "expires_at"}
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectQuery(`SELECT review_run_id, review_scope_identity, repository_scope_identity[\s\S]*expires_at > \$6[\s\S]*LIMIT \$5`).WithArgs(scope.TenantID(), scope.RepositoryID(), delivery.Source().String(), "", 100, now.UTC()).WillReturnRows(sqlmock.NewRows(columns).AddRow(reviewScope.ReviewRunID(), reviewScope.Identity(), scope.Identity(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), stored.Receipt().AcceptedAt(), value.ExpiresAt()))
	mock.ExpectCommit()
	page, err := store.List(context.Background(), scope, delivery.Source(), "", 100)
	if err != nil || len(page) != 1 || page[0].Receipt().Identity() != stored.Receipt().Identity() || bodies.reads != 1 {
		t.Fatalf("active page=%d reads=%d err=%v", len(page), bodies.reads, err)
	}
	assertMock(t, mock)
}
