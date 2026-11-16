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
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/webhook"
)

type webhookReplayFixture struct {
	store     *WebhookStore
	mock      sqlmock.Sqlmock
	artifacts artifact.Store
	delivery  webhook.VerifiedDelivery
	stored    webhook.StoredDelivery
}

func newWebhookReplayFixture(t *testing.T) webhookReplayFixture {
	t.Helper()
	scope, err := webhook.NewRepositoryScope("tenant-a", "repo-a")
	if err != nil {
		t.Fatal(err)
	}
	// The replayed observation: same signed body, event, and action, but a new forge delivery ID.
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-2", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"action":"opened","number":1}`), time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := webhook.NewStoredDelivery(delivery, time.UnixMilli(2001))
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	if err != nil {
		t.Fatal(err)
	}
	database, mock := newMockDatabase(t)
	store, err := NewWebhookStore(database, artifacts, WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: webhookFixedClock{at: time.UnixMilli(2001)}})
	if err != nil {
		t.Fatal(err)
	}
	return webhookReplayFixture{store: store, mock: mock, artifacts: artifacts, delivery: delivery, stored: stored}
}

func (f webhookReplayFixture) expectNoMapping() {
	scope := f.delivery.Scope()
	f.mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), f.delivery.Source().String(), f.delivery.DeduplicationKey()).WillReturnError(sql.ErrNoRows)
}

func TestWebhookStoreRefusesSignedBodyReplayBeforeWritingProtectedBody(t *testing.T) {
	f := newWebhookReplayFixture(t)
	scope := f.delivery.Scope()
	expectTenantTransaction(f.mock, scope.TenantID())
	f.expectNoMapping()
	// The owner row may be expired: the lookup deliberately has no expiry predicate.
	f.mock.ExpectQuery(`SELECT CASE WHEN replay_key IS NULL THEN 0 ELSE 1 END\s+FROM open_trestle_webhook_deliveries\s+WHERE tenant_id = \$1 AND repository_id = \$2 AND source = \$3 AND \(replay_key = \$4 OR replay_key IS NULL\)\s+ORDER BY replay_key NULLS FIRST\s+LIMIT 1`).
		WithArgs(scope.TenantID(), scope.RepositoryID(), f.delivery.Source().String(), f.delivery.ReplayKey()).
		WillReturnRows(sqlmock.NewRows([]string{"?column?"}).AddRow(1))
	f.mock.ExpectCommit()
	got, created, err := f.store.Put(context.Background(), f.delivery, time.UnixMilli(2001))
	if !errors.Is(err, webhook.ErrDeliveryReplayed) || created || got.Validate() == nil {
		t.Fatalf("replay=(%#v,%t,%v)", got, created, err)
	}
	assertMock(t, f.mock)
	value, reviewScope, err := f.store.newWebhookArtifact(f.stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.artifacts.Get(context.Background(), reviewScope, value.Identity(), time.UnixMilli(2001)); err == nil {
		t.Fatal("refused replay wrote a protected delivery body")
	}
}

func TestWebhookStoreMapsReplayIndexViolationFromConcurrentAcceptance(t *testing.T) {
	for name, constraint := range map[string]string{"replay-index": webhookReplayIndex, "other-constraint": "open_trestle_webhook_deliveries_pkey"} {
		t.Run(name, func(t *testing.T) {
			f := newWebhookReplayFixture(t)
			scope := f.delivery.Scope()
			value, reviewScope, err := f.store.newWebhookArtifact(f.stored)
			if err != nil {
				t.Fatal(err)
			}
			// Pre-check races with a concurrent acceptance and sees nothing.
			expectTenantTransaction(f.mock, scope.TenantID())
			f.expectNoMapping()
			f.mock.ExpectQuery(`SELECT CASE WHEN replay_key IS NULL THEN 0 ELSE 1 END\s+FROM open_trestle_webhook_deliveries`).WillReturnError(sql.ErrNoRows)
			f.mock.ExpectCommit()
			expectTenantTransaction(f.mock, scope.TenantID())
			f.mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("webhook:" + scope.Identity() + ":" + f.delivery.Source().String()).WillReturnResult(sqlmock.NewResult(0, 1))
			expectScope(f.mock, reviewScope)
			f.expectNoMapping()
			f.mock.ExpectQuery(`SELECT count\(\*\)`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			f.mock.ExpectExec("INSERT INTO open_trestle_webhook_deliveries").
				WithArgs(scope.TenantID(), scope.RepositoryID(), reviewScope.ReviewRunID(), reviewScope.Identity(), scope.Identity(), f.delivery.Source().String(), f.delivery.DeduplicationKey(), f.delivery.Identity(), value.Identity(), f.stored.Receipt().AcceptedAt(), value.ExpiresAt(), f.delivery.ReplayKey()).
				WillReturnError(&pgconn.PgError{Code: "23505", ConstraintName: constraint})
			f.mock.ExpectRollback()
			got, created, err := f.store.Put(context.Background(), f.delivery, time.UnixMilli(2001))
			if created || got.Validate() == nil {
				t.Fatalf("violation produced a delivery: created=%t", created)
			}
			if constraint == webhookReplayIndex && !errors.Is(err, webhook.ErrDeliveryReplayed) {
				t.Fatalf("replay index violation=%v", err)
			}
			if constraint != webhookReplayIndex && !errors.Is(err, ErrDatabaseUnavailable) {
				t.Fatalf("unrelated violation=%v", err)
			}
			assertMock(t, f.mock)
		})
	}
}

func TestWebhookReplayMigrationIsAdditiveAndPartiallyUnique(t *testing.T) {
	encoded, err := migrationFiles.ReadFile("migrations/0016_webhook_replay_key.sql")
	if err != nil {
		t.Fatal(err)
	}
	want := "ALTER TABLE open_trestle_webhook_deliveries ADD COLUMN replay_key text CHECK (replay_key IS NULL OR replay_key ~ '^[0-9a-f]{64}$'); " +
		"ALTER TABLE open_trestle_webhook_deliveries ADD CONSTRAINT open_trestle_webhook_deliveries_replay_key_required CHECK (replay_key IS NOT NULL) NOT VALID; " +
		"CREATE UNIQUE INDEX " + webhookReplayIndex + " ON open_trestle_webhook_deliveries (tenant_id, repository_id, source, replay_key) WHERE replay_key IS NOT NULL;"
	if got := strings.Join(strings.Fields(string(encoded)), " "); got != want {
		t.Fatalf("migration=%q", got)
	}
}
