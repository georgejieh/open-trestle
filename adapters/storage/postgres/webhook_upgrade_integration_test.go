package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/webhook"
)

func TestWebhookReplayUpgradeIntegration(t *testing.T) {
	dsn := os.Getenv("OPEN_TRESTLE_TEST_POSTGRES_UPGRADE_URL")
	if dsn == "" {
		t.Skip("OPEN_TRESTLE_TEST_POSTGRES_UPGRADE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := Open(ctx, dsn, PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	// Keep the test's search path on one connection and isolate every schema object.
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	schema := fmt.Sprintf("webhook_upgrade_%d", time.Now().UnixNano())
	if _, err = database.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := database.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	if _, err = database.ExecContext(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range orderedMigrations[:len(orderedMigrations)-1] {
		data, err := migrationFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = database.ExecContext(ctx, string(data)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	scope, _ := webhook.NewRepositoryScope("tenant-upgrade", "repository-upgrade")
	at := time.UnixMilli(2001)
	delivery := func(id, body string) webhook.VerifiedDelivery {
		t.Helper()
		value, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, id, "pull_request", "opened", strings.Repeat("a", 64), []byte(body), at)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	body := `{"action":"opened","number":1}`
	original := delivery("legacy-delivery", body)
	artifacts, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewWebhookStore(database, artifacts, WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: webhookFixedClock{at: at}})
	if err != nil {
		t.Fatal(err)
	}
	other := delivery("other-legacy-delivery", `{"action":"opened","number":3}`)
	for _, legacy := range []webhook.VerifiedDelivery{original, other} {
		stored, err := webhook.NewStoredDelivery(legacy, at)
		if err != nil {
			t.Fatal(err)
		}
		value, reviewScope, err := store.newWebhookArtifact(stored)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = artifacts.Put(ctx, value, at); err != nil {
			t.Fatal(err)
		}
		tx, err := store.store.beginTenant(ctx, scope.TenantID(), sql.LevelSerializable)
		if err != nil {
			t.Fatal(err)
		}
		if err = ensureScopeTransaction(ctx, tx, reviewScope); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO open_trestle_webhook_deliveries
 (tenant_id, repository_id, review_run_id, review_scope_identity, repository_scope_identity, source, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, scope.TenantID(), scope.RepositoryID(), reviewScope.ReviewRunID(), reviewScope.Identity(), scope.Identity(), legacy.Source().String(), legacy.DeduplicationKey(), legacy.Identity(), value.Identity(), at, value.ExpiresAt())
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	migration, err := migrationFiles.ReadFile("migrations/0016_webhook_replay_key.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.ExecContext(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	replay := delivery("new-delivery", body)
	if _, created, err := store.Put(ctx, replay, at); !errors.Is(err, ErrDatabaseUnavailable) || created {
		t.Fatalf("unbackfilled legacy body admitted: created=%t err=%v", created, err)
	}
	if got, created, err := store.Put(ctx, original, at); err != nil || created || got.Delivery().Identity() != original.Identity() {
		t.Fatalf("legacy redelivery changed: created=%t err=%v", created, err)
	}
	// The key is derived from the retained, validated canonical delivery, not invented from metadata.
	tx, err := store.store.beginTenant(ctx, scope.TenantID(), sql.LevelSerializable)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE open_trestle_webhook_deliveries SET replay_key=$4 WHERE tenant_id=$1 AND repository_id=$2 AND deduplication_key=$3 AND replay_key IS NULL`, scope.TenantID(), scope.RepositoryID(), original.DeduplicationKey(), original.ReplayKey())
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Put the known key first physically: the fence must not depend on row order.
	if _, err = database.ExecContext(ctx, `CREATE INDEX upgrade_replay_order ON open_trestle_webhook_deliveries (replay_key NULLS LAST); CLUSTER open_trestle_webhook_deliveries USING upgrade_replay_order`); err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.Put(ctx, replay, at); !errors.Is(err, ErrDatabaseUnavailable) || created {
		t.Fatalf("partial backfill bypassed legacy fence: created=%t err=%v", created, err)
	}
	probe, err := webhook.NewStoredDelivery(replay, at)
	if err != nil {
		t.Fatal(err)
	}
	probeArtifact, probeScope, err := store.newWebhookArtifact(probe)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifacts.Get(ctx, probeScope, probeArtifact.Identity(), at); err == nil {
		t.Fatal("partial backfill refusal wrote a protected body")
	}
	tx, err = store.store.beginTenant(ctx, scope.TenantID(), sql.LevelSerializable)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE open_trestle_webhook_deliveries SET replay_key=$4 WHERE tenant_id=$1 AND repository_id=$2 AND deduplication_key=$3 AND replay_key IS NULL`, scope.TenantID(), scope.RepositoryID(), other.DeduplicationKey(), other.ReplayKey())
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.Put(ctx, replay, at); !errors.Is(err, webhook.ErrDeliveryReplayed) || created {
		t.Fatalf("backfilled body replay accepted: created=%t err=%v", created, err)
	}
	fresh := delivery("fresh-delivery", `{"action":"opened","number":2}`)
	if _, created, err := store.Put(ctx, fresh, at); err != nil || !created {
		t.Fatalf("fresh delivery refused after backfill: created=%t err=%v", created, err)
	}
	tx, err = store.store.beginTenant(ctx, scope.TenantID(), sql.LevelSerializable)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(ctx, `UPDATE open_trestle_webhook_deliveries SET replay_key=NULL WHERE tenant_id=$1 AND repository_id=$2 AND deduplication_key=$3`, scope.TenantID(), scope.RepositoryID(), original.DeduplicationKey())
	_ = tx.Rollback()
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" || constraint.ConstraintName != "open_trestle_webhook_deliveries_replay_key_required" {
		t.Fatalf("new NULL replay key was not fenced: %v", err)
	}
}
