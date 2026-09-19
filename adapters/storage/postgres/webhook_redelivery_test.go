package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

type artifactStoreUsingMetadataPool struct {
	artifact.Store
	database *sql.DB
}

func (s artifactStoreUsingMetadataPool) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	bounded, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	connection, err := s.database.Conn(bounded)
	if err != nil {
		return artifact.Artifact{}, err
	}
	defer connection.Close()
	return s.Store.Get(ctx, scope, identity, at)
}

func expectRedeliveryMapping(mock sqlmock.Sqlmock, stored webhook.StoredDelivery, value artifact.Artifact, reviewScope audit.ReviewScope) {
	delivery := stored.Delivery()
	scope := delivery.Scope()
	columns := []string{"review_run_id", "review_scope_identity", "repository_scope_identity", "deduplication_key", "delivery_identity", "artifact_identity", "accepted_at", "expires_at"}
	mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").
		WithArgs(scope.TenantID(), scope.RepositoryID(), delivery.Source().String(), delivery.DeduplicationKey()).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(reviewScope.ReviewRunID(), reviewScope.Identity(), scope.Identity(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), stored.Receipt().AcceptedAt(), value.ExpiresAt()))
}

func TestWebhookStoreRedeliveryPreservesOriginalInBothDuplicatePaths(t *testing.T) {
	for _, path := range []string{"initial-lookup", "transaction-recheck"} {
		for _, changed := range []string{"receive-time", "body", "event", "action", "verifier"} {
			t.Run(path+"/"+changed, func(t *testing.T) {
				ctx := context.Background()
				scope, err := webhook.NewRepositoryScope("tenant-a", "repo-a")
				if err != nil {
					t.Fatal(err)
				}
				payload := []byte(`{"action":"opened","number":1}`)
				original, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), payload, time.UnixMilli(1000))
				if err != nil {
					t.Fatal(err)
				}
				stored, err := webhook.NewStoredDelivery(original, time.UnixMilli(1001))
				if err != nil {
					t.Fatal(err)
				}
				artifacts, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
				if err != nil {
					t.Fatal(err)
				}
				database, mock := newMockDatabase(t)
				database.SetMaxOpenConns(1)
				indexed := artifactStoreUsingMetadataPool{Store: artifacts, database: database}
				store, err := NewWebhookStore(database, indexed, WebhookStoreOptions{
					Classification: artifact.ClassificationRestricted,
					Protection:     artifact.ProtectionProcessPrivate,
					Retention:      time.Hour,
					Clock:          webhookFixedClock{at: time.UnixMilli(2000)},
				})
				if err != nil {
					t.Fatal(err)
				}
				value, reviewScope, err := store.newWebhookArtifact(stored)
				if err != nil {
					t.Fatal(err)
				}
				if created, err := artifacts.Put(ctx, value, stored.Receipt().AcceptedAt()); err != nil || !created {
					t.Fatalf("seed=(%t,%v)", created, err)
				}
				event, action, verifier := original.EventType(), original.Action(), original.VerifierIdentity()
				switch changed {
				case "body":
					payload = []byte(`{"action":"opened","number":2}`)
				case "event":
					event = "issues"
				case "action":
					action = "closed"
				case "verifier":
					verifier = strings.Repeat("b", 64)
				}
				later, err := webhook.NewVerifiedDelivery(scope, original.Source(), original.DeliveryID(), event, action, verifier, payload, time.UnixMilli(2000))
				if err != nil {
					t.Fatal(err)
				}
				if later.Identity() == original.Identity() || later.DeduplicationKey() != original.DeduplicationKey() {
					t.Fatal("fixture must use distinct observations of the same delivery ID")
				}
				expectTenantTransaction(mock, scope.TenantID())
				if path == "initial-lookup" {
					expectRedeliveryMapping(mock, stored, value, reviewScope)
					mock.ExpectCommit()
				} else {
					mock.ExpectQuery("SELECT review_run_id, review_scope_identity, repository_scope_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), original.Source().String(), original.DeduplicationKey()).WillReturnError(sql.ErrNoRows)
					mock.ExpectCommit()
					expectTenantTransaction(mock, scope.TenantID())
					mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("webhook:" + scope.Identity() + ":" + original.Source().String()).WillReturnResult(sqlmock.NewResult(0, 1))
					expectScope(mock, reviewScope)
					expectRedeliveryMapping(mock, stored, value, reviewScope)
					mock.ExpectCommit()
				}
				got, created, err := store.Put(ctx, later, time.UnixMilli(2001))
				if changed == "receive-time" {
					if err != nil || created || got.Delivery().Identity() != original.Identity() || got.Receipt().Identity() != stored.Receipt().Identity() {
						t.Fatalf("redelivery=(%t,%v)", created, err)
					}
					encoded, encodeErr := webhook.EncodeStoredDelivery(got)
					if encodeErr != nil || !bytes.Equal(encoded, value.Payload()) {
						t.Fatalf("redelivery changed original canonical record: %v", encodeErr)
					}
				} else if !errors.Is(err, webhook.ErrDeliveryConflict) || created || got.Validate() == nil {
					t.Fatalf("changed %s=(%t,%v)", changed, created, err)
				}
				assertMock(t, mock)
				persisted, err := artifacts.Get(ctx, reviewScope, value.Identity(), time.UnixMilli(2001))
				if err != nil || persisted.Identity() != value.Identity() || !bytes.Equal(persisted.Payload(), value.Payload()) {
					t.Fatalf("original protected artifact changed: %v", err)
				}
			})
		}
	}
}
