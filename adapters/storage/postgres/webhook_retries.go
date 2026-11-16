package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/georgejieh/open-trestle/webhook"
)

// RecordRetry upserts the one retry state of a delivery this store holds in
// one serializable transaction, replacing state any planner recorded.
func (s *WebhookStore) RecordRetry(ctx context.Context, record webhook.RetryRecord) error {
	if err := validateWebhookOperation(ctx, s); err != nil {
		return err
	}
	if record.Validate() != nil {
		return webhook.ErrInvalidRetryRecord
	}
	scope := record.Scope()
	return s.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		mapping, stored, err := queryWebhookMappingTransaction(ctx, tx, scope, record.Source(), record.DeduplicationKey())
		if err != nil {
			return err
		}
		if !stored || mapping.deliveryIdentity != record.DeliveryIdentity() {
			return webhook.ErrInvalidRetryRecord
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_webhook_retries
(tenant_id, repository_id, source, deduplication_key, planner_identity, delivery_identity, failures, not_before_milliseconds)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, repository_id, source, deduplication_key)
DO UPDATE SET planner_identity = EXCLUDED.planner_identity, delivery_identity = EXCLUDED.delivery_identity, failures = EXCLUDED.failures, not_before_milliseconds = EXCLUDED.not_before_milliseconds`,
			scope.TenantID(), scope.RepositoryID(), record.Source().String(), record.DeduplicationKey(), record.PlannerIdentity(),
			record.DeliveryIdentity(), int64(record.Failures()), record.NotBeforeMillis(),
		); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
}

// Retry returns the retry state of a delivery and the planner that recorded it.
func (s *WebhookStore) Retry(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key string) (webhook.RetryRecord, bool, error) {
	if err := validateWebhookRead(ctx, s, scope, source, key, 1); err != nil {
		return webhook.RetryRecord{}, false, err
	}
	if !validDigest(key) {
		return webhook.RetryRecord{}, false, webhook.ErrInvalidRetryRecord
	}
	tx, err := s.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return webhook.RetryRecord{}, false, err
	}
	defer tx.Rollback()
	var planner, deliveryIdentity string
	var failures, notBefore int64
	err = tx.QueryRowContext(ctx, `SELECT planner_identity, delivery_identity, failures, not_before_milliseconds
FROM open_trestle_webhook_retries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4`,
		scope.TenantID(), scope.RepositoryID(), source.String(), key).Scan(&planner, &deliveryIdentity, &failures, &notBefore)
	if errors.Is(err, sql.ErrNoRows) {
		return webhook.RetryRecord{}, false, commit(tx)
	}
	if err != nil {
		return webhook.RetryRecord{}, false, redactTransactionError(classifyTransactionError(err))
	}
	if failures < 1 || failures > 255 {
		return webhook.RetryRecord{}, false, ErrCorruptRecord
	}
	record, err := webhook.RestoreRetryRecord(scope, source, key, deliveryIdentity, planner, uint8(failures), notBefore)
	if err != nil {
		return webhook.RetryRecord{}, false, ErrCorruptRecord
	}
	if err := commit(tx); err != nil {
		return webhook.RetryRecord{}, false, err
	}
	return record, true, nil
}

// ClearRetry removes the retry state of a delivery, whichever planner recorded it.
func (s *WebhookStore) ClearRetry(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key string) error {
	if err := validateWebhookRead(ctx, s, scope, source, key, 1); err != nil {
		return err
	}
	if !validDigest(key) {
		return webhook.ErrInvalidRetryRecord
	}
	return s.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM open_trestle_webhook_retries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4`,
			scope.TenantID(), scope.RepositoryID(), source.String(), key); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
}

var _ webhook.RetryStore = (*WebhookStore)(nil)
