package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/georgejieh/open-trestle/webhook"
)

// RecordRefusal records a refusal of a delivery this store holds, once per
// delivery and planner identity, in one serializable transaction.
func (s *WebhookStore) RecordRefusal(ctx context.Context, record webhook.RefusalRecord) (webhook.RefusalRecord, bool, error) {
	if err := validateWebhookOperation(ctx, s); err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	if record.Validate() != nil {
		return webhook.RefusalRecord{}, false, webhook.ErrInvalidRefusalRecord
	}
	scope := record.Scope()
	var existing webhook.RefusalRecord
	found := false
	err := s.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		found = false
		mapping, stored, err := queryWebhookMappingTransaction(ctx, tx, scope, record.Source(), record.DeduplicationKey())
		if err != nil {
			return err
		}
		if !stored || mapping.deliveryIdentity != record.DeliveryIdentity() {
			return webhook.ErrInvalidRefusalRecord
		}
		existing, found, err = queryWebhookRefusalTransaction(ctx, tx, scope, record.Source(), record.DeduplicationKey(), record.PlannerIdentity())
		if err != nil || found {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_webhook_refusals
(tenant_id, repository_id, source, deduplication_key, planner_identity, delivery_identity, record_identity, reason, refused_at_milliseconds)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			scope.TenantID(), scope.RepositoryID(), record.Source().String(), record.DeduplicationKey(), record.PlannerIdentity(),
			record.DeliveryIdentity(), record.Identity(), record.Reason(), record.RefusedAtMillis(),
		); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
	if err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	if found {
		if !existing.SameRefusal(record) {
			return webhook.RefusalRecord{}, false, webhook.ErrRefusalConflict
		}
		return existing, false, nil
	}
	return record, true, nil
}

// Refusal returns the refusal recorded for a delivery and planner identity.
func (s *WebhookStore) Refusal(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key, planner string) (webhook.RefusalRecord, bool, error) {
	if err := validateWebhookRead(ctx, s, scope, source, key, 1); err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	if !validDigest(key) || !validDigest(planner) {
		return webhook.RefusalRecord{}, false, webhook.ErrInvalidRefusalRecord
	}
	tx, err := s.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	defer tx.Rollback()
	record, found, err := queryWebhookRefusalTransaction(ctx, tx, scope, source, key, planner)
	if err != nil {
		return webhook.RefusalRecord{}, false, redactTransactionError(err)
	}
	if err := commit(tx); err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	return record, found, nil
}

func queryWebhookRefusalTransaction(ctx context.Context, tx *sql.Tx, scope webhook.RepositoryScope, source webhook.Source, key, planner string) (webhook.RefusalRecord, bool, error) {
	var deliveryIdentity, recordIdentity, reason string
	var refusedAt int64
	err := tx.QueryRowContext(ctx, `SELECT delivery_identity, record_identity, reason, refused_at_milliseconds
FROM open_trestle_webhook_refusals
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4 AND planner_identity = $5`,
		scope.TenantID(), scope.RepositoryID(), source.String(), key, planner).Scan(&deliveryIdentity, &recordIdentity, &reason, &refusedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return webhook.RefusalRecord{}, false, nil
	}
	if err != nil {
		return webhook.RefusalRecord{}, false, classifyTransactionError(err)
	}
	record, err := webhook.RestoreRefusalRecord(scope, source, key, deliveryIdentity, planner, reason, refusedAt, recordIdentity)
	if err != nil {
		return webhook.RefusalRecord{}, false, ErrCorruptRecord
	}
	return record, true, nil
}

var _ webhook.RefusalStore = (*WebhookStore)(nil)
