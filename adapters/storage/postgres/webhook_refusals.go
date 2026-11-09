package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/georgejieh/open-trestle/webhook"
)

// RecordRefusal records a refusal of a delivery this store holds, at most one
// per delivery, in one serializable transaction. The same planner identity's
// record stands; a superseded planner identity's record is replaced.
func (s *WebhookStore) RecordRefusal(ctx context.Context, record webhook.RefusalRecord) (webhook.RefusalRecord, bool, error) {
	if err := validateWebhookOperation(ctx, s); err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	if record.Validate() != nil {
		return webhook.RefusalRecord{}, false, webhook.ErrInvalidRefusalRecord
	}
	scope := record.Scope()
	var existing webhook.RefusalRecord
	kept := false
	err := s.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		kept = false
		mapping, stored, err := queryWebhookMappingTransaction(ctx, tx, scope, record.Source(), record.DeduplicationKey())
		if err != nil {
			return err
		}
		if !stored || mapping.deliveryIdentity != record.DeliveryIdentity() {
			return webhook.ErrInvalidRefusalRecord
		}
		var found bool
		existing, found, err = queryWebhookRefusalTransaction(ctx, tx, scope, record.Source(), record.DeduplicationKey())
		if err != nil {
			return err
		}
		if found && existing.PlannerIdentity() == record.PlannerIdentity() {
			kept = true
			return nil
		}
		statement := `INSERT INTO open_trestle_webhook_refusals
(tenant_id, repository_id, source, deduplication_key, planner_identity, delivery_identity, record_identity, reason, refused_at_milliseconds)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
		if found {
			statement = `UPDATE open_trestle_webhook_refusals
SET planner_identity = $5, delivery_identity = $6, record_identity = $7, reason = $8, refused_at_milliseconds = $9
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4`
		}
		if _, err := tx.ExecContext(ctx, statement,
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
	if kept {
		if !existing.SameRefusal(record) {
			return webhook.RefusalRecord{}, false, webhook.ErrRefusalConflict
		}
		return existing, false, nil
	}
	return record, true, nil
}

// RecordedRefusal returns the refusal recorded for a delivery, whichever
// planner identity recorded it.
func (s *WebhookStore) RecordedRefusal(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key string) (webhook.RefusalRecord, bool, error) {
	if err := validateWebhookRead(ctx, s, scope, source, key, 1); err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	if !validDigest(key) {
		return webhook.RefusalRecord{}, false, webhook.ErrInvalidRefusalRecord
	}
	tx, err := s.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	defer tx.Rollback()
	record, found, err := queryWebhookRefusalTransaction(ctx, tx, scope, source, key)
	if err != nil {
		return webhook.RefusalRecord{}, false, redactTransactionError(err)
	}
	if err := commit(tx); err != nil {
		return webhook.RefusalRecord{}, false, err
	}
	return record, found, nil
}

// Refusal returns the refusal recorded for a delivery by a planner identity.
func (s *WebhookStore) Refusal(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key, planner string) (webhook.RefusalRecord, bool, error) {
	if !validDigest(planner) {
		return webhook.RefusalRecord{}, false, webhook.ErrInvalidRefusalRecord
	}
	record, found, err := s.RecordedRefusal(ctx, scope, source, key)
	if err != nil || !found || record.PlannerIdentity() != planner {
		return webhook.RefusalRecord{}, false, err
	}
	return record, true, nil
}

// ClearRefusal removes the refusal of a delivery if the planner identity
// recorded it.
func (s *WebhookStore) ClearRefusal(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key, planner string) error {
	if err := validateWebhookRead(ctx, s, scope, source, key, 1); err != nil {
		return err
	}
	if !validDigest(key) || !validDigest(planner) {
		return webhook.ErrInvalidRefusalRecord
	}
	return s.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM open_trestle_webhook_refusals
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4 AND planner_identity = $5`,
			scope.TenantID(), scope.RepositoryID(), source.String(), key, planner); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
}

func queryWebhookRefusalTransaction(ctx context.Context, tx *sql.Tx, scope webhook.RepositoryScope, source webhook.Source, key string) (webhook.RefusalRecord, bool, error) {
	var planner, deliveryIdentity, recordIdentity, reason string
	var refusedAt int64
	err := tx.QueryRowContext(ctx, `SELECT planner_identity, delivery_identity, record_identity, reason, refused_at_milliseconds
FROM open_trestle_webhook_refusals
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4`,
		scope.TenantID(), scope.RepositoryID(), source.String(), key).Scan(&planner, &deliveryIdentity, &recordIdentity, &reason, &refusedAt)
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
