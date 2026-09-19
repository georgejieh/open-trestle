package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/jackc/pgx/v5/stdlib"
)

func (s *Store) EnqueueTaskNotification(ctx context.Context, notice controlplane.TaskNotification) (bool, error) {
	if validateNotificationStore(ctx, s) != nil || notice.Validate() != nil {
		return false, controlplane.ErrInvalidTaskNotificationQueue
	}
	encoded, err := controlplane.EncodeTaskNotification(notice)
	if err != nil {
		return false, controlplane.ErrInvalidTaskNotification
	}
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	scope := notice.Scope()
	inserted := false
	err = s.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		inserted = false
		if err := lockScopeTransaction(ctx, tx, "task-notification:"+notice.Identity()); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, scope); err != nil {
			return err
		}
		var existingIdentity, existingChecksum string
		var existing []byte
		err := tx.QueryRowContext(ctx, `SELECT notice_identity, canonical_notice, canonical_checksum
FROM open_trestle_task_notifications
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND notice_identity = $4`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), notice.Identity()).Scan(&existingIdentity, &existing, &existingChecksum)
		if err == nil {
			if existingIdentity != notice.Identity() || existingChecksum != checksum || !bytes.Equal(existing, encoded) {
				return controlplane.ErrTaskNotificationConflict
			}
			if _, parseErr := controlplane.ParseTaskNotification(existing); parseErr != nil {
				return ErrCorruptRecord
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_task_notifications
(tenant_id, repository_id, review_run_id, scope_identity, notice_identity, plan_identity, task_state_revision, task_state_event_identity, task_key, task_identity, handler_identity, attempt, available_at, canonical_notice, canonical_checksum)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), notice.Identity(), notice.PlanIdentity(), notice.TaskStateRevision(), notice.TaskStateEventIdentity(), notice.TaskKey(), notice.TaskIdentity(), notice.HandlerIdentity(), notice.Attempt(), notice.AvailableAt(), encoded, checksum); err != nil {
			return classifyTransactionError(err)
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

func (s *Store) ClaimTaskNotification(ctx context.Context, scope audit.ReviewScope, worker string, at time.Time, duration time.Duration) (controlplane.TaskNotificationLease, bool, error) {
	if validateNotificationStore(ctx, s) != nil || scope.Validate() != nil || !validNotificationWorker(worker) || !validNotificationTime(at, duration) {
		return controlplane.TaskNotificationLease{}, false, controlplane.ErrInvalidTaskNotificationQueue
	}
	at = time.UnixMilli(at.UnixMilli()).UTC()
	expires := at.Add(duration)
	var token string
	var claimedLease controlplane.TaskNotificationLease
	found := false
	err := s.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		claimedLease, found = controlplane.TaskNotificationLease{}, false
		var identity, planIdentity, headIdentity, taskKey, taskIdentity, handlerIdentity, checksum string
		var revision uint64
		var attempt uint8
		var available time.Time
		var encoded []byte
		var delivery int64
		err := tx.QueryRowContext(ctx, `SELECT notice_identity, plan_identity, task_state_revision, task_state_event_identity, task_key, task_identity, handler_identity, attempt, available_at, canonical_notice, canonical_checksum, delivery_count
FROM open_trestle_task_notifications
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
  AND acknowledged_at IS NULL AND delivery_count < 10 AND available_at <= $4
  AND (lease_expires_at IS NULL OR lease_expires_at <= $4)
ORDER BY available_at ASC, notice_identity ASC
FOR UPDATE SKIP LOCKED LIMIT 1`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), at).Scan(&identity, &planIdentity, &revision, &headIdentity, &taskKey, &taskIdentity, &handlerIdentity, &attempt, &available, &encoded, &checksum, &delivery)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return classifyTransactionError(err)
		}
		if delivery < 0 || delivery >= 10 {
			return ErrCorruptRecord
		}
		notice, err := controlplane.ParseTaskNotification(encoded)
		digest := sha256.Sum256(encoded)
		valid := err == nil && identity == notice.Identity() && scope.Identity() == notice.Scope().Identity() && planIdentity == notice.PlanIdentity() && revision == notice.TaskStateRevision() && headIdentity == notice.TaskStateEventIdentity() && taskKey == notice.TaskKey() && taskIdentity == notice.TaskIdentity() && handlerIdentity == notice.HandlerIdentity() && attempt == notice.Attempt() && available.Equal(notice.AvailableAt()) && checksum == hex.EncodeToString(digest[:])
		if !valid {
			return ErrCorruptRecord
		}
		// An unexposed token survives only confirmed aborted attempts of this call.
		if token == "" {
			token, err = postgresNotificationToken(s.notificationRandom)
			if err != nil {
				return ErrDatabaseUnavailable
			}
		}
		lease, err := controlplane.NewTaskNotificationLease(notice, worker, token, uint8(delivery+1), at, expires)
		if err != nil {
			return ErrCorruptRecord
		}
		result, err := tx.ExecContext(ctx, `UPDATE open_trestle_task_notifications
SET delivery_count = delivery_count + 1, lease_worker_identity = $1, lease_token_identity = $2, leased_at = $3, lease_expires_at = $4
WHERE tenant_id = $5 AND repository_id = $6 AND review_run_id = $7 AND notice_identity = $8 AND delivery_count = $9`, worker, lease.TokenIdentity(), at, expires, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), notice.Identity(), delivery)
		if err != nil {
			return classifyTransactionError(err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return ErrDatabaseUnavailable
		}
		claimedLease, found = lease, true
		return nil
	})
	if err != nil {
		return controlplane.TaskNotificationLease{}, false, err
	}
	return claimedLease, found, nil
}

func (s *Store) AcknowledgeTaskNotification(ctx context.Context, lease controlplane.TaskNotificationLease, at time.Time) error {
	if validateNotificationStore(ctx, s) != nil || lease.Validate() != nil || at.IsZero() {
		return controlplane.ErrInvalidTaskNotificationQueue
	}
	at = time.UnixMilli(at.UnixMilli()).UTC()
	if at.Before(lease.LeasedAt()) || at.After(lease.ExpiresAt()) {
		return controlplane.ErrInvalidTaskNotificationQueue
	}
	scope := lease.Notification().Scope()
	return s.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `UPDATE open_trestle_task_notifications
SET acknowledged_at = $1, lease_worker_identity = NULL, lease_token_identity = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE tenant_id = $2 AND repository_id = $3 AND review_run_id = $4 AND notice_identity = $5
  AND acknowledged_at IS NULL AND delivery_count = $6 AND lease_worker_identity = $7
  AND lease_token_identity = $8 AND leased_at = $9 AND lease_expires_at = $10 AND lease_expires_at >= $1`, at, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), lease.Notification().Identity(), lease.Delivery(), lease.WorkerIdentity(), lease.TokenIdentity(), lease.LeasedAt(), lease.ExpiresAt())
		if err != nil {
			return classifyTransactionError(err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return ErrDatabaseUnavailable
		}
		if affected != 1 {
			return controlplane.ErrTaskNotificationLeaseMismatch
		}
		return nil
	})
}
func validateNotificationStore(ctx context.Context, s *Store) error {
	if nilContext(ctx) || s == nil || s.database == nil || s.notificationRandom == nil || ctx.Err() != nil {
		return controlplane.ErrInvalidTaskNotificationQueue
	}
	return nil
}
func validNotificationWorker(value string) bool { return validScopeValue(value) }
func validNotificationTime(at time.Time, duration time.Duration) bool {
	return !at.IsZero() && duration%time.Millisecond == 0 && duration >= time.Second && duration <= 24*time.Hour && !at.Add(duration).Before(at) && at.Add(duration).Year() <= 9999
}
func postgresNotificationToken(random io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	token := hex.EncodeToString(value)
	if len(token) != 64 || strings.Trim(token, "0") == "" {
		return "", controlplane.ErrInvalidTaskNotificationQueue
	}
	return token, nil
}

var _ controlplane.TaskNotificationQueue = (*Store)(nil)

// WaitForTaskNotification blocks on PostgreSQL LISTEN until a committed enqueue wakes consumers.
func (s *Store) WaitForTaskNotification(ctx context.Context) error {
	if s == nil || s.database == nil || s.notificationRandom == nil || nilContext(ctx) {
		return controlplane.ErrInvalidTaskNotificationQueue
	}
	if ctx.Err() != nil {
		return controlplane.ErrTaskNotificationWaitCanceled
	}
	connection, err := s.database.Conn(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return controlplane.ErrTaskNotificationWaitCanceled
		}
		return ErrDatabaseUnavailable
	}
	defer connection.Close()
	err = connection.Raw(func(driverConnection any) error {
		connection, ok := driverConnection.(*stdlib.Conn)
		if !ok {
			return ErrDatabaseUnavailable
		}
		if _, err := connection.Conn().Exec(ctx, "LISTEN open_trestle_task_notifications"); err != nil {
			return ErrDatabaseUnavailable
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _ = connection.Conn().Exec(cleanup, "UNLISTEN open_trestle_task_notifications")
		}()
		notification, err := connection.Conn().WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return controlplane.ErrTaskNotificationWaitCanceled
			}
			return ErrDatabaseUnavailable
		}
		if notification == nil || notification.Channel != "open_trestle_task_notifications" || notification.Payload != "" {
			return ErrCorruptRecord
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return controlplane.ErrTaskNotificationWaitCanceled
		}
		return err
	}
	return nil
}

var _ controlplane.TaskNotificationWaiter = (*Store)(nil)
