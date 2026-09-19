package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/review"
)

func (s *Store) Identity() string {
	if s == nil || s.database == nil || s.publicationAuthority.Validate() != nil {
		return ""
	}
	encoded := []byte("open-trestle/postgresql-publication-attempt-guard/v3/" + s.publicationAuthority.Identity())
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (s *Store) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	if s == nil || s.database == nil || s.Identity() == "" {
		return 0
	}
	return review.PublisherExactOperationKey
}
func (s *Store) ClaimPublicationAttempt(ctx context.Context, scope audit.ReviewScope, operationKey, attemptIdentity, requestIdentity string, at time.Time) (bool, error) {
	if validatePublicationAttemptOperation(ctx, s, scope, at) != nil || !validDigest(operationKey) || !validDigest(attemptIdentity) || !validDigest(requestIdentity) {
		return false, review.ErrPublicationAttemptGuardUnavailable
	}
	at = time.UnixMilli(at.UnixMilli()).UTC()
	acquired := false
	err := s.retrySerializableMutation(ctx, scope.TenantID(), review.ErrPublicationAttemptGuardUnavailable, func(tx *sql.Tx) error {
		acquired = false
		if err := lockScopeTransaction(ctx, tx, "publication-operation:"+operationKey); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, scope); err != nil {
			return err
		}
		var existingAttempt, existingRequest, status string
		err := tx.QueryRowContext(ctx, `SELECT attempt_identity, request_identity, status
FROM open_trestle_publication_attempts
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND operation_key = $4`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), operationKey).Scan(&existingAttempt, &existingRequest, &status)
		if err == nil {
			if existingAttempt != attemptIdentity || existingRequest != requestIdentity || (status != "claimed" && status != "completed") {
				return review.ErrPublicationAttemptGuardConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_publication_attempts
(tenant_id, repository_id, review_run_id, scope_identity, operation_key, attempt_identity, request_identity, status, claimed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'claimed', $8)`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), operationKey, attemptIdentity, requestIdentity, at); err != nil {
			return classifyTransactionError(err)
		}
		acquired = true
		return nil
	})
	if err == review.ErrPublicationAttemptGuardConflict {
		return false, err
	}
	if err != nil {
		return false, review.ErrPublicationAttemptGuardUnavailable
	}
	return acquired, nil
}
func (s *Store) CompletePublicationAttempt(ctx context.Context, scope audit.ReviewScope, attemptIdentity, resultIdentity string, at time.Time) error {
	if validatePublicationAttemptOperation(ctx, s, scope, at) != nil || !validDigest(attemptIdentity) || !validDigest(resultIdentity) {
		return review.ErrPublicationAttemptGuardUnavailable
	}
	at = time.UnixMilli(at.UnixMilli()).UTC()
	err := s.retrySerializableMutation(ctx, scope.TenantID(), review.ErrPublicationAttemptGuardUnavailable, func(tx *sql.Tx) error {
		if err := lockScopeTransaction(ctx, tx, "publication-attempt:"+attemptIdentity); err != nil {
			return err
		}
		var status string
		var existingResult sql.NullString
		var claimedAt time.Time
		err := tx.QueryRowContext(ctx, `SELECT status, result_identity, claimed_at
FROM open_trestle_publication_attempts
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND attempt_identity = $4`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), attemptIdentity).Scan(&status, &existingResult, &claimedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return review.ErrPublicationAttemptGuardConflict
		}
		if err != nil {
			return classifyTransactionError(err)
		}
		if claimedAt.After(at) {
			return review.ErrPublicationAttemptGuardConflict
		}
		if status == "completed" {
			if !existingResult.Valid || existingResult.String != resultIdentity {
				return review.ErrPublicationAttemptGuardConflict
			}
			return nil
		}
		if status != "claimed" || existingResult.Valid {
			return review.ErrPublicationAttemptGuardConflict
		}
		result, err := tx.ExecContext(ctx, `UPDATE open_trestle_publication_attempts
SET status = 'completed', result_identity = $1, completed_at = $2
WHERE tenant_id = $3 AND repository_id = $4 AND review_run_id = $5 AND attempt_identity = $6 AND status = 'claimed' AND result_identity IS NULL`, resultIdentity, at, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), attemptIdentity)
		if err != nil {
			return classifyTransactionError(err)
		}
		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			return review.ErrPublicationAttemptGuardUnavailable
		}
		return nil
	})
	if err != nil && err != review.ErrPublicationAttemptGuardConflict {
		return review.ErrPublicationAttemptGuardUnavailable
	}
	return err
}
func validatePublicationAttemptOperation(ctx context.Context, s *Store, scope audit.ReviewScope, at time.Time) error {
	if nilContext(ctx) || ctx.Err() != nil || s == nil || s.database == nil || s.Identity() == "" || scope.Validate() != nil || at.IsZero() || at.Year() > 9999 {
		return review.ErrPublicationAttemptGuardUnavailable
	}
	return nil
}

var _ review.PublicationAttemptGuard = (*Store)(nil)
