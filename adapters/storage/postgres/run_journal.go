package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func (s *Store) SavePlan(ctx context.Context, plan controlplane.ReviewRunPlan) error {
	if err := validateRunContext(ctx, s); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	encoded, err := controlplane.EncodeReviewRunPlan(plan)
	if err != nil {
		return err
	}
	scope := plan.Scope()
	return s.retrySerializableMutation(ctx, scope.TenantID(), controlplane.ErrRunJournalContextDone, func(tx *sql.Tx) error {
		if err := lockScopeTransaction(ctx, tx, scope.Identity()); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, scope); err != nil {
			return err
		}
		var existingIdentity string
		var existingBytes []byte
		err := tx.QueryRowContext(ctx, `SELECT plan_identity, canonical_plan
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&existingIdentity, &existingBytes)
		if err == nil {
			existing, parseErr := controlplane.ParseReviewRunPlan(existingBytes)
			if parseErr != nil || existingIdentity != existing.Identity() || existing.Scope().Identity() != scope.Identity() {
				return ErrCorruptRecord
			}
			if existing.Identity() != plan.Identity() || !bytes.Equal(existingBytes, encoded) {
				return controlplane.ErrRunPlanConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		var eventPlanIdentity string
		err = tx.QueryRowContext(ctx, `SELECT plan_identity
FROM open_trestle_run_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
ORDER BY sequence ASC LIMIT 1`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&eventPlanIdentity)
		if err == nil && eventPlanIdentity != plan.Identity() {
			return controlplane.ErrRunPlanConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO open_trestle_run_plans
(tenant_id, repository_id, review_run_id, scope_identity, plan_identity, canonical_plan)
VALUES ($1, $2, $3, $4, $5, $6)`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), plan.Identity(), encoded); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
}

func (s *Store) LoadPlan(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunPlan, bool, error) {
	if err := validateRunScope(ctx, s, scope); err != nil {
		return controlplane.ReviewRunPlan{}, false, err
	}
	tx, err := s.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return controlplane.ReviewRunPlan{}, false, err
	}
	defer tx.Rollback()
	var identity string
	var encoded []byte
	err = tx.QueryRowContext(ctx, `SELECT plan_identity, canonical_plan
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&identity, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.ReviewRunPlan{}, false, commit(tx)
	}
	if err != nil {
		return controlplane.ReviewRunPlan{}, false, ErrDatabaseUnavailable
	}
	plan, err := controlplane.ParseReviewRunPlan(encoded)
	if err != nil || plan.Identity() != identity || plan.Scope().Identity() != scope.Identity() {
		return controlplane.ReviewRunPlan{}, false, ErrCorruptRecord
	}
	if err := commit(tx); err != nil {
		return controlplane.ReviewRunPlan{}, false, err
	}
	return plan, true, nil
}

func (s *Store) ListPlans(ctx context.Context, tenantID, repositoryID, afterRunID string, limit int) ([]controlplane.ReviewRunPlan, error) {
	if err := validateRunContext(ctx, s); err != nil {
		return nil, err
	}
	if !validScopeValue(tenantID) || !validScopeValue(repositoryID) || afterRunID != "" && !validScopeValue(afterRunID) || limit <= 0 || limit > 1000 {
		return nil, controlplane.ErrInvalidRunPlanQuery
	}
	tx, err := s.beginTenant(ctx, tenantID, sql.LevelReadCommitted)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT plan_identity, canonical_plan
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id > $3
ORDER BY review_run_id ASC LIMIT $4`, tenantID, repositoryID, afterRunID, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	plans := make([]controlplane.ReviewRunPlan, 0)
	previous := afterRunID
	for rows.Next() {
		var identity string
		var encoded []byte
		if err := rows.Scan(&identity, &encoded); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		plan, parseErr := controlplane.ParseReviewRunPlan(encoded)
		if parseErr != nil || plan.Identity() != identity || plan.Scope().TenantID() != tenantID || plan.Scope().RepositoryID() != repositoryID || plan.Scope().ReviewRunID() <= previous {
			return nil, ErrCorruptRecord
		}
		plans = append(plans, plan)
		previous = plan.Scope().ReviewRunID()
	}
	if rows.Err() != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := commit(tx); err != nil {
		return nil, err
	}
	return plans, nil
}

func (s *Store) Head(ctx context.Context, scope audit.ReviewScope) (controlplane.RunEvent, bool, error) {
	if err := validateRunScope(ctx, s, scope); err != nil {
		return controlplane.RunEvent{}, false, err
	}
	tx, err := s.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return controlplane.RunEvent{}, false, err
	}
	defer tx.Rollback()
	event, found, err := queryRunHead(ctx, tx, scope)
	if err != nil {
		return controlplane.RunEvent{}, false, err
	}
	if err := commit(tx); err != nil {
		return controlplane.RunEvent{}, false, err
	}
	return event, found, nil
}

func (s *Store) Append(ctx context.Context, expectedHead string, event controlplane.RunEvent) error {
	if err := validateRunContext(ctx, s); err != nil {
		return err
	}
	if expectedHead != "" && !validDigest(expectedHead) {
		return controlplane.ErrRunJournalHeadConflict
	}
	if err := event.Validate(); err != nil {
		return err
	}
	encoded, err := controlplane.EncodeRunEvent(event)
	if err != nil {
		return err
	}
	scope := event.Scope()
	return s.retrySerializableMutation(ctx, scope.TenantID(), controlplane.ErrRunJournalContextDone, func(tx *sql.Tx) error {
		if err := lockScopeTransaction(ctx, tx, scope.Identity()); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, scope); err != nil {
			return err
		}
		var planIdentity string
		err := tx.QueryRowContext(ctx, `SELECT plan_identity
FROM open_trestle_run_plans
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&planIdentity)
		if err == nil && planIdentity != event.PlanIdentity() {
			return controlplane.ErrRunPlanConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		head, found, err := queryRunHeadTransaction(ctx, tx, scope)
		if err != nil {
			return err
		}
		if found && head.Identity() == event.Identity() {
			return nil
		}
		actualHead := ""
		wantSequence := uint64(1)
		if found {
			actualHead, wantSequence = head.Identity(), head.Sequence()+1
		}
		if actualHead != expectedHead {
			return controlplane.ErrRunJournalHeadConflict
		}
		if event.Sequence() != wantSequence {
			return controlplane.ErrRunJournalSequenceMismatch
		}
		if event.PreviousIdentity() != actualHead {
			return controlplane.ErrRunJournalChainMismatch
		}
		if wantSequence > maxStreamEvents {
			return controlplane.ErrRunJournalStreamTooLarge
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_run_events
(tenant_id, repository_id, review_run_id, scope_identity, plan_identity, sequence, event_identity, previous_identity, canonical_event, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(),
			event.PlanIdentity(), event.Sequence(), event.Identity(), event.PreviousIdentity(), encoded, event.OccurredAt(),
		); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
}

func (s *Store) Read(ctx context.Context, scope audit.ReviewScope, after uint64, limit int) ([]controlplane.RunEvent, error) {
	if err := validateRunScope(ctx, s, scope); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		return nil, controlplane.ErrInvalidRunJournalReadLimit
	}
	tx, err := s.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT sequence, event_identity, canonical_event
FROM open_trestle_run_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND sequence > $4
ORDER BY sequence ASC LIMIT $5`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), after, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	events := make([]controlplane.RunEvent, 0)
	previousSequence := after
	for rows.Next() {
		var sequence uint64
		var identity string
		var encoded []byte
		if err := rows.Scan(&sequence, &identity, &encoded); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		event, parseErr := controlplane.ParseRunEvent(encoded)
		if parseErr != nil || event.Identity() != identity || event.Sequence() != sequence || event.Scope().Identity() != scope.Identity() || sequence != previousSequence+1 {
			return nil, ErrCorruptRecord
		}
		events = append(events, event)
		previousSequence = sequence
	}
	if rows.Err() != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := commit(tx); err != nil {
		return nil, err
	}
	return events, nil
}

func queryRunHead(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (controlplane.RunEvent, bool, error) {
	event, found, err := queryRunHeadTransaction(ctx, tx, scope)
	return event, found, redactTransactionError(err)
}

func queryRunHeadTransaction(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (controlplane.RunEvent, bool, error) {
	var identity string
	var sequence uint64
	var encoded []byte
	var eventCount uint64
	err := tx.QueryRowContext(ctx, `SELECT sequence, event_identity, canonical_event, count(*) OVER ()
FROM open_trestle_run_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
ORDER BY sequence DESC LIMIT 1`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&sequence, &identity, &encoded, &eventCount)
	if errors.Is(err, sql.ErrNoRows) {
		return controlplane.RunEvent{}, false, nil
	}
	if err != nil {
		return controlplane.RunEvent{}, false, classifyTransactionError(err)
	}
	event, err := controlplane.ParseRunEvent(encoded)
	if err != nil || event.Identity() != identity || event.Sequence() != sequence || eventCount != sequence || event.Scope().Identity() != scope.Identity() {
		return controlplane.RunEvent{}, false, ErrCorruptRecord
	}
	return event, true, nil
}

func validateRunContext(ctx context.Context, store *Store) error {
	if nilContext(ctx) {
		return controlplane.ErrInvalidRunJournalContext
	}
	if store == nil || store.database == nil {
		return controlplane.ErrInvalidRunJournal
	}
	if ctx.Err() != nil {
		return controlplane.ErrRunJournalContextDone
	}
	return nil
}
func validateRunScope(ctx context.Context, store *Store, scope audit.ReviewScope) error {
	if err := validateRunContext(ctx, store); err != nil {
		return err
	}
	return scope.Validate()
}

var _ controlplane.RunJournal = (*Store)(nil)
