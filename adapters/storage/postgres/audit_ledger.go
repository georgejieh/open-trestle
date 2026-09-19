package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// AuditLedger implements the append-only content-free audit ledger in PostgreSQL.
type AuditLedger struct{ store *Store }

// NewAuditLedger validates a database handle without applying migrations.
func NewAuditLedger(database *sql.DB) (*AuditLedger, error) {
	store, err := New(database)
	if err != nil {
		return nil, err
	}
	return &AuditLedger{store: store}, nil
}

func (l *AuditLedger) Append(ctx context.Context, expectedHead string, event audit.Event) error {
	if err := validateAuditContext(ctx, l); err != nil {
		return err
	}
	if expectedHead != "" && !validDigest(expectedHead) {
		return audit.ErrInvalidAuditExpectedHead
	}
	if err := event.Validate(); err != nil {
		return err
	}
	encoded, err := audit.EncodeEvent(event)
	if err != nil {
		return err
	}
	scope := event.Scope()
	return l.store.retrySerializableMutation(ctx, scope.TenantID(), audit.ErrAuditContextDone, func(tx *sql.Tx) error {
		if err := lockScopeTransaction(ctx, tx, "audit:"+scope.Identity()); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, scope); err != nil {
			return err
		}
		head, found, err := queryAuditHeadTransaction(ctx, tx, scope)
		if err != nil {
			return err
		}
		actualHead := ""
		wantSequence := uint64(1)
		if found {
			actualHead, wantSequence = head.Identity(), head.Sequence()+1
		}
		if actualHead != expectedHead {
			return audit.ErrAuditHeadConflict
		}
		if event.Sequence() != wantSequence || event.PreviousIdentity() != actualHead {
			return audit.ErrAuditChainMismatch
		}
		if wantSequence > maxStreamEvents {
			return audit.ErrAuditStreamTooLarge
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_audit_events
(tenant_id, repository_id, review_run_id, scope_identity, sequence, event_identity, previous_identity, canonical_event, occurred_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(),
			event.Sequence(), event.Identity(), event.PreviousIdentity(), encoded,
			time.UnixMilli(event.OccurredAtUnixMilliseconds()).UTC(),
		); err != nil {
			return classifyTransactionError(err)
		}
		return nil
	})
}

func (l *AuditLedger) Head(ctx context.Context, scope audit.ReviewScope) (audit.Event, bool, error) {
	if err := validateAuditScope(ctx, l, scope); err != nil {
		return audit.Event{}, false, err
	}
	tx, err := l.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return audit.Event{}, false, err
	}
	defer tx.Rollback()
	event, found, err := queryAuditHead(ctx, tx, scope)
	if err != nil {
		return audit.Event{}, false, err
	}
	if err := commit(tx); err != nil {
		return audit.Event{}, false, err
	}
	return event, found, nil
}

func (l *AuditLedger) Read(ctx context.Context, scope audit.ReviewScope, after uint64, limit uint16) ([]audit.Event, error) {
	if err := validateAuditScope(ctx, l, scope); err != nil {
		return nil, err
	}
	if limit == 0 || limit > 1000 {
		return nil, audit.ErrInvalidAuditReadLimit
	}
	tx, err := l.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT sequence, event_identity, canonical_event
FROM open_trestle_audit_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND sequence > $4
ORDER BY sequence ASC LIMIT $5`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), after, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	events := make([]audit.Event, 0)
	previousSequence := after
	for rows.Next() {
		var sequence uint64
		var identity string
		var encoded []byte
		if err := rows.Scan(&sequence, &identity, &encoded); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		event, parseErr := audit.ParseEvent(encoded)
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

func queryAuditHead(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (audit.Event, bool, error) {
	event, found, err := queryAuditHeadTransaction(ctx, tx, scope)
	return event, found, redactTransactionError(err)
}

func queryAuditHeadTransaction(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (audit.Event, bool, error) {
	var identity string
	var sequence uint64
	var encoded []byte
	var eventCount uint64
	err := tx.QueryRowContext(ctx, `SELECT sequence, event_identity, canonical_event, count(*) OVER ()
FROM open_trestle_audit_events
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
ORDER BY sequence DESC LIMIT 1`, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).Scan(&sequence, &identity, &encoded, &eventCount)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.Event{}, false, nil
	}
	if err != nil {
		return audit.Event{}, false, classifyTransactionError(err)
	}
	event, err := audit.ParseEvent(encoded)
	if err != nil || event.Identity() != identity || event.Sequence() != sequence || eventCount != sequence || event.Scope().Identity() != scope.Identity() {
		return audit.Event{}, false, ErrCorruptRecord
	}
	return event, true, nil
}

func validateAuditContext(ctx context.Context, ledger *AuditLedger) error {
	if nilContext(ctx) {
		return audit.ErrInvalidAuditContext
	}
	if ledger == nil || ledger.store == nil || ledger.store.database == nil {
		return audit.ErrInvalidAuditLedger
	}
	if ctx.Err() != nil {
		return audit.ErrAuditContextDone
	}
	return nil
}
func validateAuditScope(ctx context.Context, ledger *AuditLedger, scope audit.ReviewScope) error {
	if err := validateAuditContext(ctx, ledger); err != nil {
		return err
	}
	return scope.Validate()
}

var _ audit.Ledger = (*AuditLedger)(nil)
