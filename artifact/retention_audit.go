package artifact

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const maxDeletionAuditConflicts = 8

// RecordDeletionAudit appends content-free physical deletion evidence idempotently.
func RecordDeletionAudit(ctx context.Context, ledger audit.Ledger, receipt DeletionReceipt, occurredAt time.Time) (audit.Event, error) {
	if isNilAuditLedger(ledger) {
		return audit.Event{}, audit.ErrInvalidAuditLedger
	}
	if receipt.Validate() != nil || occurredAt.Before(receipt.DeletedAt()) {
		return audit.Event{}, ErrInvalidDeletionReceipt
	}
	for range maxDeletionAuditConflicts {
		events, err := readDeletionAudit(ctx, ledger, receipt.Scope())
		if err != nil {
			return audit.Event{}, err
		}
		for _, event := range events {
			if event.Kind() == audit.EventArtifactDeleted && event.SubjectIdentity() == receipt.Identity() {
				return event, nil
			}
		}
		// Compare against the same snapshot used for duplicate detection.
		sequence, previous := uint64(1), ""
		if len(events) != 0 {
			head := events[len(events)-1]
			sequence, previous = head.Sequence()+1, head.Identity()
		}
		event, err := audit.NewEvent(receipt.Scope(), sequence, previous, audit.EventArtifactDeleted, receipt.Identity(), []string{receipt.ArtifactIdentity(), receipt.AuthorizationIdentity()}, occurredAt)
		if err != nil {
			return audit.Event{}, err
		}
		if err := ledger.Append(ctx, previous, event); err == nil {
			return event, nil
		} else if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, err
		}
	}
	return audit.Event{}, audit.ErrAuditHeadConflict
}
func readDeletionAudit(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope) ([]audit.Event, error) {
	var events []audit.Event
	var after uint64
	for pages := 0; pages < 100; pages++ {
		page, err := ledger.Read(ctx, scope, after, 1000)
		if err != nil {
			return nil, err
		}
		events = append(events, page...)
		if len(page) < 1000 {
			return events, nil
		}
		next := page[len(page)-1].Sequence()
		if next <= after {
			return nil, audit.ErrAuditChainMismatch
		}
		after = next
	}
	return nil, audit.ErrAuditChainMismatch
}
func isNilAuditLedger(ledger audit.Ledger) bool {
	if ledger == nil {
		return true
	}
	value := reflect.ValueOf(ledger)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
