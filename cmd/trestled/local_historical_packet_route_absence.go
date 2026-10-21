package main

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/audit"
)

var errHistoricalPacketRouteAbsence = errors.New("historical packet audit absence not observed")

// localHistoricalPacketAuditHead is an informational observed head, not an
// authorization token or a validated source/audit closure.
type localHistoricalPacketAuditHead struct {
	present  bool
	sequence uint64
	identity string
}

type historicalPacketAuditReader interface {
	Head(context.Context, audit.ReviewScope) (audit.Event, bool, error)
	Read(context.Context, audit.ReviewScope, uint64, uint16) ([]audit.Event, error)
}

// observeHistoricalPacketRouteAbsence is a read-only, startup-only allowed-kind
// absence observation. Its premise is exclusive, unexposed boot-time FileLedger
// and OwnerA ownership. It is not a transaction or protection against raw
// same-UID writes. Later mutation requires separate authority and checks.
//
// Empty streams and ReviewSnapshotBound events alone are permitted. The latter
// kind is emitted by RecordAcquiredReviewSnapshot, but this scope-only predicate
// does not validate its subject or parents against any expected source snapshot.
// Context-stage events are deliberately refused; not every legitimate historical
// packet is accepted by this conservative first branch.
func observeHistoricalPacketRouteAbsence(ctx context.Context, ledger *audit.FileLedger, scope audit.ReviewScope) (localHistoricalPacketAuditHead, error) {
	if ledger == nil {
		return localHistoricalPacketAuditHead{}, errHistoricalPacketRouteAbsence
	}
	return readHistoricalPacketRouteAbsence(ctx, ledger, scope)
}

func readHistoricalPacketRouteAbsence(ctx context.Context, ledger historicalPacketAuditReader, scope audit.ReviewScope) (localHistoricalPacketAuditHead, error) {
	fail := func(err error) (localHistoricalPacketAuditHead, error) {
		return localHistoricalPacketAuditHead{}, errors.Join(errHistoricalPacketRouteAbsence, err)
	}
	if daemonNilDependency(ctx) || daemonNilDependency(ledger) {
		return fail(nil)
	}
	if err := scope.Validate(); err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	before, present, err := ledger.Head(ctx, scope)
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	observed := localHistoricalPacketAuditHead{present: present}
	if present {
		if before.Validate() != nil || before.Scope() != scope || before.Kind() != audit.EventReviewSnapshotBound {
			return fail(nil)
		}
		observed.sequence = before.Sequence()
		observed.identity = before.Identity()
	} else if before.Identity() != "" || before.Sequence() != 0 {
		return fail(nil)
	}
	var sequence uint64
	previous := ""
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		// FileLedger already enforces its 10,000-event stream limit. The captured
		// head bounds progress; 64 is the existing owner-audit page size.
		events, err := ledger.Read(ctx, scope, sequence, 64)
		if err != nil {
			return fail(err)
		}
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if len(events) > 64 {
			return fail(nil)
		}
		if len(events) == 0 {
			break
		}
		for _, event := range events {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			if sequence >= observed.sequence || event.Validate() != nil || event.Scope() != scope || event.Sequence() != sequence+1 || event.PreviousIdentity() != previous || event.Kind() != audit.EventReviewSnapshotBound {
				return fail(nil)
			}
			sequence = event.Sequence()
			previous = event.Identity()
		}
	}
	if sequence != observed.sequence || previous != observed.identity {
		return fail(nil)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	after, afterPresent, err := ledger.Head(ctx, scope)
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if afterPresent != present {
		return fail(nil)
	}
	if afterPresent {
		if after.Validate() != nil || after.Scope() != scope || after.Sequence() != observed.sequence || after.Identity() != observed.identity {
			return fail(nil)
		}
	} else if after.Identity() != "" || after.Sequence() != 0 {
		return fail(nil)
	}
	return observed, nil
}
