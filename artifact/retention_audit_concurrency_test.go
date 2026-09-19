package artifact

import (
	"context"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

type appendAfterAuditRead struct {
	audit.Ledger
	afterRead func()
}

func (l *appendAfterAuditRead) Read(ctx context.Context, scope audit.ReviewScope, after uint64, limit uint16) ([]audit.Event, error) {
	events, err := l.Ledger.Read(ctx, scope, after, limit)
	if err == nil && l.afterRead != nil {
		action := l.afterRead
		l.afterRead = nil
		action()
	}
	return events, err
}

func TestDeletionAuditRescansWhenAppendWinsAfterRead(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-audit-race")
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"erase":true}`)
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	receipt := newDeletionReceipt(value, authorization, time.UnixMilli(1000))
	ledger := audit.NewMemoryLedger()
	var first audit.Event
	var firstErr error
	interleaved := &appendAfterAuditRead{Ledger: ledger, afterRead: func() {
		first, firstErr = RecordDeletionAudit(ctx, ledger, receipt, time.UnixMilli(1001))
	}}
	second, err := RecordDeletionAudit(ctx, interleaved, receipt, time.UnixMilli(1002))
	if firstErr != nil || err != nil {
		t.Fatalf("record errors: first=%v second=%v", firstErr, err)
	}
	events, err := ledger.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || second.Identity() != first.Identity() {
		t.Fatalf("duplicate deletion events: count=%d first=%s second=%s", len(events), first.Identity(), second.Identity())
	}
}
