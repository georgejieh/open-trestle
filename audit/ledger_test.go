package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func auditEvent(t *testing.T, scope ReviewScope, sequence uint64, previous string, kind EventKind, marker byte) Event {
	t.Helper()
	event, err := NewEvent(scope, sequence, previous, kind, strings.Repeat(string(marker), 64), nil, time.UnixMilli(int64(sequence)))
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestMemoryLedgerAppendsAndReadsOneScopeInOrder(t *testing.T) {
	ledger := NewMemoryLedger()
	scope, _ := NewReviewScope("tenant", "repo", "run")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	second := auditEvent(t, scope, 2, first.Identity(), EventRouteAttemptClaimed, 'b')
	if err := ledger.Append(context.Background(), first.Identity(), second); err != nil {
		t.Fatal(err)
	}
	head, exists, err := ledger.Head(context.Background(), scope)
	if err != nil || !exists || head.Identity() != second.Identity() {
		t.Fatalf("Head() = (%#v, %t, %v)", head, exists, err)
	}
	events, err := ledger.Read(context.Background(), scope, 0, 10)
	if err != nil || len(events) != 2 || events[0].Identity() != first.Identity() || events[1].Identity() != second.Identity() {
		t.Fatalf("Read() = (%#v, %v)", events, err)
	}
	events[0].causalParentIdentities = []string{strings.Repeat("f", 64)}
	again, _ := ledger.Read(context.Background(), scope, 0, 10)
	if len(again[0].CausalParentIdentities()) != 0 {
		t.Fatal("ledger exposed mutable event state")
	}
	page, err := ledger.Read(context.Background(), scope, 1, 1)
	if err != nil || len(page) != 1 || page[0].Identity() != second.Identity() {
		t.Fatalf("paged read = (%#v, %v)", page, err)
	}
}

func TestMemoryLedgerEnforcesExpectedHeadAndChain(t *testing.T) {
	ledger := NewMemoryLedger()
	scope, _ := NewReviewScope("tenant", "repo", "run")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	if err := ledger.Append(context.Background(), strings.Repeat("f", 64), first); !errors.Is(err, ErrAuditHeadConflict) {
		t.Fatalf("wrong initial head = %v", err)
	}
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	wrongPrevious := auditEvent(t, scope, 2, strings.Repeat("f", 64), EventRouteAttemptClaimed, 'b')
	if err := ledger.Append(context.Background(), first.Identity(), wrongPrevious); !errors.Is(err, ErrAuditChainMismatch) {
		t.Fatalf("wrong previous = %v", err)
	}
	wrongSequence, _ := NewEvent(scope, 3, first.Identity(), EventRouteAttemptClaimed, strings.Repeat("b", 64), nil, time.UnixMilli(3))
	if err := ledger.Append(context.Background(), first.Identity(), wrongSequence); !errors.Is(err, ErrAuditChainMismatch) {
		t.Fatalf("wrong sequence = %v", err)
	}
	if err := ledger.Append(context.Background(), first.Identity(), first); !errors.Is(err, ErrAuditChainMismatch) {
		t.Fatalf("duplicate event = %v", err)
	}
}

func TestMemoryLedgerKeepsScopesIsolated(t *testing.T) {
	ledger := NewMemoryLedger()
	firstScope, _ := NewReviewScope("tenant-a", "repo", "run")
	secondScope, _ := NewReviewScope("tenant-b", "repo", "run")
	first := auditEvent(t, firstScope, 1, "", EventRouteSelected, 'a')
	second := auditEvent(t, secondScope, 1, "", EventRouteSelected, 'b')
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), "", second); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		scope    ReviewScope
		identity string
	}{{firstScope, first.Identity()}, {secondScope, second.Identity()}} {
		events, err := ledger.Read(context.Background(), test.scope, 0, 10)
		if err != nil || len(events) != 1 || events[0].Identity() != test.identity {
			t.Fatalf("isolated Read() = (%#v, %v)", events, err)
		}
	}
}

func TestMemoryLedgerSerializesConcurrentHeadUpdates(t *testing.T) {
	ledger := NewMemoryLedger()
	scope, _ := NewReviewScope("tenant", "repo", "run")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	left := auditEvent(t, scope, 2, first.Identity(), EventRouteAttemptClaimed, 'b')
	right := auditEvent(t, scope, 2, first.Identity(), EventRouteDispatchCompleted, 'c')
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for _, event := range []Event{left, right} {
		wait.Add(1)
		go func() { defer wait.Done(); errorsSeen <- ledger.Append(context.Background(), first.Identity(), event) }()
	}
	wait.Wait()
	close(errorsSeen)
	succeeded, conflicted := 0, 0
	for err := range errorsSeen {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrAuditHeadConflict) {
			conflicted++
		} else {
			t.Fatalf("unexpected append error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent updates succeeded=%d conflicted=%d", succeeded, conflicted)
	}
}

func TestMemoryLedgerRejectsInvalidQueriesAndCanceledContext(t *testing.T) {
	ledger := NewMemoryLedger()
	scope, _ := NewReviewScope("tenant", "repo", "run")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ledger.Append(ctx, "", auditEvent(t, scope, 1, "", EventRouteSelected, 'a')); !errors.Is(err, ErrAuditContextDone) {
		t.Fatalf("canceled append = %v", err)
	}
	if _, err := ledger.Read(context.Background(), scope, 0, 0); !errors.Is(err, ErrInvalidAuditReadLimit) {
		t.Fatalf("zero limit = %v", err)
	}
	if _, _, err := ledger.Head(context.Background(), ReviewScope{}); !errors.Is(err, ErrInvalidAuditScopeIdentifier) {
		t.Fatalf("invalid scope = %v", err)
	}
}

var _ Ledger = (*MemoryLedger)(nil)
