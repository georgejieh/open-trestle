package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLedgerPersistsAndVerifiesEventChain(t *testing.T) {
	root := t.TempDir()
	ledger, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := NewReviewScope("tenant", "repo", "run")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	second := auditEvent(t, scope, 2, first.Identity(), EventRouteAttemptClaimed, 'b')
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), first.Identity(), second); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	events, err := reopened.Read(context.Background(), scope, 0, 10)
	if err != nil || len(events) != 2 || events[0].Identity() != first.Identity() || events[1].Identity() != second.Identity() {
		t.Fatalf("persisted Read() = (%#v, %v)", events, err)
	}
	head, exists, err := reopened.Head(context.Background(), scope)
	if err != nil || !exists || head.Identity() != second.Identity() {
		t.Fatalf("persisted Head() = (%#v, %t, %v)", head, exists, err)
	}
	contents, err := os.ReadFile(reopened.streamPath(scope))
	if err != nil || strings.Contains(string(contents), "payload") || !strings.Contains(string(contents), `"tenant_id":"tenant"`) {
		t.Fatalf("stored record = %q, %v", contents, err)
	}
}

func TestFileLedgerHoldsExclusiveWriterLease(t *testing.T) {
	root := t.TempDir()
	first, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := NewFileLedger(root); !errors.Is(err, ErrAuditLedgerLocked) || second != nil {
		t.Fatalf("second writer = (%#v, %v)", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileLedgerFailsClosedOnCorruptStream(t *testing.T) {
	root := t.TempDir()
	ledger, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	scope, _ := NewReviewScope("tenant", "repo", "run")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	path := ledger.streamPath(scope)
	contents, _ := os.ReadFile(path)
	contents = []byte(strings.Replace(string(contents), strings.Repeat("a", 64), strings.Repeat("b", 64), 1))
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if events, err := ledger.Read(context.Background(), scope, 0, 10); !errors.Is(err, ErrCorruptAuditStream) || events != nil {
		t.Fatalf("corrupt Read() = (%#v, %v)", events, err)
	}
	if err := ledger.Append(context.Background(), first.Identity(), auditEvent(t, scope, 2, first.Identity(), EventRouteAttemptClaimed, 'c')); !errors.Is(err, ErrCorruptAuditStream) {
		t.Fatalf("corrupt Append() = %v", err)
	}
}

func TestFileLedgerKeepsScopeFilesSeparateAndChecksHead(t *testing.T) {
	ledger, err := NewFileLedger(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
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
	if ledger.streamPath(firstScope) == ledger.streamPath(secondScope) {
		t.Fatal("scopes share a file")
	}
	wrong := auditEvent(t, firstScope, 2, first.Identity(), EventRouteAttemptClaimed, 'c')
	if err := ledger.Append(context.Background(), strings.Repeat("f", 64), wrong); !errors.Is(err, ErrAuditHeadConflict) {
		t.Fatalf("head conflict = %v", err)
	}
	if _, err := os.Stat(filepath.Join(ledger.root, firstScope.Identity()+auditStreamFileSuffix)); err != nil {
		t.Fatal(err)
	}
}

func TestNewFileLedgerRejectsUnsafeRootAndClosedUse(t *testing.T) {
	if ledger, err := NewFileLedger(""); !errors.Is(err, ErrInvalidAuditLedgerRoot) || ledger != nil {
		t.Fatalf("empty root = (%#v, %v)", ledger, err)
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if ledger, err := NewFileLedger(link); !errors.Is(err, ErrInvalidAuditLedgerRoot) || ledger != nil {
		t.Fatalf("symlink root = (%#v, %v)", ledger, err)
	}
	ledger, err := NewFileLedger(filepath.Join(parent, "ledger"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	scope, _ := NewReviewScope("tenant", "repo", "run")
	if _, _, err := ledger.Head(context.Background(), scope); !errors.Is(err, ErrAuditLedgerClosed) {
		t.Fatalf("closed Head() = %v", err)
	}
}

var _ Ledger = (*FileLedger)(nil)
