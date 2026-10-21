//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

type rejectionClosingClock struct {
	at, expired time.Time
	calls       int
}

func (c *rejectionClosingClock) Now() time.Time {
	c.calls++
	if c.calls > 2 {
		return c.expired
	}
	return c.at
}

func testGenerationRejectionLateClock(t *testing.T, d *daemon, args []string, getenv func(string) string, fact controlplane.HistoricalContextPacketFact, repository evidence.RepositoryIdentity) {
	t.Helper()
	state := daemonTestFlagValue(t, args, "--state-dir")
	gitRoot, digest, err := openDaemonLocalGitRoot(daemonTestFlagValue(t, args, "--local-git-objects-root"), repository)
	if err != nil {
		t.Fatal(err)
	}
	defer gitRoot.Close()
	gitID, err := observeLocalSourceDirectory(gitRoot.Name(), gitRoot)
	if err != nil {
		t.Fatal(err)
	}
	objectStore, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(objectStore)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := loadLocalGenerationStartupAuthority(context.Background(), daemonTestFlagValue(t, args, "--runtime-route-inventory"), daemonTestFlagValue(t, args, "--runtime-policy"), getenv, daemonTestGenerationSanitizer())
	if err != nil {
		t.Fatal(err)
	}
	var ledger *audit.FileLedger
	for _, closer := range d.closers {
		if value, ok := closer.(*audit.FileLedger); ok {
			ledger = value
		}
	}
	if ledger == nil {
		t.Fatal("ledger missing")
	}
	clock := &rejectionClosingClock{at: time.Now().UTC(), expired: time.UnixMilli(fact.PreparedEvent().PacketDescriptor().ExpiresAtMilliseconds)}
	owner := &localPacketOwner{store: d.artifactStore.(*artifact.FileStore), journal: d.journal.(*controlplane.FileRunJournal), sourceRootDigest: digest, gitIdentity: gitID, pendingSettlementAudit: true, clock: clock, statePath: state, sourceBinding: historicalRecordedSourceBinding{RootIdentity: digest, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity()}, generationStartup: authority}
	err = verifyOwnerSettledStartup(context.Background(), owner, ledger, gitRoot)
	if err == nil || owner.settlementAuditVerified {
		t.Fatalf("expired closing proof admitted after %d clock reads", clock.calls)
	}
	if clock.calls < 3 {
		t.Fatalf("did not reach closing time check: %d: %v", clock.calls, err)
	}
	owner.clock = httpapi.SystemClock{}
	check := func(wantRefusal bool) {
		t.Helper()
		owner.settlementAuditVerified = false
		err := verifyOwnerSettledStartup(context.Background(), owner, ledger, gitRoot)
		if wantRefusal && (err == nil || owner.settlementAuditVerified) {
			t.Fatal("independent later proof admitted invalid evidence")
		}
		if !wantRefusal && (err != nil || !owner.settlementAuditVerified) {
			t.Fatalf("valid independent later proof refused: %v", err)
		}
	}
	check(false)
	auditPath := filepath.Join(state, "audit", fact.Plan().Scope().Identity()+".audit.jsonl")
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, []byte("malformed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check(true)
	if err := os.WriteFile(auditPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	check(false)
	sanitizer := authority.sanitizer
	authority.sanitizer = mismatchedGenerationScanner{sanitizer}
	check(true)
	authority.sanitizer = sanitizer
	check(false)
	scope := fact.Plan().Scope()
	markerErr := errors.New("interrupted owned effect")
	if err := owner.journal.WithScopeIntent(context.Background(), scope, "context-input", fact.FinalHeadIdentity(), func(context.Context) error { return markerErr }, func(context.Context) error { return nil }); !errors.Is(err, markerErr) {
		t.Fatalf("marker fixture: %v", err)
	}
	owner.startupScopeIntents = []string{scope.Identity()}
	check(true)
	if err := os.Remove(filepath.Join(state, scope.Identity()+".scope-intent.json")); err != nil {
		t.Fatal(err)
	}
	owner.startupScopeIntents = nil
	check(false)
}
