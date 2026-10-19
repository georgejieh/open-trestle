package runtimecatalog

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalFullAdmissionFileJournalSharesScopeGate(t *testing.T) {
	intent, config, _, store := fullAdmissionFixture(t, "run-file-gated")
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	admitter, err := NewLocalFullReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- journal.WithScopeGate(context.Background(), intent.Scope(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	waiting, stop, err := journal.WatchEffectGateContention()
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	admitted := make(chan error, 1)
	go func() { _, err := admitter.Admit(ctx, intent, intent.CreatedAt().Add(time.Second)); admitted <- err }()
	select {
	case <-waiting:
	case <-ctx.Done():
		close(release)
		t.Fatal("admission did not wait for scope gate")
	}
	select {
	case err := <-admitted:
		close(release)
		t.Fatalf("admission entered held gate: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-admitted; err != nil {
		t.Fatal(err)
	}
}

func TestLocalFullAdmissionFileJournalConflictDoesNotQuarantine(t *testing.T) {
	intent, config, _, store := fullAdmissionFixture(t, "run-file-conflict")
	journal, err := controlplane.NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	admitter, err := NewLocalFullReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("9", 40))
	conflicting, _ := NewLocalFullReviewIntent(intent.Scope(), intent.Repository(), intent.BaseRevision(), otherHead, intent.ReviewPolicyIdentity(), intent.InventoryIdentity(), intent.RuntimePolicyIdentity(), intent.CreatedAt())
	if _, err := admitter.Admit(context.Background(), conflicting, intent.CreatedAt().Add(time.Second)); !errors.Is(err, ErrLocalFullReviewConflict) {
		t.Fatalf("conflict=%v", err)
	}
	if _, err := admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(time.Second)); err != nil {
		t.Fatalf("valid replay quarantined=%v", err)
	}
}

type afterPutFaultStore struct {
	artifact.Store
	fault  error
	failed bool
}

func (s *afterPutFaultStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	stored, err := s.Store.Put(ctx, value, at)
	if err == nil && !s.failed {
		s.failed = true
		return stored, s.fault
	}
	return stored, err
}

func TestLocalFullAdmissionFileJournalPutErrorQuarantinesAfterReopen(t *testing.T) {
	intent, config, _, underlying := fullAdmissionFixture(t, "run-file-put-fault")
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("put returned error after write")
	store := &afterPutFaultStore{Store: underlying, fault: fault}
	admitter, err := NewLocalFullReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(time.Second)); !errors.Is(err, fault) || !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("fault=%v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlplane.NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	fresh, err := NewLocalFullReviewAdmitter(reopened, underlying, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Admit(context.Background(), intent, intent.CreatedAt().Add(time.Second)); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("unsafe retry=%v", err)
	}
}
