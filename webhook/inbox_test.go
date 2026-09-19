package webhook

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func inboxFixture(t *testing.T, payload string) VerifiedDelivery {
	t.Helper()
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(payload), time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}
func TestInboxAdmitsAuthorizedDeliveryAndDeduplicates(t *testing.T) {
	delivery := inboxFixture(t, `{"action":"opened"}`)
	policy, err := NewAdmissionPolicy([]VerifierAuthority{{Scope: delivery.Scope(), Source: SourceGitHub, VerifierIdentity: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := NewInbox(NewMemoryStore(), policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt, created, err := inbox.Accept(context.Background(), delivery, time.UnixMilli(200))
	if err != nil || !created || receipt.DeliveryIdentity() != delivery.Identity() || receipt.Validate() != nil {
		t.Fatalf("accept=(%#v,%t,%v)", receipt, created, err)
	}
	duplicate, created, err := inbox.Accept(context.Background(), delivery, time.UnixMilli(300))
	if err != nil || created || duplicate.Identity() != receipt.Identity() {
		t.Fatalf("duplicate=(%#v,%t,%v)", duplicate, created, err)
	}
	changed := inboxFixture(t, `{"action":"opened","number":2}`)
	if got, created, err := inbox.Accept(context.Background(), changed, time.UnixMilli(300)); !errors.Is(err, ErrDeliveryConflict) || created || got.Identity() != "" {
		t.Fatalf("conflict=(%#v,%t,%v)", got, created, err)
	}
}
func TestInboxRejectsUnapprovedVerifierBeforePersistence(t *testing.T) {
	delivery := inboxFixture(t, `{}`)
	policy, _ := NewAdmissionPolicy([]VerifierAuthority{{Scope: delivery.Scope(), Source: SourceGitHub, VerifierIdentity: strings.Repeat("b", 64)}})
	store := NewMemoryStore()
	inbox, _ := NewInbox(store, policy)
	if got, created, err := inbox.Accept(context.Background(), delivery, time.UnixMilli(200)); !errors.Is(err, ErrVerifierNotAuthorized) || created || got.Identity() != "" {
		t.Fatalf("accept=(%#v,%t,%v)", got, created, err)
	}
	if entries, err := store.List(context.Background(), delivery.Scope(), SourceGitHub, "", 10); err != nil || len(entries) != 0 {
		t.Fatalf("entries=(%#v,%v)", entries, err)
	}
}
func TestMemoryStoreSerializesConcurrentDeduplication(t *testing.T) {
	delivery := inboxFixture(t, `{}`)
	policy, _ := NewAdmissionPolicy([]VerifierAuthority{{Scope: delivery.Scope(), Source: SourceGitHub, VerifierIdentity: strings.Repeat("a", 64)}})
	inbox, _ := NewInbox(NewMemoryStore(), policy)
	var created atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, wasCreated, err := inbox.Accept(context.Background(), delivery, time.UnixMilli(200))
			if err != nil {
				failures.Add(1)
			}
			if wasCreated {
				created.Add(1)
			}
		}()
	}
	wait.Wait()
	if created.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("created=%d failures=%d", created.Load(), failures.Load())
	}
}
