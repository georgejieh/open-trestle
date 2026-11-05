package webhook

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func replayFixture(t *testing.T, deliveryID, eventType, action, payload string) VerifiedDelivery {
	t.Helper()
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := NewVerifiedDelivery(scope, SourceGitHub, deliveryID, eventType, action, strings.Repeat("a", 64), []byte(payload), time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

func TestReplayKeyIgnoresDeliveryIDAndTimeButBindsSignedContent(t *testing.T) {
	base := replayFixture(t, "delivery-1", "pull_request", "opened", `{"n":1}`)
	if base.ReplayKey() != replayFixture(t, "delivery-2", "pull_request", "opened", `{"n":1}`).ReplayKey() {
		t.Fatal("delivery ID changed the replay key")
	}
	for name, other := range map[string]VerifiedDelivery{
		"event":  replayFixture(t, "delivery-1", "push", "opened", `{"n":1}`),
		"action": replayFixture(t, "delivery-1", "pull_request", "synchronize", `{"n":1}`),
		"body":   replayFixture(t, "delivery-1", "pull_request", "opened", `{"n":2}`),
	} {
		if other.ReplayKey() == base.ReplayKey() {
			t.Fatalf("%s did not change the replay key", name)
		}
	}
	otherScope, _ := NewRepositoryScope("tenant-a", "repo-b")
	moved, _ := NewVerifiedDelivery(otherScope, SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"n":1}`), time.UnixMilli(100))
	if moved.ReplayKey() == base.ReplayKey() {
		t.Fatal("scope did not change the replay key")
	}
}

func TestMemoryStoreRefusesSignedBodyReplayUnderNewDeliveryID(t *testing.T) {
	store := NewMemoryStore()
	original := replayFixture(t, "delivery-1", "pull_request", "opened", `{"n":1}`)
	if _, created, err := store.Put(context.Background(), original, time.UnixMilli(200)); err != nil || !created {
		t.Fatalf("original=(%t,%v)", created, err)
	}
	replayed := replayFixture(t, "delivery-2", "pull_request", "opened", `{"n":1}`)
	if got, created, err := store.Put(context.Background(), replayed, time.UnixMilli(300)); !errors.Is(err, ErrDeliveryReplayed) || created || got.Validate() == nil {
		t.Fatalf("replay=(%#v,%t,%v)", got, created, err)
	}
	if _, found, err := store.Get(context.Background(), replayed.Scope(), SourceGitHub, replayed.DeduplicationKey()); err != nil || found {
		t.Fatalf("replay created a delivery: found=%t err=%v", found, err)
	}
	if entries, _ := store.List(context.Background(), original.Scope(), SourceGitHub, "", 10); len(entries) != 1 {
		t.Fatalf("entries=%d", len(entries))
	}
	// Same-ID redelivery stays an idempotent duplicate, and a different event or body is still admitted.
	if _, created, err := store.Put(context.Background(), original, time.UnixMilli(400)); err != nil || created {
		t.Fatalf("redelivery=(%t,%v)", created, err)
	}
	if _, created, err := store.Put(context.Background(), replayFixture(t, "delivery-3", "pull_request", "opened", `{"n":2}`), time.UnixMilli(400)); err != nil || !created {
		t.Fatalf("distinct body=(%t,%v)", created, err)
	}
}

func TestInboxRefusesSignedBodyReplayBeforeCreatingDelivery(t *testing.T) {
	original := replayFixture(t, "delivery-1", "pull_request", "opened", `{"n":1}`)
	policy, _ := NewAdmissionPolicy([]VerifierAuthority{{Scope: original.Scope(), Source: SourceGitHub, VerifierIdentity: strings.Repeat("a", 64)}})
	store := NewMemoryStore()
	inbox, _ := NewInbox(store, policy)
	if _, created, err := inbox.Accept(context.Background(), original, time.UnixMilli(200)); err != nil || !created {
		t.Fatalf("original=(%t,%v)", created, err)
	}
	got, created, err := inbox.Accept(context.Background(), replayFixture(t, "delivery-2", "pull_request", "opened", `{"n":1}`), time.UnixMilli(300))
	if !errors.Is(err, ErrDeliveryReplayed) || created || got.Identity() != "" {
		t.Fatalf("replay=(%#v,%t,%v)", got, created, err)
	}
	if errors.Is(err, ErrDeliveryConflict) {
		t.Fatal("replay must be distinguishable from a same-ID conflict")
	}
}

func TestFileStoreRefusesSignedBodyReplayAcrossRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	original := replayFixture(t, "delivery-1", "pull_request", "opened", `{"n":1}`)
	if _, created, err := store.Put(context.Background(), original, time.UnixMilli(200)); err != nil || !created {
		t.Fatalf("original=(%t,%v)", created, err)
	}
	replayed := replayFixture(t, "delivery-2", "pull_request", "opened", `{"n":1}`)
	if _, created, err := store.Put(context.Background(), replayed, time.UnixMilli(300)); !errors.Is(err, ErrDeliveryReplayed) || created {
		t.Fatalf("same-process replay=(%t,%v)", created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, created, err := reopened.Put(context.Background(), replayed, time.UnixMilli(400)); !errors.Is(err, ErrDeliveryReplayed) || created {
		t.Fatalf("post-restart replay=(%t,%v)", created, err)
	}
	if _, found, err := reopened.Get(context.Background(), replayed.Scope(), SourceGitHub, replayed.DeduplicationKey()); err != nil || found {
		t.Fatalf("replay persisted a delivery: found=%t err=%v", found, err)
	}
	if _, created, err := reopened.Put(context.Background(), original, time.UnixMilli(500)); err != nil || created {
		t.Fatalf("original redelivery=(%t,%v)", created, err)
	}
	if _, created, err := reopened.Put(context.Background(), replayFixture(t, "delivery-3", "pull_request", "opened", `{"n":2}`), time.UnixMilli(600)); err != nil || !created {
		t.Fatalf("distinct body=(%t,%v)", created, err)
	}
	files, _ := os.ReadDir(root)
	deliveries := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), deliveryFileSuffix) {
			deliveries++
		}
	}
	if deliveries != 2 {
		t.Fatalf("deliveries on disk=%d", deliveries)
	}
}

func TestFileStoreFailsClosedWhenPersistedDeliveryCannotBeIndexed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	store, _ := NewFileStore(root)
	original := replayFixture(t, "delivery-1", "pull_request", "opened", `{"n":1}`)
	if _, _, err := store.Put(context.Background(), original, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if err := os.WriteFile(filepath.Join(root, original.Scope().Identity()+"-github-"+strings.Repeat("c", 64)+deliveryFileSuffix), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, _ := NewFileStore(root)
	defer reopened.Close()
	replayed := replayFixture(t, "delivery-2", "pull_request", "opened", `{"n":1}`)
	if _, created, err := reopened.Put(context.Background(), replayed, time.UnixMilli(300)); err == nil || created || errors.Is(err, ErrDeliveryReplayed) {
		t.Fatalf("unindexable store admitted a write: created=%t err=%v", created, err)
	}
}
