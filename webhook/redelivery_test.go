package webhook

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func laterWebhookDelivery(t *testing.T, original VerifiedDelivery) VerifiedDelivery {
	t.Helper()
	delivery, err := NewVerifiedDelivery(original.Scope(), original.Source(), original.DeliveryID(), original.EventType(), original.Action(), original.VerifierIdentity(), original.Payload(), time.UnixMilli(300))
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Identity() == original.Identity() || delivery.DeduplicationKey() != original.DeduplicationKey() {
		t.Fatal("receive time must change observation identity, not deduplication key")
	}
	return delivery
}

func redeliveryStore(t *testing.T, backend string) Store {
	t.Helper()
	if backend == "memory" {
		return NewMemoryStore()
	}
	store, err := NewFileStore(filepath.Join(t.TempDir(), "inbox"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStoreRedeliveryPreservesOriginalObservation(t *testing.T) {
	for _, backend := range []string{"memory", "file"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			store := redeliveryStore(t, backend)
			original := inboxFixture(t, `{"action":"opened"}`)
			first, created, err := store.Put(ctx, original, time.UnixMilli(200))
			if err != nil || !created {
				t.Fatalf("first=(%t,%v)", created, err)
			}
			encoded, err := EncodeStoredDelivery(first)
			if err != nil {
				t.Fatal(err)
			}
			if original.Identity() != "2864d29db9ca6f1ba8c5bd45fd57fc25c934ccbf70f59a0d73933035c31d2589" || first.Receipt().Identity() != "5a58ae5c7b6ceaa62f61bc3dcb1bda53ad947ee4d21d1ec3a420d6f813cadd44" {
				t.Fatal("version-one persisted delivery or receipt identity changed")
			}
			var path string
			if fileStore, ok := store.(*FileStore); ok {
				path = fileStore.deliveryPath(original.Scope(), original.Source(), original.DeduplicationKey())
				if err := fileStore.Close(); err != nil {
					t.Fatal(err)
				}
				reopened, err := NewFileStore(fileStore.root)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = reopened.Close() })
				store = reopened
			}
			later := laterWebhookDelivery(t, original)
			duplicate, created, err := store.Put(ctx, later, time.UnixMilli(400))
			if err != nil || created {
				t.Fatalf("redelivery=(%t,%v)", created, err)
			}
			got, err := EncodeStoredDelivery(duplicate)
			if err != nil || !bytes.Equal(got, encoded) {
				t.Fatalf("redelivery replaced original observation or receipt: %v", err)
			}
			loaded, found, err := store.Get(ctx, original.Scope(), original.Source(), original.DeduplicationKey())
			if err != nil || !found || loaded.Delivery().Identity() != original.Identity() || loaded.Receipt().Identity() != first.Receipt().Identity() {
				t.Fatalf("get=(%t,%v)", found, err)
			}
			entries, err := store.List(ctx, original.Scope(), original.Source(), "", 10)
			if err != nil || len(entries) != 1 || entries[0].Delivery().Identity() != original.Identity() {
				t.Fatalf("list=(%d,%v)", len(entries), err)
			}
			if path != "" {
				onDisk, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(onDisk, encoded) {
					t.Fatalf("persisted record was rewritten: %v", err)
				}
			}
		})
	}
}

func TestStoreRedeliveryStillBindsContentAndAuthority(t *testing.T) {
	for _, backend := range []string{"memory", "file"} {
		for _, field := range []string{"body", "event", "action", "verifier"} {
			t.Run(backend+"/"+field, func(t *testing.T) {
				store := redeliveryStore(t, backend)
				original := inboxFixture(t, `{"action":"opened"}`)
				first, _, err := store.Put(context.Background(), original, time.UnixMilli(200))
				if err != nil {
					t.Fatal(err)
				}
				changed := changedWebhookDelivery(t, original, field)
				got, created, err := store.Put(context.Background(), changed, time.UnixMilli(400))
				if !errors.Is(err, ErrDeliveryConflict) || created || got.Validate() == nil {
					t.Fatalf("changed %s=(%t,%v)", field, created, err)
				}
				loaded, found, err := store.Get(context.Background(), original.Scope(), original.Source(), original.DeduplicationKey())
				if err != nil || !found || loaded.Receipt().Identity() != first.Receipt().Identity() {
					t.Fatal("conflict changed original receipt")
				}
			})
		}
	}
}

func changedWebhookDelivery(t *testing.T, original VerifiedDelivery, field string) VerifiedDelivery {
	t.Helper()
	scope, source, id := original.Scope(), original.Source(), original.DeliveryID()
	event, action, verifier, payload := original.EventType(), original.Action(), original.VerifierIdentity(), original.Payload()
	switch field {
	case "tenant":
		scope, _ = NewRepositoryScope("tenant-b", scope.RepositoryID())
	case "repository":
		scope, _ = NewRepositoryScope(scope.TenantID(), "repo-b")
	case "source":
		source = SourceGitLab
	case "delivery-id":
		id = "delivery-2"
	case "event":
		event = "issues"
	case "action":
		action = "closed"
	case "verifier":
		verifier = strings.Repeat("b", 64)
	case "body":
		payload = []byte(`{"action":"opened","number":2}`)
	}
	delivery, err := NewVerifiedDelivery(scope, source, id, event, action, verifier, payload, time.UnixMilli(300))
	if err != nil {
		t.Fatal(err)
	}
	return delivery
}

type redeliveryResultStore struct {
	Store
	stored  StoredDelivery
	created bool
	calls   int
}

func (s *redeliveryResultStore) Put(context.Context, VerifiedDelivery, time.Time) (StoredDelivery, bool, error) {
	s.calls++
	return s.stored, s.created, nil
}

func TestInboxRedeliveryValidatesOriginalReceiptAgainstStableContent(t *testing.T) {
	original := inboxFixture(t, `{"action":"opened"}`)
	policy, err := NewAdmissionPolicy([]VerifierAuthority{{Scope: original.Scope(), Source: original.Source(), VerifierIdentity: original.VerifierIdentity()}})
	if err != nil {
		t.Fatal(err)
	}
	later := laterWebhookDelivery(t, original)
	for _, field := range []string{"receive-time", "tenant", "repository", "source", "delivery-id", "event", "action", "verifier", "body", "created"} {
		t.Run(field, func(t *testing.T) {
			returned := original
			if field != "receive-time" && field != "created" {
				returned = changedWebhookDelivery(t, original, field)
			}
			stored, err := NewStoredDelivery(returned, returned.ReceivedAt().Add(time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			store := &redeliveryResultStore{stored: stored, created: field == "created"}
			inbox, err := NewInbox(store, policy)
			if err != nil {
				t.Fatal(err)
			}
			receipt, created, err := inbox.Accept(context.Background(), later, time.UnixMilli(400))
			if field == "receive-time" {
				if err != nil || created || receipt.Identity() != stored.Receipt().Identity() || receipt.DeliveryIdentity() != original.Identity() {
					t.Fatalf("duplicate receipt=(%t,%v)", created, err)
				}
			} else if !errors.Is(err, ErrInvalidAcceptanceReceipt) || created || receipt.Identity() != "" {
				t.Fatalf("unrelated %s receipt=(%t,%v)", field, created, err)
			}
		})
	}
	stored, err := NewStoredDelivery(original, time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	store := &redeliveryResultStore{stored: stored}
	inbox, err := NewInbox(store, policy)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := changedWebhookDelivery(t, original, "verifier")
	if _, _, err := inbox.Accept(context.Background(), unauthorized, time.UnixMilli(400)); !errors.Is(err, ErrVerifierNotAuthorized) || store.calls != 0 {
		t.Fatalf("unauthorized retry reached store: calls=%d err=%v", store.calls, err)
	}
}

func TestVerifiedDeliverySameContentRequiresValidObservations(t *testing.T) {
	original := inboxFixture(t, `{"action":"opened"}`)
	later := laterWebhookDelivery(t, original)
	if !original.SameContent(later) || !later.SameContent(original) || !original.SameContent(original) {
		t.Fatal("valid observations of unchanged content are not equivalent")
	}
	for _, field := range []string{"tenant", "repository", "source", "delivery-id", "event", "action", "verifier", "body"} {
		t.Run(field, func(t *testing.T) {
			changed := changedWebhookDelivery(t, original, field)
			if original.SameContent(changed) || changed.SameContent(original) {
				t.Fatalf("equivalence omitted %s", field)
			}
		})
	}
	for _, field := range []string{"zero", "identity", "key", "digest", "payload", "time", "scope"} {
		t.Run("invalid-"+field, func(t *testing.T) {
			invalid := original
			switch field {
			case "zero":
				invalid = VerifiedDelivery{}
			case "identity":
				invalid.identity = strings.Repeat("b", 64)
			case "key":
				invalid.deduplicationKey = strings.Repeat("b", 64)
			case "digest":
				invalid.bodyDigest = strings.Repeat("b", 64)
			case "payload":
				invalid.payload = []byte(`{"action":"closed"}`)
			case "time":
				invalid.receivedAtMillis = 0
			case "scope":
				invalid.scope.identity = strings.Repeat("b", 64)
			}
			if invalid.Validate() == nil {
				t.Fatal("fixture must be invalid")
			}
			if original.SameContent(invalid) || invalid.SameContent(original) || invalid.SameContent(invalid) {
				t.Fatalf("equivalence accepted invalid %s", field)
			}
		})
	}
}
