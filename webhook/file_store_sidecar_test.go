package webhook

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

// fillFileInbox writes count valid delivery files straight into a file
// inbox root, as earlier accepted deliveries would have left them.
func fillFileInbox(t *testing.T, store *FileStore, count int) []string {
	t.Helper()
	repositoryScope, _ := NewRepositoryScope("tenant-a", "repo-a")
	paths := make([]string, 0, count)
	for index := 0; index < count; index++ {
		id := fmt.Sprintf("filler-%d", index)
		delivery, err := NewVerifiedDelivery(repositoryScope, SourceGitHub, id, "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"id":"`+id+`"}`), time.UnixMilli(1000))
		if err != nil {
			t.Fatal(err)
		}
		stored, err := NewStoredDelivery(delivery, time.UnixMilli(1000))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeStoredDelivery(stored)
		if err != nil {
			t.Fatal(err)
		}
		path := store.deliveryPath(repositoryScope, SourceGitHub, delivery.DeduplicationKey())
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

// Refusal and retry files never take a delivery's place in a full file inbox,
// and a full retry bound is the delivery's own outcome: the supervisor keeps
// recording outcomes and admitting deliveries instead of stopping intake.
func TestFileInboxSidecarsNeverStopIntake(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	journal := failingJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal()}
	f := newRefusalFixture(t, store, supervisorPlanner{identity: strings.Repeat("d", 64)}, &journal)
	clock := &steppingClock{at: time.UnixMilli(1001)}
	f.supervisor.options.Clock = clock
	journal.run = ReviewRunIDForDelivery(f.deliveries[0])
	scope, planner, key := f.deliveries[0].Scope(), strings.Repeat("d", 64), f.deliveries[0].DeduplicationKey()
	// The writer lock and two deliveries are there; fill the rest of the
	// delivery bound with accepted deliveries.
	fillers := fillFileInbox(t, store, maxInboxStoreFiles-3)
	extra, _ := NewVerifiedDelivery(scope, SourceGitHub, "delivery-extra", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"id":"extra"}`), time.UnixMilli(1000))
	if _, _, err := store.Put(ctx, extra, time.UnixMilli(1000)); !errors.Is(err, ErrInboxStoreCapacity) {
		t.Fatalf("a full inbox accepted another delivery: %v", err)
	}
	stored, _, err := store.Get(ctx, scope, SourceGitHub, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.supervisor.handle(ctx, stored); err != nil {
		t.Fatalf("a full inbox stopped intake on a retry: %v", err)
	}
	if retry, retrying, err := store.Retry(ctx, scope, SourceGitHub, key); err != nil || !retrying || retry.Failures() != 1 {
		t.Fatalf("a full inbox did not record the retry: retrying=%t err=%v", retrying, err)
	}
	clock.at = clock.at.Add(maximumSupervisorDelay)
	if err := f.supervisor.handle(ctx, stored); err != nil {
		t.Fatalf("a full inbox stopped intake on a refusal: %v", err)
	}
	if record, refused, err := store.Refusal(ctx, scope, SourceGitHub, key, planner); err != nil || !refused || record.Reason() != RefusalReasonRetriesExhausted {
		t.Fatalf("a full inbox did not record the refusal: refused=%t err=%v", refused, err)
	}
	if err := os.Remove(fillers[0]); err != nil {
		t.Fatal(err)
	}
	if _, created, err := store.Put(ctx, extra, time.UnixMilli(1000)); err != nil || !created {
		t.Fatalf("a refusal file took a delivery's place: %v", err)
	}
	// Retry files the store did not write fill the retry bound.
	for index := 0; index < maxInboxStoreFiles; index++ {
		name := fmt.Sprintf("%s-%s-%064x-%s%s", scope.Identity(), SourceGitHub, index, strings.Repeat("9", 64), retryFileSuffix)
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	journal.run = ReviewRunIDForDelivery(f.deliveries[1])
	other, _, err := store.Get(ctx, scope, SourceGitHub, f.deliveries[1].DeduplicationKey())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.supervisor.handle(ctx, other); err != nil {
		t.Fatalf("a full retry bound stopped intake: %v", err)
	}
	if _, retrying, err := store.Retry(ctx, scope, SourceGitHub, f.deliveries[1].DeduplicationKey()); err != nil || retrying {
		t.Fatalf("a retry file was written past the retry bound: retrying=%t err=%v", retrying, err)
	}
	if _, err := store.List(ctx, scope, SourceGitHub, "", 100); err != nil {
		t.Fatalf("a full retry bound failed listing: %v", err)
	}
}
