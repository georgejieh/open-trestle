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
)

// A file inbox holds at most one refusal record per delivery, so refusal
// records are bounded in total like deliveries: a root already holding that
// many refusal files the store did not write refuses another refusal, and
// listing still reads it.
func TestFileInboxBoundsRefusalRecordsInTotal(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	scope, _ := NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := NewVerifiedDelivery(scope, SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"id":"delivery-1"}`), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	stored, _, err := store.Put(ctx, delivery, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxInboxStoreFiles; index++ {
		name := fmt.Sprintf("%s-%s-%064x%s", scope.Identity(), SourceGitHub, index, refusalFileSuffix)
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	record, err := NewRefusalRecord(stored, strings.Repeat("d", 64), RefusalReasonPlanningRefused, time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordRefusal(ctx, record); !errors.Is(err, ErrInboxStoreCapacity) {
		t.Fatalf("a refusal was recorded past the refusal bound: %v", err)
	}
	if listed, err := store.List(ctx, scope, SourceGitHub, "", 100); err != nil || len(listed) != 1 {
		t.Fatalf("refusal files made the inbox unreadable: %d %v", len(listed), err)
	}
}
