package webhook

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

// retryFiles counts the retry files in a file inbox root.
func retryFiles(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), retryFileSuffix) {
			count++
		}
	}
	return count
}

// Retry state a superseded planner identity recorded neither holds a delivery
// back nor counts against it, and is pruned once the current planner admits
// or refuses the delivery, so it never accumulates in the inbox.
func TestSupervisorPrunesSupersededRetryState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	files, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	t.Run("file", func(t *testing.T) {
		testSupervisorPrunesSupersededRetryState(t, files, func() int { return retryFiles(t, root) })
	})
	t.Run("memory", func(t *testing.T) {
		testSupervisorPrunesSupersededRetryState(t, NewMemoryStore(), nil)
	})
}

func testSupervisorPrunesSupersededRetryState(t *testing.T, store interface {
	Store
	RefusalStore
	RetryStore
}, files func() int) {
	ctx := context.Background()
	f := newRefusalFixture(t, store, refusingPlanner{}, controlplane.NewMemoryRunJournal())
	retained := func() int {
		count := 0
		for _, delivery := range f.deliveries {
			if _, found, err := store.Retry(ctx, delivery.Scope(), SourceGitHub, delivery.DeduplicationKey()); err != nil {
				t.Fatal(err)
			} else if found {
				count++
			}
		}
		if files != nil && files() != count {
			t.Fatalf("retry files=%d readable records=%d", files(), count)
		}
		return count
	}
	f.supervisor.processor.planner = refusingPlanner{refused: f.deliveries[1].DeduplicationKey(), err: errors.New("invalid payload")}
	superseded := strings.Repeat("9", 64)
	for _, delivery := range f.deliveries {
		stored, _, err := store.Get(ctx, delivery.Scope(), SourceGitHub, delivery.DeduplicationKey())
		if err != nil {
			t.Fatal(err)
		}
		record, err := NewRetryRecord(stored, superseded, 3, time.UnixMilli(1001).Add(maximumSupervisorDelay))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.RecordRetry(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if count := retained(); count != 2 {
		t.Fatalf("fixture retry state=%d", count)
	}
	if retry, _, _ := store.Retry(ctx, f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey()); retry.PlannerIdentity() != superseded {
		t.Fatal("retry state lost the planner that recorded it")
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.admitted(t, f.deliveries[0]) {
		t.Fatal("superseded retry state held the delivery back")
	}
	if record, refused, err := store.Refusal(ctx, f.deliveries[1].Scope(), SourceGitHub, f.deliveries[1].DeduplicationKey(), strings.Repeat("d", 64)); err != nil || !refused || record.Reason() != RefusalReasonPlanningRefused {
		t.Fatalf("refusal=(%t,%v)", refused, err)
	}
	if count := retained(); count != 0 {
		t.Fatalf("superseded retry state outlived admission or refusal: %d records", count)
	}
}

// A failure under the current planner starts its own count: retry state a
// superseded planner left is replaced, not continued toward exhaustion.
func TestSupervisorDoesNotCountSupersededFailures(t *testing.T) {
	ctx := context.Background()
	journal := failingJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal()}
	f, _ := retryFixture(t, &journal)
	journal.run = ReviewRunIDForDelivery(f.deliveries[0])
	scope, key := f.deliveries[0].Scope(), f.deliveries[0].DeduplicationKey()
	stored, _, err := f.store.Get(ctx, scope, SourceGitHub, key)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := NewRetryRecord(stored, strings.Repeat("9", 64), f.supervisor.options.MaximumRetries-1, time.UnixMilli(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.supervisor.retries.RecordRetry(ctx, previous); err != nil {
		t.Fatal(err)
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, refused, _ := f.store.Refusal(ctx, scope, SourceGitHub, key, strings.Repeat("d", 64)); refused {
		t.Fatal("superseded failures exhausted the current planner's retries")
	}
	if retry, found, _ := f.supervisor.retries.Retry(ctx, scope, SourceGitHub, key); !found || retry.PlannerIdentity() != strings.Repeat("d", 64) || retry.Failures() != 1 {
		t.Fatalf("current retry state found=%t failures=%d", found, retry.Failures())
	}
}
