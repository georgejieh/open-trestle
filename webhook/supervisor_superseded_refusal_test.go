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

// refusalFiles counts the refusal records in a file inbox root.
func refusalFiles(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), refusalFileSuffix) {
			count++
		}
	}
	return count
}

// A refusal a superseded planner identity recorded is kept until the current
// planner has its own outcome for the delivery: it is pruned once the delivery
// is admitted and replaced once the current planner refuses it, so the inbox
// holds at most one refusal record per delivery.
func TestSupervisorPrunesSupersededRefusals(t *testing.T) {
	root := filepath.Join(t.TempDir(), "inbox")
	files, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	t.Run("file", func(t *testing.T) {
		testSupervisorPrunesSupersededRefusals(t, files, func() int { return refusalFiles(t, root) })
	})
	t.Run("memory", func(t *testing.T) {
		testSupervisorPrunesSupersededRefusals(t, NewMemoryStore(), nil)
	})
}

func testSupervisorPrunesSupersededRefusals(t *testing.T, store interface {
	Store
	RefusalStore
	RetryStore
}, files func() int) {
	ctx := context.Background()
	f := newRefusalFixture(t, store, refusingPlanner{}, controlplane.NewMemoryRunJournal())
	f.supervisor.processor.planner = refusingPlanner{refused: f.deliveries[1].DeduplicationKey(), err: errors.New("invalid payload")}
	superseded, current := strings.Repeat("9", 64), strings.Repeat("d", 64)
	for _, delivery := range f.deliveries {
		stored, _, err := store.Get(ctx, delivery.Scope(), SourceGitHub, delivery.DeduplicationKey())
		if err != nil {
			t.Fatal(err)
		}
		record, err := NewRefusalRecord(stored, superseded, RefusalReasonPlanningRefused, time.UnixMilli(1001))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.RecordRefusal(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.admitted(t, f.deliveries[0]) || f.admitted(t, f.deliveries[1]) {
		t.Fatal("a superseded refusal decided the current planner's outcome")
	}
	if record, refused, err := store.Refusal(ctx, f.deliveries[1].Scope(), SourceGitHub, f.deliveries[1].DeduplicationKey(), current); err != nil || !refused || record.PlannerIdentity() != current {
		t.Fatalf("the current refusal was not recorded: refused=%t err=%v", refused, err)
	}
	if _, found, err := store.RecordedRefusal(ctx, f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey()); err != nil || found {
		t.Fatalf("the admitted delivery kept its superseded refusal: found=%t err=%v", found, err)
	}
	if files != nil && files() != 1 {
		t.Fatalf("superseded refusals were not pruned: %d refusal records", files())
	}
}
