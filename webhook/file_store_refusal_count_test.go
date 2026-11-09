package webhook

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
)

// Refusal records are audit records and are kept, so each planner identity's
// records are counted on their own, at most one per delivery: records that
// superseded planner identities left never keep the current planner from
// recording its refusal, and never make the inbox unreadable.
func TestFileInboxCountsRefusalRecordsPerPlanner(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	f := newRefusalFixture(t, store, refusingPlanner{}, controlplane.NewMemoryRunJournal())
	f.supervisor.processor.planner = refusingPlanner{refused: f.deliveries[0].DeduplicationKey(), err: errors.New("invalid payload")}
	scope := f.deliveries[0].Scope()
	// Three generations of superseded planners each refused every delivery
	// of a full inbox.
	for generation := 0; generation < 3; generation++ {
		planner := strings.Repeat(fmt.Sprint(generation+6), 64)
		for index := 0; index < maxInboxStoreFiles; index++ {
			name := fmt.Sprintf("%s-%s-%064x-%s%s", scope.Identity(), SourceGitHub, index, planner, refusalFileSuffix)
			if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatalf("superseded refusal records stopped intake: %v", err)
	}
	record, refused, err := store.Refusal(ctx, scope, SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64))
	if err != nil || !refused || record.Reason() != RefusalReasonPlanningRefused {
		t.Fatalf("superseded refusal records kept the current refusal out: refused=%t err=%v", refused, err)
	}
	if !f.admitted(t, f.deliveries[1]) {
		t.Fatal("superseded refusal records blocked the other delivery")
	}
}
