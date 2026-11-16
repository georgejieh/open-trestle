package worker

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"testing"
	"time"
)

func TestSupervisorJournalCancellationRetainsIndependentFaults(t *testing.T) {
	fault := errors.New("independent journal fault")
	for _, tc := range []struct {
		name         string
		err          error
		cancelCaller bool
		want         error
	}{
		{"pure", controlplane.ErrRunJournalContextDone, true, nil},
		{"live-caller", controlplane.ErrRunJournalContextDone, false, controlplane.ErrRunJournalContextDone},
		{"joined-persistence", errors.Join(controlplane.ErrRunJournalContextDone, fault), true, fault},
		{"joined-unresolved", errors.Join(controlplane.ErrRunJournalContextDone, controlplane.ErrScopeIntentUnresolved), true, controlplane.ErrScopeIntentUnresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller, cancel := context.WithCancel(context.Background())
			defer cancel()
			journal := &blockingDiscoveryJournal{RunJournal: controlplane.NewMemoryRunJournal(), entered: make(chan struct{}), release: make(chan struct{}), fault: tc.err}
			counter := &planStartCounter{}
			source, build := planHandlers(counter)
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "journal-cancel")
			if err != nil {
				t.Fatal(err)
			}
			supervisor, _ := supervisorFixture(t, journal, []controlplane.TaskHandler{source, build}, twoTaskPlan(t, scope))
			done := make(chan error, 1)
			go func() { done <- supervisor.Run(caller) }()
			select {
			case <-journal.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("discovery did not enter")
			}
			if tc.cancelCaller {
				cancel()
			}
			close(journal.release)
			select {
			case err := <-done:
				if tc.want == nil && err != nil {
					t.Fatalf("pure canceled journal returned failure: %v", err)
				}
				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Fatalf("required failure hidden: %v", err)
				}
				if tc.want != nil && !errors.Is(err, controlplane.ErrRunJournalContextDone) {
					t.Fatalf("journal cancellation leaf hidden: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("supervisor did not exit")
			}
		})
	}
}
