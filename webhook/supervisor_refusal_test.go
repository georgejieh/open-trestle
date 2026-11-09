package webhook

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// refusingPlanner refuses one delivery every time and plans the others.
type refusingPlanner struct {
	refused string
	err     error
}

func (p refusingPlanner) Identity() string { return strings.Repeat("d", 64) }
func (p refusingPlanner) Plan(ctx context.Context, stored StoredDelivery) (controlplane.ReviewRunPlan, error) {
	if stored.Delivery().DeduplicationKey() == p.refused {
		return controlplane.ReviewRunPlan{}, p.err
	}
	return supervisorPlanner{identity: p.Identity()}.Plan(ctx, stored)
}

// failingJournal fails every write for one review run, like an unavailable store.
type failingJournal struct {
	*controlplane.MemoryRunJournal
	run string
}

func (j failingJournal) SavePlan(ctx context.Context, plan controlplane.ReviewRunPlan) error {
	if plan.Scope().ReviewRunID() == j.run {
		return errors.New("journal unavailable")
	}
	return j.MemoryRunJournal.SavePlan(ctx, plan)
}

type refusalFixture struct {
	store interface {
		Store
		RefusalStore
	}
	deliveries  []VerifiedDelivery
	coordinator *controlplane.Coordinator
	supervisor  *Supervisor
}

func newRefusalFixture(t *testing.T, store interface {
	Store
	RefusalStore
}, planner RunPlanner, journal controlplane.RunJournal) refusalFixture {
	t.Helper()
	repositoryScope, _ := NewRepositoryScope("tenant-a", "repo-a")
	f := refusalFixture{store: store}
	for _, id := range []string{"delivery-1", "delivery-2"} {
		delivery, err := NewVerifiedDelivery(repositoryScope, SourceGitHub, id, "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"id":"`+id+`"}`), time.UnixMilli(1000))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.Put(context.Background(), delivery, time.UnixMilli(1000)); err != nil {
			t.Fatal(err)
		}
		f.deliveries = append(f.deliveries, delivery)
	}
	f.coordinator, _ = controlplane.NewCoordinator(journal)
	processor, err := NewProcessor(f.coordinator, planner)
	if err != nil {
		t.Fatal(err)
	}
	f.supervisor, err = NewSupervisor(store, processor, repositoryScope, SourceGitHub, SupervisorOptions{QueueCapacity: 4, MaximumRetries: 2, RetryDelay: 10 * time.Millisecond, Clock: supervisorClock{at: time.UnixMilli(1001)}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f refusalFixture) admitted(t *testing.T, delivery VerifiedDelivery) bool {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", ReviewRunIDForDelivery(delivery))
	_, _, err := f.coordinator.Resume(context.Background(), scope)
	return err == nil
}

// A delivery whose planning always fails must not stop intake of the others:
// it is recorded once as refused, with its reason, and skipped.
func TestSupervisorKeepsIntakeAfterADeterministicRefusal(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		err          error
	}{
		{"unnamed planning error", RefusalReasonPlanningRefused, errors.New("invalid payload")},
		{"planner-named reason", "invalid_payload", NewDeliveryRefusal("invalid_payload", "invalid pull request payload")},
	} {
		t.Run(c.name, func(t *testing.T) {
			store := NewMemoryStore()
			f := newRefusalFixture(t, store, refusingPlanner{refused: "", err: c.err}, controlplane.NewMemoryRunJournal())
			f.supervisor.processor.planner = refusingPlanner{refused: f.deliveries[0].DeduplicationKey(), err: c.err}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- f.supervisor.Run(ctx) }()
			select {
			case <-f.supervisor.Ready():
			case err := <-done:
				t.Fatalf("supervisor stopped before intake: %v", err)
			case <-time.After(2 * time.Second):
				t.Fatal("supervisor not ready")
			}
			if !f.admitted(t, f.deliveries[1]) || f.admitted(t, f.deliveries[0]) {
				t.Fatal("refusal blocked the other delivery or admitted the refused one")
			}
			record, found, err := store.Refusal(context.Background(), f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64))
			if err != nil || !found || record.Reason() != c.reason || record.DeliveryIdentity() != f.deliveries[0].Identity() {
				t.Fatalf("refusal record=(%v,%t,%v)", record.Reason(), found, err)
			}
			if err := f.supervisor.reconcile(context.Background()); err != nil {
				t.Fatalf("a recorded refusal failed the next pass: %v", err)
			}
			again, _, _ := store.Refusal(context.Background(), f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64))
			if again.Identity() != record.Identity() {
				t.Fatal("reprocessing rewrote the refusal record")
			}
		})
	}
}

// A transient failure of one delivery is retried after its own backoff, is
// not recorded as a refusal, and does not keep the other delivery from being
// admitted in the same pass.
func TestSupervisorRetriesTransientFailuresWithoutRefusing(t *testing.T) {
	store := NewMemoryStore()
	journal := failingJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal()}
	f := newRefusalFixture(t, store, supervisorPlanner{identity: strings.Repeat("d", 64)}, &journal)
	clock := &steppingClock{at: time.UnixMilli(1001)}
	f.supervisor.options.Clock = clock
	journal.run = ReviewRunIDForDelivery(f.deliveries[0])
	if err := f.supervisor.reconcile(context.Background()); err != nil {
		t.Fatalf("one delivery's transient failure failed the pass: %v", err)
	}
	if !f.admitted(t, f.deliveries[1]) {
		t.Fatal("transient failure blocked the other delivery")
	}
	if _, found, _ := store.Refusal(context.Background(), f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64)); found {
		t.Fatal("transient failure was recorded as a refusal")
	}
	journal.run = ""
	clock.at = clock.at.Add(maximumSupervisorDelay)
	if err := f.supervisor.reconcile(context.Background()); err != nil || !f.admitted(t, f.deliveries[0]) {
		t.Fatalf("retry did not admit the delivery: %v", err)
	}
}
