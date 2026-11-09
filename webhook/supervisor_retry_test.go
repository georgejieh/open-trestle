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

type steppingClock struct{ at time.Time }

func (c *steppingClock) Now() time.Time { return c.at }

// outageJournal fails every operation while down, like an unavailable journal.
type outageJournal struct {
	*controlplane.MemoryRunJournal
	down bool
}

var errJournalDown = errors.New("journal down")

func (j *outageJournal) SavePlan(ctx context.Context, plan controlplane.ReviewRunPlan) error {
	if j.down {
		return errJournalDown
	}
	return j.MemoryRunJournal.SavePlan(ctx, plan)
}
func (j *outageJournal) LoadPlan(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunPlan, bool, error) {
	if j.down {
		return controlplane.ReviewRunPlan{}, false, errJournalDown
	}
	return j.MemoryRunJournal.LoadPlan(ctx, scope)
}
func (j *outageJournal) Head(ctx context.Context, scope audit.ReviewScope) (controlplane.RunEvent, bool, error) {
	if j.down {
		return controlplane.RunEvent{}, false, errJournalDown
	}
	return j.MemoryRunJournal.Head(ctx, scope)
}

func retryFixture(t *testing.T, journal controlplane.RunJournal) (refusalFixture, *steppingClock) {
	t.Helper()
	f := newRefusalFixture(t, NewMemoryStore(), supervisorPlanner{identity: strings.Repeat("d", 64)}, journal)
	clock := &steppingClock{at: time.UnixMilli(1001)}
	f.supervisor.options.Clock = clock
	return f, clock
}

// One delivery that keeps failing while the journal is healthy backs off on
// its own, never fails the pass or stops intake, and is recorded as refused
// with retries_exhausted once its bounded attempts are spent.
func TestSupervisorGivesEachDeliveryItsOwnBoundedRetries(t *testing.T) {
	ctx := context.Background()
	journal := failingJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal()}
	f, clock := retryFixture(t, &journal)
	journal.run = ReviewRunIDForDelivery(f.deliveries[0])
	refusal := func() (RefusalRecord, bool) {
		record, found, err := f.store.Refusal(ctx, f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64))
		if err != nil {
			t.Fatal(err)
		}
		return record, found
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatalf("one delivery's failure failed the pass: %v", err)
	}
	if !f.admitted(t, f.deliveries[1]) {
		t.Fatal("the failing delivery blocked the other one")
	}
	if _, found := refusal(); found {
		t.Fatal("first failure was recorded as a refusal")
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if retry := f.supervisor.retries[f.deliveries[0].DeduplicationKey()]; retry == nil || retry.failures != 1 {
		t.Fatal("a delivery inside its backoff was retried early")
	}
	for attempt := 2; attempt <= int(f.supervisor.options.MaximumRetries); attempt++ {
		clock.at = clock.at.Add(maximumSupervisorDelay)
		if err := f.supervisor.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record, found := refusal()
	if !found || record.Reason() != RefusalReasonRetriesExhausted || f.supervisor.retries[f.deliveries[0].DeduplicationKey()] != nil {
		t.Fatalf("exhausted delivery recorded=%t reason=%s", found, record.Reason())
	}
}

// A journal outage is global: it fails the pass for supervisor-level retry and
// is never counted against, or recorded as a refusal of, any delivery.
func TestSupervisorTreatsAJournalOutageAsGlobal(t *testing.T) {
	ctx := context.Background()
	journal := &outageJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal(), down: true}
	f, clock := retryFixture(t, journal)
	for pass := 0; pass < 2*int(f.supervisor.options.MaximumRetries); pass++ {
		if err := f.supervisor.reconcile(ctx); err == nil {
			t.Fatal("an outage did not fail the pass")
		}
		clock.at = clock.at.Add(maximumSupervisorDelay)
	}
	for _, delivery := range f.deliveries {
		if _, found, _ := f.store.Refusal(ctx, delivery.Scope(), SourceGitHub, delivery.DeduplicationKey(), strings.Repeat("d", 64)); found || f.supervisor.retries[delivery.DeduplicationKey()] != nil {
			t.Fatal("an outage was counted against a delivery")
		}
	}
	journal.down = false
	if err := f.supervisor.reconcile(ctx); err != nil || !f.admitted(t, f.deliveries[0]) || !f.admitted(t, f.deliveries[1]) {
		t.Fatalf("deliveries not admitted after recovery: %v", err)
	}
}
