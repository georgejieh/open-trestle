package webhook

import (
	"context"
	"errors"
	"path/filepath"
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
	if retry, found, _ := f.supervisor.retries.Retry(ctx, f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64)); !found || retry.Failures() != 1 {
		t.Fatal("a delivery inside its backoff was retried early")
	}
	for attempt := 2; attempt <= int(f.supervisor.options.MaximumRetries); attempt++ {
		clock.at = clock.at.Add(maximumSupervisorDelay)
		if err := f.supervisor.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record, found := refusal()
	_, retrying, _ := f.supervisor.retries.Retry(ctx, f.deliveries[0].Scope(), SourceGitHub, f.deliveries[0].DeduplicationKey(), strings.Repeat("d", 64))
	if !found || record.Reason() != RefusalReasonRetriesExhausted || retrying {
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
		_, retrying, _ := f.supervisor.retries.Retry(ctx, delivery.Scope(), SourceGitHub, delivery.DeduplicationKey(), strings.Repeat("d", 64))
		if _, found, _ := f.store.Refusal(ctx, delivery.Scope(), SourceGitHub, delivery.DeduplicationKey(), strings.Repeat("d", 64)); found || retrying {
			t.Fatal("an outage was counted against a delivery")
		}
	}
	journal.down = false
	if err := f.supervisor.reconcile(ctx); err != nil || !f.admitted(t, f.deliveries[0]) || !f.admitted(t, f.deliveries[1]) {
		t.Fatalf("deliveries not admitted after recovery: %v", err)
	}
}

// A delivery's own retry count and next-attempt time live in the inbox, so a
// restart neither resets the bound nor retries the delivery early or forever.
func TestSupervisorRetryStateSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "inbox")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	journal := failingJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal()}
	f := newRefusalFixture(t, store, supervisorPlanner{identity: strings.Repeat("d", 64)}, &journal)
	clock := &steppingClock{at: time.UnixMilli(1001)}
	f.supervisor.options.Clock = clock
	journal.run = ReviewRunIDForDelivery(f.deliveries[0])
	planner, key := strings.Repeat("d", 64), f.deliveries[0].DeduplicationKey()
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retry, found, err := reopened.Retry(ctx, f.deliveries[0].Scope(), SourceGitHub, key, planner)
	if err != nil || !found || retry.Failures() != 1 || !retry.NotBefore().After(clock.at) {
		t.Fatalf("retry state did not survive the restart: found=%t failures=%d err=%v", found, retry.Failures(), err)
	}
	encoded, err := EncodeRetryRecord(retry)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseRetryRecord(encoded); err != nil || parsed != retry {
		t.Fatalf("retry readback: %v", err)
	}
	for _, forged := range []string{strings.Replace(string(encoded), `"schema_version":1`, `"schema_version":2`, 1), strings.Replace(string(encoded), `"failures":1`, `"failures":0`, 1)} {
		if _, err := ParseRetryRecord([]byte(forged)); err == nil {
			t.Fatal("retry record accepted a forged version or count")
		}
	}
	restarted, err := NewSupervisor(reopened, f.supervisor.processor, f.deliveries[0].Scope(), SourceGitHub, SupervisorOptions{QueueCapacity: 4, MaximumRetries: f.supervisor.options.MaximumRetries, RetryDelay: f.supervisor.options.RetryDelay, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := reopened.Retry(ctx, f.deliveries[0].Scope(), SourceGitHub, key, planner); again.Failures() != 1 {
		t.Fatal("the restarted supervisor retried inside the recorded backoff")
	}
	for attempt := 2; attempt <= int(restarted.options.MaximumRetries); attempt++ {
		clock.at = clock.at.Add(maximumSupervisorDelay)
		if err := restarted.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	record, refused, err := reopened.Refusal(ctx, f.deliveries[0].Scope(), SourceGitHub, key, planner)
	if err != nil || !refused || record.Reason() != RefusalReasonRetriesExhausted {
		t.Fatalf("bound did not hold across the restart: refused=%t err=%v", refused, err)
	}
	if _, found, _ := reopened.Retry(ctx, f.deliveries[0].Scope(), SourceGitHub, key, planner); found {
		t.Fatal("retry state outlived the refusal")
	}
}

// A refusal is terminal for its delivery and planner: once a delivery's
// retries are exhausted, later passes start no new retry cycle, clear retry
// state a crash left beside the refusal, and never open the delivery's run
// after the failure clears.
func TestSupervisorTreatsARecordedRefusalAsTerminal(t *testing.T) {
	ctx := context.Background()
	journal := failingJournal{MemoryRunJournal: controlplane.NewMemoryRunJournal()}
	f, clock := retryFixture(t, &journal)
	journal.run = ReviewRunIDForDelivery(f.deliveries[0])
	scope, planner, key := f.deliveries[0].Scope(), strings.Repeat("d", 64), f.deliveries[0].DeduplicationKey()
	for attempt := 1; attempt <= int(f.supervisor.options.MaximumRetries); attempt++ {
		if err := f.supervisor.reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		clock.at = clock.at.Add(maximumSupervisorDelay)
	}
	first, refused, err := f.store.Refusal(ctx, scope, SourceGitHub, key, planner)
	if err != nil || !refused || first.Reason() != RefusalReasonRetriesExhausted {
		t.Fatalf("retries were not exhausted: refused=%t err=%v", refused, err)
	}
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if retry, retrying, _ := f.supervisor.retries.Retry(ctx, scope, SourceGitHub, key, planner); retrying {
		t.Fatalf("a refused delivery started a new retry cycle: failures=%d", retry.Failures())
	}
	stored, _, err := f.store.Get(ctx, scope, SourceGitHub, key)
	if err != nil {
		t.Fatal(err)
	}
	lingering, err := NewRetryRecord(stored, planner, 1, clock.at)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.supervisor.retries.RecordRetry(ctx, lingering); err != nil {
		t.Fatal(err)
	}
	journal.run = ""
	clock.at = clock.at.Add(maximumSupervisorDelay)
	if err := f.supervisor.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if f.admitted(t, f.deliveries[0]) {
		t.Fatal("a run was opened for a refused delivery")
	}
	if _, retrying, _ := f.supervisor.retries.Retry(ctx, scope, SourceGitHub, key, planner); retrying {
		t.Fatal("retry state left beside a refusal was kept")
	}
	if again, _, _ := f.store.Refusal(ctx, scope, SourceGitHub, key, planner); again.Identity() != first.Identity() {
		t.Fatal("the refusal record changed")
	}
}
