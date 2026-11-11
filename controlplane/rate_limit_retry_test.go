package controlplane

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

// rateLimitedRun opens a run, claims its candidates task at a fixed instant
// and returns what a rate-limited completion needs. The fixture task retries
// after 1000 ms and allows three attempts.
func rateLimitedRun(t *testing.T, run string) (*FileRunJournal, *Coordinator, ReviewRunPlan, TaskDefinition, TaskLease, time.Time) {
	t.Helper()
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { journal.Close() })
	plan := inventoryPlan(t, "tenant", "repository", run)
	coordinator := inventoryOpen(t, journal, plan)
	lease := modelTaskLease(t, coordinator, plan, "candidates", 200)
	task, _ := plan.Task("candidates")
	return journal, coordinator, plan, task, lease, time.UnixMilli(lease.ExpiresAt().UnixMilli() - 5_000)
}

// A retry after a rate-limited model attempt waits for the provider's
// Retry-After when it named one, bounded by the largest task retry delay and
// by the run deadline, and waits the task's fixed delay otherwise. The event
// records the requested delay; its retry time records the delay used.
func TestRateLimitedRetryWaitsForTheProviderRetryAfter(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name       string
		retryAfter uint32
		deadline   time.Duration // after the completion instant; zero means none
		wantDelay  time.Duration
		recorded   uint32
	}{
		{"retry after", 7_000, 0, 7 * time.Second, 7_000},
		{"no retry after", 0, 0, time.Second, 0},
		{"shorter than the fixed delay", 200, 0, 200 * time.Millisecond, 200},
		{"bounded by the largest task retry delay", 4_000_000, 0, time.Hour, maxReviewTaskRetryDelayMillis},
		{"bounded by the run deadline", 7_000, 3 * time.Second, 3 * time.Second, 7_000},
		{"deadline beyond the retry after", 7_000, time.Minute, 7 * time.Second, 7_000},
		{"deadline already reached", 7_000, -time.Second, 0, 7_000},
		{"fixed delay ignores the deadline", 0, 300 * time.Millisecond, time.Second, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			journal, coordinator, plan, task, lease, at := rateLimitedRun(t, "run-rate-limit")
			completion, err := NewRateLimitedModelTaskFailure(test.retryAfter, plan, task)
			if err != nil || completion.Validate() != nil || completion.Failure() != RunFailureTransient || completion.FailureReason() != TaskFailureReasonProviderRateLimited || completion.RetryAfterMilliseconds() != test.recorded {
				t.Fatalf("completion retry after=%d err=%v", completion.RetryAfterMilliseconds(), err)
			}
			deadline := time.Time{}
			if test.deadline != 0 {
				deadline = at.Add(test.deadline)
			}
			state, err := coordinator.CompleteTaskWithin(ctx, plan, lease, completion, at, deadline)
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := state.Task("candidates")
			if got := runtime.RetryAt().Sub(at); runtime.Status() != TaskRuntimeFailed || got != test.wantDelay {
				t.Fatalf("retry in %v, want %v", got, test.wantDelay)
			}
			events, _ := journal.Read(ctx, plan.Scope(), 0, 100)
			last := events[len(events)-1]
			encoded, err := EncodeRunEvent(last)
			if err != nil || last.RetryAfterMilliseconds() != test.recorded || (test.recorded != 0) != bytes.Contains(encoded, []byte(`"retry_after_milliseconds":`)) {
				t.Fatalf("event=%s err=%v", encoded, err)
			}
			if parsed, err := ParseRunEvent(encoded); err != nil || parsed.Identity() != last.Identity() || parsed.RetryAfterMilliseconds() != test.recorded {
				t.Fatalf("event readback: %v", err)
			}
			if again, err := coordinator.CompleteTaskWithin(ctx, plan, lease, completion, at.Add(time.Millisecond), deadline); err != nil {
				t.Fatalf("idempotent completion refused: %v", err)
			} else if repeated, _ := again.Task("candidates"); !repeated.RetryAt().Equal(runtime.RetryAt()) {
				t.Fatal("idempotent completion moved the retry")
			}
			_, replayed, err := coordinator.Resume(ctx, plan.Scope())
			if err != nil {
				t.Fatal(err)
			}
			if task, _ := replayed.Task("candidates"); !task.RetryAt().Equal(runtime.RetryAt()) {
				t.Fatal("replay changed the retry time")
			}
			if test.wantDelay > 0 {
				if task, _ := replayed.Task("candidates"); task.RetryableAt(at.Add(test.wantDelay-time.Millisecond)) || !task.RetryableAt(at.Add(test.wantDelay)) {
					t.Fatal("the retry became available before or not at its recorded time")
				}
			}
		})
	}
}

// A Retry-After belongs to a rate-limited model attempt; it is never carried
// by another reason, and an attempt with no attempts left records it with no
// retry.
func TestRetryAfterIsRateLimitOnly(t *testing.T) {
	plan := inventoryPlan(t, "tenant", "repository", "run-retry-after-scope")
	candidates, _ := plan.Task("candidates")
	source, _ := plan.Task("source")
	if _, err := NewRateLimitedModelTaskFailure(1_000, plan, source); !errors.Is(err, ErrInvalidTaskCompletion) {
		t.Fatalf("retry after on a source task err=%v", err)
	}
	payment, err := NewModelTaskFailureWithReason(RunFailurePolicy, TaskFailureReasonProviderPaymentRequired, plan, candidates)
	if err != nil {
		t.Fatal(err)
	}
	payment.retryAfterMillis = 1_000
	payment.identity = deriveTaskCompletionIdentity(payment)
	if payment.Validate() == nil {
		t.Fatal("a payment refusal carried a retry after")
	}
	plain, _ := NewTaskFailure(RunFailureTransient)
	plain.retryAfterMillis = 1_000
	plain.identity = deriveTaskCompletionIdentity(plain)
	if plain.Validate() == nil {
		t.Fatal("a reasonless failure carried a retry after")
	}
	limited, err := NewRateLimitedModelTaskFailure(1_000, plan, candidates)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTaskCompletion(limited)
	if err != nil || !bytes.Contains(encoded, []byte(`"retry_after_milliseconds":1000`)) {
		t.Fatalf("completion=%s err=%v", encoded, err)
	}
	if parsed, err := ParseTaskCompletion(encoded); err != nil || parsed.Identity() != limited.Identity() || parsed.RetryAfterMilliseconds() != 1_000 {
		t.Fatalf("completion readback: %v", err)
	}
	unlimited, _ := NewRateLimitedModelTaskFailure(0, plan, candidates)
	if unlimited.Identity() == limited.Identity() {
		t.Fatal("the retry after is not bound into the completion identity")
	}
	for _, forged := range [][]byte{
		bytes.Replace(encoded, []byte(`"retry_after_milliseconds":1000`), []byte(`"retry_after_milliseconds":2000`), 1),
		bytes.Replace(encoded, []byte(`"provider_rate_limited"`), []byte(`"provider_payment_required"`), 1),
	} {
		if _, err := ParseTaskCompletion(forged); err == nil {
			t.Fatalf("forged completion parsed: %s", forged)
		}
	}
}

// An event may schedule a rate-limited retry no later than the requested
// delay, and carries a requested delay only for a rate limit.
func TestRunEventRefusesARetryPastTheRequestedDelay(t *testing.T) {
	plan := inventoryPlan(t, "tenant", "repository", "run-retry-after-event")
	task, _ := plan.Task("candidates")
	at := time.UnixMilli(10_000)
	failed := func(failure RunFailure, retryAt time.Time) RunEvent {
		event, err := NewRunEvent(plan, 9, strings.Repeat("f", 64), RunEventTaskFailed, task, 1, strings.Repeat("1", 64), "", time.Time{}, "", failure, retryAt, at)
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	limited, err := failed(RunFailureTransient, at.Add(5*time.Second)).withFailureReason(task, TaskFailureReasonProviderRateLimited, TaskFailureContextShortfall{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limited.withRetryAfter(5_000); err != nil {
		t.Fatalf("retry at the requested delay refused: %v", err)
	}
	if _, err := limited.withRetryAfter(4_999); !errors.Is(err, ErrInvalidRunEventRetry) {
		t.Fatalf("retry past the requested delay err=%v", err)
	}
	if _, err := limited.withRetryAfter(maxReviewTaskRetryDelayMillis + 1); !errors.Is(err, ErrInvalidRunEventRetry) {
		t.Fatalf("requested delay beyond the task bound err=%v", err)
	}
	payment, err := failed(RunFailurePolicy, time.Time{}).withFailureReason(task, TaskFailureReasonProviderPaymentRequired, TaskFailureContextShortfall{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := payment.withRetryAfter(1_000); !errors.Is(err, ErrInvalidRunEventRetry) {
		t.Fatalf("requested delay on a payment refusal err=%v", err)
	}
}

// On the last attempt the requested delay is recorded and nothing retries.
func TestRateLimitedLastAttemptRecordsTheRequestedDelayWithoutRetry(t *testing.T) {
	ctx := context.Background()
	scope := inventoryPlan(t, "tenant", "repository", "run-retry-after-last").Scope()
	tasks := runPlanTasks(t)
	for index, task := range tasks {
		if task.Key() == "candidates" {
			tasks[index] = mustTaskWithAttempts(t, "candidates", TaskGenerateCandidates, 1, "context")
		}
	}
	plan, err := NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, tasks)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	coordinator := inventoryOpen(t, journal, plan)
	lease := modelTaskLease(t, coordinator, plan, "candidates", 200)
	task, _ := plan.Task("candidates")
	completion, _ := NewRateLimitedModelTaskFailure(7_000, plan, task)
	state, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(lease.ExpiresAt().UnixMilli()-1))
	if err != nil {
		t.Fatal(err)
	}
	if runtime, _ := state.Task("candidates"); runtime.Status() != TaskRuntimeFailed || !runtime.RetryAt().IsZero() || runtime.RetryableAt(time.UnixMilli(lease.ExpiresAt().UnixMilli()+3_600_000)) {
		t.Fatalf("last attempt retry=%v", runtime.RetryAt())
	}
	events, _ := journal.Read(ctx, plan.Scope(), 0, 100)
	for _, event := range events {
		if event.Kind() == RunEventTaskFailed && event.TaskKey() == "candidates" && event.RetryAfterMilliseconds() != 7_000 {
			t.Fatal("the last attempt lost the requested delay")
		}
	}
}

// The requested delay validates against the completion and event schemas,
// which refuse it with any reason but a rate limit.
func TestRetryAfterRecordsValidateAgainstSchemas(t *testing.T) {
	ctx := context.Background()
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	journal, coordinator, plan, task, lease, at := rateLimitedRun(t, "run-retry-after-schema")
	completion, _ := NewRateLimitedModelTaskFailure(7_000, plan, task)
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at); err != nil {
		t.Fatal(err)
	}
	encodedCompletion, _ := EncodeTaskCompletion(completion)
	events, _ := journal.Read(ctx, plan.Scope(), 0, 100)
	encodedEvent, _ := EncodeRunEvent(events[len(events)-1])
	for name, encoded := range map[string][]byte{"completion": encodedCompletion, "event": encodedEvent} {
		id := recordSchemaID(t, name, encoded)
		if err := registry.Validate(id, encoded); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, encoded)
		}
		for _, forged := range [][]byte{
			bytes.Replace(bytes.Replace(encoded, []byte(`"provider_rate_limited"`), []byte(`"provider_payment_required"`), 1), []byte(`"failure":"transient"`), []byte(`"failure":"policy"`), 1),
			bytes.Replace(encoded, []byte(`"retry_after_milliseconds":7000`), []byte(`"retry_after_milliseconds":0`), 1),
			bytes.Replace(encoded, []byte(`"retry_after_milliseconds":7000`), []byte(`"retry_after_milliseconds":3600001`), 1),
		} {
			if bytes.Equal(forged, encoded) {
				t.Fatalf("%s forgery did not apply", name)
			}
			if err := registry.Validate(id, forged); err == nil {
				t.Fatalf("%s forgery validated:\n%s", name, forged)
			}
		}
	}
}
