package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func availableNotificationFixture(t *testing.T) (ReviewRunPlan, ReviewRunState, TaskNotification) {
	t.Helper()
	plan := runPlanFixture(t)
	journal := NewMemoryRunJournal()
	coordinator, _ := newCoordinator(journal, strings.NewReader(strings.Repeat("a", 256)))
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Advance(context.Background(), plan, time.UnixMilli(101))
	if err != nil {
		t.Fatal(err)
	}
	runtime, ok := state.Task("source")
	if !ok {
		t.Fatal("source absent")
	}
	notice, err := NewTaskNotification(state, runtime, time.UnixMilli(101))
	if err != nil {
		t.Fatal(err)
	}
	return plan, state, notice
}

func TestTaskNotificationCanonicalEncodingRoundTrips(t *testing.T) {
	_, _, notice := availableNotificationFixture(t)
	encoded, err := EncodeTaskNotification(notice)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTaskNotification(encoded)
	if err != nil || parsed.Identity() != notice.Identity() || parsed.Scope().Identity() != notice.Scope().Identity() || parsed.Attempt() != 1 || parsed.TaskKey() != "source" {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
	if fmt.Sprint(notice) != "task notification" || fmt.Sprintf("%#v", notice) != "controlplane.TaskNotification{<redacted>}" {
		t.Fatalf("format=%v/%#v", notice, notice)
	}
	for _, mutated := range [][]byte{append(append([]byte(nil), encoded...), byte(' ')), []byte(`{"contract":"open-trestle/task-notification"}`), bytes.Replace(encoded, []byte(`"attempt":1`), []byte(`"attempt":2`), 1)} {
		if _, err := ParseTaskNotification(mutated); !errors.Is(err, ErrInvalidTaskNotificationEncoding) {
			t.Fatalf("mutation err=%v", err)
		}
	}
}

func TestMemoryTaskNotificationQueueLeasesRedeliversAndAcknowledges(t *testing.T) {
	_, _, notice := availableNotificationFixture(t)
	queue := newMemoryTaskNotificationQueue(bytes.NewReader(append(bytes.Repeat([]byte("b"), 32), bytes.Repeat([]byte("c"), 224)...)))
	created, err := queue.EnqueueTaskNotification(context.Background(), notice)
	if err != nil || !created {
		t.Fatalf("enqueue=(%v,%v)", created, err)
	}
	if err := queue.WaitForTaskNotification(context.Background()); err != nil {
		t.Fatal(err)
	}
	created, err = queue.EnqueueTaskNotification(context.Background(), notice)
	if err != nil || created {
		t.Fatalf("repeat=(%v,%v)", created, err)
	}
	lease, found, err := queue.ClaimTaskNotification(context.Background(), notice.Scope(), "worker-1", time.UnixMilli(102), time.Second)
	if err != nil || !found || lease.Delivery() != 1 || lease.Notification().Identity() != notice.Identity() {
		t.Fatalf("claim=(%#v,%v,%v)", lease, found, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", lease), lease.token) || fmt.Sprintf("%#v", lease) != "controlplane.TaskNotificationLease{<redacted>}" {
		t.Fatal("lease leaked")
	}
	encodedLease, err := EncodeTaskNotificationLease(lease)
	if err != nil {
		t.Fatal(err)
	}
	parsedLease, err := ParseTaskNotificationLease(encodedLease)
	if err != nil || parsedLease.Identity() != lease.Identity() || parsedLease.TokenIdentity() != lease.TokenIdentity() || parsedLease.LeasedAt() != lease.LeasedAt() {
		t.Fatalf("lease round trip=(%#v,%v)", parsedLease, err)
	}
	if _, found, err := queue.ClaimTaskNotification(context.Background(), notice.Scope(), "worker-2", time.UnixMilli(500), time.Second); err != nil || found {
		t.Fatalf("active second claim=(%v,%v)", found, err)
	}
	redelivered, found, err := queue.ClaimTaskNotification(context.Background(), notice.Scope(), "worker-2", time.UnixMilli(1102), time.Second)
	if err != nil || !found || redelivered.Delivery() != 2 || redelivered.TokenIdentity() == lease.TokenIdentity() {
		t.Fatalf("redelivery=(%#v,%v,%v)", redelivered, found, err)
	}
	if err := queue.AcknowledgeTaskNotification(context.Background(), lease, time.UnixMilli(1103)); !errors.Is(err, ErrTaskNotificationLeaseMismatch) {
		t.Fatalf("stale ack=%v", err)
	}
	if err := queue.AcknowledgeTaskNotification(context.Background(), redelivered, time.UnixMilli(1103)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := queue.ClaimTaskNotification(context.Background(), notice.Scope(), "worker-3", time.UnixMilli(1200), time.Second); err != nil || found {
		t.Fatalf("acked claim=(%v,%v)", found, err)
	}
}

func TestTaskNotificationSchedulerReconcilesJournalAsAuthority(t *testing.T) {
	plan := runPlanFixture(t)
	journal := NewMemoryRunJournal()
	coordinator, _ := newCoordinator(journal, strings.NewReader(strings.Repeat("c", 512)))
	queue := newMemoryTaskNotificationQueue(strings.NewReader(strings.Repeat("d", 512)))
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	scheduler, err := NewTaskNotificationScheduler(journal, queue)
	if err != nil {
		t.Fatal(err)
	}
	state, count, err := scheduler.ReconcileRun(context.Background(), plan.Scope(), time.UnixMilli(101))
	if err != nil || count != 1 {
		t.Fatalf("reconcile=(%v,%d,%v)", state.Status(), count, err)
	}
	lease, found, err := queue.ClaimTaskNotification(context.Background(), plan.Scope(), "worker", time.UnixMilli(102), time.Second)
	if err != nil || !found || lease.Notification().TaskKey() != "source" {
		t.Fatalf("claim=(%#v,%v,%v)", lease, found, err)
	}
	if _, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", lease.Notification().HandlerIdentity(), "worker", time.UnixMilli(102)); err != nil || !acquired {
		t.Fatalf("task claim=(%v,%v)", acquired, err)
	}
	if err := queue.AcknowledgeTaskNotification(context.Background(), lease, time.UnixMilli(103)); err != nil {
		t.Fatal(err)
	}
}

func TestTaskNotificationIdentityIgnoresUnrelatedRunTransitions(t *testing.T) {
	plan := runPlanFixture(t)
	journal := NewMemoryRunJournal()
	coordinator, _ := newCoordinator(journal, bytes.NewReader(bytes.Repeat([]byte("e"), 512)))
	at := time.UnixMilli(100)
	if _, err := coordinator.Open(context.Background(), plan, at); err != nil {
		t.Fatal(err)
	}
	complete := func(key string, at time.Time) {
		task, _ := plan.Task(key)
		lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !acquired {
			t.Fatalf("claim %s=(%v,%v)", key, acquired, err)
		}
		completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	complete("source", at.Add(time.Millisecond))
	complete("change", at.Add(3*time.Millisecond))
	state, err := coordinator.Advance(context.Background(), plan, at.Add(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("memory")
	before, err := NewTaskNotification(state, runtime, at.Add(5*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	analysis, _ := plan.Task("analysis")
	if _, acquired, err := coordinator.ClaimTask(context.Background(), plan, "analysis", analysis.HandlerIdentity(), "worker", at.Add(6*time.Millisecond)); err != nil || !acquired {
		t.Fatalf("claim=(%v,%v)", acquired, err)
	}
	_, afterState, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ = afterState.Task("memory")
	after, err := NewTaskNotification(afterState, runtime, at.Add(6*time.Millisecond))
	if err != nil || after.Identity() != before.Identity() || after.TaskStateEventIdentity() != before.TaskStateEventIdentity() {
		t.Fatalf("notifications=(%#v,%#v,%v)", before, after, err)
	}
}

func TestMemoryTaskNotificationQueueStopsAfterBoundedDeliveries(t *testing.T) {
	_, _, notice := availableNotificationFixture(t)
	random := make([]byte, 0, 320)
	for value := byte(1); value <= 10; value++ {
		random = append(random, bytes.Repeat([]byte{value}, 32)...)
	}
	queue := newMemoryTaskNotificationQueue(bytes.NewReader(random))
	if _, err := queue.EnqueueTaskNotification(context.Background(), notice); err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(102)
	for delivery := uint8(1); delivery <= 10; delivery++ {
		lease, found, err := queue.ClaimTaskNotification(context.Background(), notice.Scope(), "worker", at, time.Second)
		if err != nil || !found || lease.Delivery() != delivery {
			t.Fatalf("delivery %d=(%#v,%v,%v)", delivery, lease, found, err)
		}
		at = at.Add(time.Second)
	}
	if _, found, err := queue.ClaimTaskNotification(context.Background(), notice.Scope(), "worker", at, time.Second); err != nil || found {
		t.Fatalf("exhausted=(%v,%v)", found, err)
	}
}

func TestTaskNotificationLeaseLifetimeRejectsOverflow(t *testing.T) {
	_, _, notice := availableNotificationFixture(t)
	issued := time.UnixMilli(1_700_000_000_000)
	token := strings.Repeat("a", 64)
	expiry := time.UnixMilli(issued.UnixMilli() + 18_446_744_074_710)
	lease, err := NewTaskNotificationLease(notice, "worker", token, 1, issued, expiry)
	if !errors.Is(err, ErrTaskNotificationLeaseMismatch) || lease.Identity() != "" {
		t.Errorf("overflow lifetime accepted: %v", err)
	}
	valid, err := NewTaskNotificationLease(notice, "worker", token, 1, issued, issued.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	valid.expiresAtMillis = expiry.UnixMilli()
	valid.identity = deriveTaskNotificationLeaseIdentity(valid)
	record := taskNotificationLeaseRecord{"open-trestle/task-notification-lease", 1, valid.identity, taskNotificationToRecord(valid.notification), valid.workerIdentity, valid.token, valid.tokenIdentity, valid.delivery, valid.leasedAtMillis, valid.expiresAtMillis}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTaskNotificationLease(encoded); !errors.Is(err, ErrInvalidTaskNotificationEncoding) {
		t.Errorf("canonical overflow lease decoded: %v", err)
	}
	if _, err := NewTaskNotificationLease(notice, "worker", token, 1, issued, issued.Add(24*time.Hour+time.Millisecond)); !errors.Is(err, ErrTaskNotificationLeaseMismatch) {
		t.Errorf("excess lifetime accepted: %v", err)
	}
}
